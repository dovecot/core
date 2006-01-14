/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "base64.h"
#include "hex-binary.h"
#include "md5.h"
#include "module-dir.h"
#include "mycrypt.h"
#include "randgen.h"
#include "sha1.h"
#include "str.h"
#include "password-scheme.h"

static const char salt_chars[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static buffer_t *schemes_buf;
static const struct password_scheme *schemes;
#ifdef HAVE_MODULES
static struct module *scheme_modules;
#endif

int password_verify(const char *plaintext, const char *password,
		    const char *scheme, const char *user)
{
	const struct password_scheme *s;

	if (password == NULL)
		return 0;

	for (s = schemes; s->name != NULL; s++) {
		if (strcasecmp(s->name, scheme) == 0)
			return s->password_verify(plaintext, password, user);
	}

	return -1;
}

const char *password_list_schemes(const struct password_scheme **listptr)
{
	if (*listptr == NULL)
		*listptr = schemes;

	if ((*listptr)->name == NULL) {
		*listptr = NULL;
		return NULL;
	}

	return (*listptr)++->name;
}

const char *password_get_scheme(const char **password)
{
	const char *p, *scheme;

	if (*password == NULL)
		return NULL;

	if (strncmp(*password, "$1$", 3) == 0) {
		/* skip the salt */
		p = strchr(*password + 3, '$');
		if (p != NULL) {
			/* stop at next '$' */
			p = strchr(p+1, '$');
			if (p != NULL)
				*password = t_strdup_until(*password, p);
			return "MD5";
		}
	}

	if (**password != '{')
		return NULL;

	p = strchr(*password, '}');
	if (p == NULL)
		return NULL;

	scheme = t_strdup_until(*password + 1, p);
	*password = p + 1;

	/* LDAP's RFC2307 specifies the MD5 scheme for what we call LDAP-MD5.
	   We can detect this case - base64 doesn't use '$'. */
	if (strncasecmp(scheme, "MD5", 3) == 0 &&
	    strncmp(*password, "$1$", 3) != 0)
		scheme = "LDAP-MD5";
	return scheme;
}

const char *password_generate(const char *plaintext, const char *user,
			      const char *scheme)
{
	const struct password_scheme *s;

	for (s = schemes; s->name != NULL; s++) {
		if (strcasecmp(s->name, scheme) == 0)
			return s->password_generate(plaintext, user);
	}

	return NULL;
}

static bool crypt_verify(const char *plaintext, const char *password,
			 const char *user __attr_unused__)
{
	return strcmp(mycrypt(plaintext, password), password) == 0;
}

static const char *crypt_generate(const char *plaintext,
				  const char *user __attr_unused__)
{
	char salt[9];

	random_fill(salt, 2);
	salt[0] = salt_chars[salt[0] % (sizeof(salt_chars)-1)];
	salt[1] = salt_chars[salt[1] % (sizeof(salt_chars)-1)];
	salt[2] = '\0';
	return t_strdup(mycrypt(plaintext, salt));
}

static bool md5_verify(const char *plaintext, const char *password,
		       const char *user __attr_unused__)
{
	const char *str;

	str = password_generate_md5_crypt(plaintext, password);
	return strcmp(str, password) == 0;
}

static const char *md5_generate(const char *plaintext,
				const char *user __attr_unused__)
{
	char salt[9];
	int i;

	random_fill(salt, 8);
	for (i = 0; i < 8; i++)
		salt[i] = salt_chars[salt[i] % (sizeof(salt_chars)-1)];
	salt[8] = '\0';
	return password_generate_md5_crypt(plaintext, salt);
}

static const char *sha1_generate(const char *plaintext,
				const char *user __attr_unused__)
{
	unsigned char digest[SHA1_RESULTLEN];
	string_t *str;

	sha1_get_digest(plaintext, strlen(plaintext), digest);
	str = t_str_new(MAX_BASE64_ENCODED_SIZE(sizeof(digest)+1));
	base64_encode(digest, sizeof(digest), str);
	return str_c(str);
}

static bool sha1_verify(const char *plaintext, const char *password,
			const char *user __attr_unused__)
{
	unsigned char sha1_digest[SHA1_RESULTLEN];
	const char *data;
	buffer_t *buf;
	size_t size, password_len;

	sha1_get_digest(plaintext, strlen(plaintext), sha1_digest);

	password_len = strlen(password);
	buf = buffer_create_static_hard(pool_datastack_create(),
					MAX_BASE64_DECODED_SIZE(password_len));

	if (base64_decode(password, password_len, NULL, buf) < 0) {
		i_error("sha1_verify(%s): failed decoding SHA base64", user);
		return 0;
	}

	data = buffer_get_data(buf, &size);
	if (size < SHA1_RESULTLEN) {
		i_error("sha1_verify(%s): invalid SHA base64 decode", user);
		return 0;
	}

	return memcmp(sha1_digest, data, SHA1_RESULTLEN) == 0;
}

static const char *ssha_generate(const char *plaintext,
				 const char *user __attr_unused__)
{
	unsigned char ssha_digest[SHA1_RESULTLEN+4];
	unsigned char *salt = &ssha_digest[SHA1_RESULTLEN];
	struct sha1_ctxt ctx;
	string_t *str;

	random_fill(salt, 4);

	sha1_init(&ctx);
	sha1_loop(&ctx, plaintext, strlen(plaintext));
	sha1_loop(&ctx, salt, 4);
	sha1_result(&ctx, ssha_digest);

	str = t_str_new(MAX_BASE64_ENCODED_SIZE(sizeof(ssha_digest))+1);
	base64_encode(ssha_digest, sizeof(ssha_digest), str);
	return str_c(str);
}

static bool ssha_verify(const char *plaintext, const char *password,
			const char *user __attr_unused__)
{
	unsigned char sha1_digest[SHA1_RESULTLEN];
	buffer_t *buf;
	const char *data;
	size_t size, password_len;
	struct sha1_ctxt ctx;

	/* format: base64-encoded MD5 hash and salt */
	password_len = strlen(password);
	buf = buffer_create_static_hard(pool_datastack_create(),
					MAX_BASE64_DECODED_SIZE(password_len));

	if (base64_decode(password, password_len, NULL, buf) < 0) {
		i_error("ssha_verify(%s): failed decoding SSHA base64", user);
		return 0;
	}

	data = buffer_get_data(buf, &size);
	if (size <= SHA1_RESULTLEN) {
		i_error("ssha_verify(%s): invalid SSHA base64 decode", user);
		return 0;
	}

	sha1_init(&ctx);
	sha1_loop(&ctx, plaintext, strlen(plaintext));
	sha1_loop(&ctx, &data[SHA1_RESULTLEN], size-SHA1_RESULTLEN);
	sha1_result(&ctx, sha1_digest);
	return memcmp(sha1_digest, data, SHA1_RESULTLEN) == 0;
}

static const char *smd5_generate(const char *plaintext,
				 const char *user __attr_unused__)
{
	unsigned char smd5_digest[20];
	unsigned char *salt = &smd5_digest[16];
	struct md5_context ctx;
	string_t *str;

	random_fill(salt, 4);

	md5_init(&ctx);
	md5_update(&ctx, plaintext, strlen(plaintext));
	md5_update(&ctx, salt, 4);
	md5_final(&ctx, smd5_digest);

	str = t_str_new(MAX_BASE64_ENCODED_SIZE(sizeof(smd5_digest))+1);
	base64_encode(smd5_digest, sizeof(smd5_digest), str);
	return str_c(str);
}

static bool smd5_verify(const char *plaintext, const char *password,
			const char *user __attr_unused__)
{
	unsigned char md5_digest[16];
	buffer_t *buf;
	const char *data;
	size_t size, password_len;
	struct md5_context ctx;

	/* format: base64-encoded MD5 hash and salt */
	password_len = strlen(password);
	buf = buffer_create_static_hard(pool_datastack_create(),
					MAX_BASE64_DECODED_SIZE(password_len));

	if (base64_decode(password, password_len, NULL, buf) < 0) {
		i_error("smd5_verify(%s): failed decoding SMD5 base64", user);
		return 0;
	}

	data = buffer_get_data(buf, &size);
	if (size <= 16) {
		i_error("smd5_verify(%s): invalid SMD5 base64 decode", user);
		return 0;
	}

	md5_init(&ctx);
	md5_update(&ctx, plaintext, strlen(plaintext));
	md5_update(&ctx, &data[16], size-16);
	md5_final(&ctx, md5_digest);
	return memcmp(md5_digest, data, 16) == 0;
}

static bool plain_verify(const char *plaintext, const char *password,
			 const char *user __attr_unused__)
{
	return strcmp(password, plaintext) == 0;
}

static const char *plain_generate(const char *plaintext,
				  const char *user __attr_unused__)
{
	return plaintext;
}

static bool hmac_md5_verify(const char *plaintext, const char *password,
			    const char *user __attr_unused__)
{
	return strcmp(password_generate_cram_md5(plaintext), password) == 0;
}

static const char *hmac_md5_generate(const char *plaintext,
				     const char *user __attr_unused__)
{
	return password_generate_cram_md5(plaintext);
}

static bool digest_md5_verify(const char *plaintext, const char *password,
			      const char *user)
{
	unsigned char digest[16];
	const char *realm, *str;

	/* user:realm:passwd */
	realm = strchr(user, '@');
	if (realm != NULL) realm++; else realm = "";

	str = t_strconcat(t_strcut(user, '@'), ":", realm,  ":",
			  plaintext, NULL);
	md5_get_digest(str, strlen(str), digest);
	str = binary_to_hex(digest, sizeof(digest));

	return strcasecmp(str, password) == 0;
}

static const char *digest_md5_generate(const char *plaintext, const char *user)
{
	const char *realm, *str;
	unsigned char digest[16];

	if (user == NULL)
		i_fatal("digest_md5_generate(): username not given");

	/* user:realm:passwd */
	realm = strchr(user, '@');
	if (realm != NULL) realm++; else realm = "";

	str = t_strconcat(t_strcut(user, '@'), ":", realm,  ":",
			  plaintext, NULL);
	md5_get_digest(str, strlen(str), digest);
	return binary_to_hex(digest, sizeof(digest));
}

static bool plain_md5_verify(const char *plaintext, const char *password,
			     const char *user __attr_unused__)
{
	unsigned char digest[16];
	const char *str;

	md5_get_digest(plaintext, strlen(plaintext), digest);
	str = binary_to_hex(digest, sizeof(digest));
	return strcasecmp(str, password) == 0;
}

static const char *plain_md5_generate(const char *plaintext,
				      const char *user __attr_unused__)
{
	unsigned char digest[16];

	md5_get_digest(plaintext, strlen(plaintext), digest);
	return binary_to_hex(digest, sizeof(digest));
}

static const char *ldap_md5_generate(const char *plaintext,
				     const char *user __attr_unused__)
{
	unsigned char digest[16];
	string_t *str;

	md5_get_digest(plaintext, strlen(plaintext), digest);
	str = t_str_new(MAX_BASE64_ENCODED_SIZE(sizeof(digest)+1));
	base64_encode(digest, sizeof(digest), str);
	return str_c(str);
}

static bool ldap_md5_verify(const char *plaintext, const char *password,
			    const char *user __attr_unused__)
{
	unsigned char md5_digest[16];
	buffer_t *buf;
	const char *data;
	size_t size, password_len;

	md5_get_digest(plaintext, strlen(plaintext), md5_digest);

	password_len = strlen(password);
	buf = buffer_create_static_hard(pool_datastack_create(),
					MAX_BASE64_DECODED_SIZE(password_len));

	if (base64_decode(password, password_len, NULL, buf) < 0) {
		i_error("ldap_md5_verify(%s): failed decoding MD5 base64",
			user);
		return 0;
	}

	data = buffer_get_data(buf, &size);
	if (size != 16) {
		i_error("ldap_md5_verify(%s): invalid MD5 base64 decode", user);
		return 0;
	}

	return memcmp(md5_digest, data, 16) == 0;
}

static bool lm_verify(const char *plaintext, const char *password,
		      const char *user __attr_unused__)
{
	return strcasecmp(password, password_generate_lm(plaintext)) == 0;
}

static const char *lm_generate(const char *plaintext,
				 const char *user __attr_unused__)
{
	return password_generate_lm(plaintext);
}

static bool ntlm_verify(const char *plaintext, const char *password,
			const char *user __attr_unused__)
{
	return strcasecmp(password, password_generate_ntlm(plaintext)) == 0;
}

static const char *ntlm_generate(const char *plaintext,
				 const char *user __attr_unused__)
{
	return password_generate_ntlm(plaintext);
}

static bool rpa_verify(const char *plaintext, const char *password,
		       const char *user __attr_unused__)
{
	return strcasecmp(password, password_generate_rpa(plaintext)) == 0;
}

static const char *rpa_generate(const char *plaintext,
				const char *user __attr_unused__)
{
	return password_generate_rpa(plaintext);
}

static const struct password_scheme default_schemes[] = {
	{ "CRYPT", crypt_verify, crypt_generate },
	{ "MD5", md5_verify, md5_generate },
 	{ "SHA", sha1_verify, sha1_generate },
 	{ "SHA1", sha1_verify, sha1_generate },
	{ "SMD5", smd5_verify, smd5_generate },
	{ "SSHA", ssha_verify, ssha_generate },
	{ "PLAIN", plain_verify, plain_generate },
	{ "CLEARTEXT", plain_verify, plain_generate },
	{ "HMAC-MD5", hmac_md5_verify, hmac_md5_generate },
	{ "DIGEST-MD5", digest_md5_verify, digest_md5_generate },
	{ "PLAIN-MD5", plain_md5_verify, plain_md5_generate },
	{ "LDAP-MD5", ldap_md5_verify, ldap_md5_generate },
	{ "LANMAN", lm_verify, lm_generate },
	{ "NTLM", ntlm_verify, ntlm_generate },
	{ "RPA", rpa_verify, rpa_generate },
	{ NULL, NULL, NULL }
};

void password_schemes_init(void)
{
	static const struct password_scheme null_scheme = { NULL, NULL, NULL };
	const struct password_scheme *s;
#ifdef HAVE_MODULES
	struct module *mod;
	const char *symbol;
#endif

	schemes_buf = buffer_create_dynamic(default_pool, 128);
	for (s = default_schemes; s->name != NULL; s++)
		buffer_append(schemes_buf, s, sizeof(*s));

#ifdef HAVE_MODULES
	scheme_modules = module_dir_load(AUTH_MODULE_DIR"/password", FALSE);
	for (mod = scheme_modules; mod != NULL; mod = mod->next) {
		t_push();
		symbol = t_strconcat(mod->name, "_scheme", NULL);
		s = module_get_symbol(mod, symbol);
		if (s != NULL)
			buffer_append(schemes_buf, s, sizeof(*s));
		t_pop();
	}
#endif

	buffer_append(schemes_buf, &null_scheme, sizeof(null_scheme));
	schemes = buffer_get_data(schemes_buf, NULL);
}

void password_schemes_deinit(void)
{
#ifdef HAVE_MODULES
	module_dir_unload(&scheme_modules);
#endif

	buffer_free(schemes_buf);
	schemes = NULL;
}
