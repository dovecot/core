/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "base64.h"
#include "hex-binary.h"
#include "md5.h"
#include "module-dir.h"
#include "mycrypt.h"
#include "randgen.h"
#include "str.h"
#include "password-scheme.h"

#ifdef HAVE_OPENSSL_SHA1
#  include <openssl/sha.h>
#endif

static const char *salt_chars =
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

static int crypt_verify(const char *plaintext, const char *password,
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

static int md5_verify(const char *plaintext, const char *password,
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

#ifdef HAVE_OPENSSL_SHA1
static int sha_verify(const char *plaintext, const char *password,
		      const char *user __attr_unused__)
{
	unsigned char digest[SHA_DIGEST_LENGTH];
	string_t *str;

	SHA1(plaintext, strlen(plaintext), digest);

	str = t_str_new(64);
	base64_encode(digest, sizeof(digest), str);
	return strcasecmp(str_c(str), password) == 0;
}
#endif

static int plain_verify(const char *plaintext, const char *password,
			const char *user __attr_unused__)
{
	return strcmp(password, plaintext) == 0;
}

static const char *plain_generate(const char *plaintext,
				  const char *user __attr_unused__)
{
	return plaintext;
}

static int hmac_md5_verify(const char *plaintext, const char *password,
			   const char *user __attr_unused__)
{
	return strcmp(password_generate_cram_md5(plaintext), password) == 0;
}

static const char *hmac_md5_generate(const char *plaintext,
				     const char *user __attr_unused__)
{
	return password_generate_cram_md5(plaintext);
}

static int digest_md5_verify(const char *plaintext, const char *password,
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

	/* user:realm:passwd */
	realm = strchr(user, '@');
	if (realm != NULL) realm++; else realm = "";

	str = t_strconcat(t_strcut(user, '@'), ":", realm,  ":",
			  plaintext, NULL);
	md5_get_digest(str, strlen(str), digest);
	return binary_to_hex(digest, sizeof(digest));
}

static int plain_md5_verify(const char *plaintext, const char *password,
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

static const struct password_scheme default_schemes[] = {
	{ "CRYPT", crypt_verify, crypt_generate },
	{ "MD5", md5_verify, md5_generate },
#ifdef HAVE_OPENSSL_SHA1
	{ "SHA", sha_verify, NULL },
	{ "SHA1", sha_verify, NULL },
#endif
	{ "PLAIN", plain_verify, plain_generate },
	{ "HMAC-MD5", hmac_md5_verify, hmac_md5_generate },
	{ "DIGEST-MD5", digest_md5_verify, digest_md5_generate },
	{ "PLAIN-MD5", plain_md5_verify, plain_md5_generate },
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

	schemes_buf = buffer_create_dynamic(default_pool, 128, (size_t)-1);
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
	module_dir_unload(scheme_modules);
#endif

	buffer_free(schemes_buf);
	schemes = NULL;
}
