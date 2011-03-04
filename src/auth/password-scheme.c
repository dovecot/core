/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "base64.h"
#include "hex-binary.h"
#include "md4.h"
#include "md5.h"
#include "hmac-md5.h"
#include "ntlm.h"
#include "mycrypt.h"
#include "randgen.h"
#include "sha1.h"
#include "sha2.h"
#include "otp.h"
#include "str.h"
#include "password-scheme.h"

static const char salt_chars[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

ARRAY_TYPE(password_scheme_p) password_schemes;

static const struct password_scheme *
password_scheme_lookup_name(const char *name)
{
	const struct password_scheme *const *schemes;

	array_foreach(&password_schemes, schemes) {
		const struct password_scheme *scheme = *schemes;

		if (strcasecmp(scheme->name, name) == 0)
			return scheme;
	}
	return NULL;
}

/* Lookup scheme and encoding by given name. The encoding is taken from
   ".base64", ".b64" or ".hex" suffix if it exists, otherwise the default
   encoding is used. */
static const struct password_scheme *
password_scheme_lookup(const char *name, enum password_encoding *encoding_r)
{
	const struct password_scheme *scheme;
	const char *encoding = NULL;
	unsigned int scheme_len;

	*encoding_r = PW_ENCODING_NONE;

	for (scheme_len = 0; name[scheme_len] != '\0'; scheme_len++) {
		if (name[scheme_len] == '.') {
			encoding = name + scheme_len + 1;
			name = t_strndup(name, scheme_len);
			break;
		}
	}

	scheme = password_scheme_lookup_name(name);
	if (scheme == NULL)
		return NULL;

	if (encoding == NULL)
		*encoding_r = scheme->default_encoding;
	else if (strcasecmp(encoding, "b64") == 0 ||
		 strcasecmp(encoding, "base64") == 0)
		*encoding_r = PW_ENCODING_BASE64;
	else if (strcasecmp(encoding, "hex") == 0)
		*encoding_r = PW_ENCODING_HEX;
	else {
		/* unknown encoding. treat as invalid scheme. */
		return NULL;
	}
	return scheme;
}

int password_verify(const char *plaintext, const char *user, const char *scheme,
		    const unsigned char *raw_password, size_t size)
{
	const struct password_scheme *s;
	enum password_encoding encoding;
	const unsigned char *generated;
	size_t generated_size;

	s = password_scheme_lookup(scheme, &encoding);
	if (s == NULL)
		return -1;

	if (s->password_verify != NULL)
		return s->password_verify(plaintext, user, raw_password, size);

	/* generic verification handler: generate the password and compare it
	   to the one in database */
	s->password_generate(plaintext, user, &generated, &generated_size);
	return size != generated_size ? 0 :
		memcmp(generated, raw_password, size) == 0;
}

const char *password_get_scheme(const char **password)
{
	const char *p, *scheme;

	if (*password == NULL)
		return NULL;

	if (strncmp(*password, "$1$", 3) == 0) {
		/* $1$<salt>$<password>[$<ignored>] */
		p = strchr(*password + 3, '$');
		if (p != NULL) {
			/* stop at next '$' after password */
			p = strchr(p+1, '$');
			if (p != NULL)
				*password = t_strdup_until(*password, p);
			return "MD5-CRYPT";
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

int password_decode(const char *password, const char *scheme,
		    const unsigned char **raw_password_r, size_t *size_r)
{
	const struct password_scheme *s;
	enum password_encoding encoding;
	buffer_t *buf;
	unsigned int len;

	s = password_scheme_lookup(scheme, &encoding);
	if (s == NULL)
		return 0;

	len = strlen(password);
	if (encoding != PW_ENCODING_NONE && s->raw_password_len != 0 &&
	    strchr(scheme, '.') == NULL) {
		/* encoding not specified. we can guess quite well between
		   base64 and hex encodings. the only problem is distinguishing
		   2 character strings, but there shouldn't be any that short
		   raw_password_lens. */
		encoding = len == s->raw_password_len * 2 ? PW_ENCODING_HEX :
			PW_ENCODING_BASE64;
	}

	switch (encoding) {
	case PW_ENCODING_NONE:
		*raw_password_r = (const unsigned char *)password;
		*size_r = len;
		break;
	case PW_ENCODING_HEX:
		buf = buffer_create_dynamic(pool_datastack_create(),
					    len / 2 + 1);
		if (hex_to_binary(password, buf) == 0) {
			*raw_password_r = buf->data;
			*size_r = buf->used;
			break;
		}
		/* fall through, just in case it was base64-encoded after
		   all. some input lengths produce matching hex and base64
		   encoded lengths. */
	case PW_ENCODING_BASE64:
		buf = buffer_create_dynamic(pool_datastack_create(),
					    MAX_BASE64_DECODED_SIZE(len));
		if (base64_decode(password, len, NULL, buf) < 0)
			return -1;

		*raw_password_r = buf->data;
		*size_r = buf->used;
		break;
	}
	if (s->raw_password_len != *size_r && s->raw_password_len != 0) {
		/* password has invalid length */
		return -1;
	}
	return 1;
}

bool password_generate(const char *plaintext, const char *user,
		       const char *scheme,
		       const unsigned char **raw_password_r, size_t *size_r)
{
	const struct password_scheme *s;
	enum password_encoding encoding;

	s = password_scheme_lookup(scheme, &encoding);
	if (s == NULL)
		return FALSE;

	s->password_generate(plaintext, user, raw_password_r, size_r);
	return TRUE;
}

bool password_generate_encoded(const char *plaintext, const char *user,
			       const char *scheme, const char **password_r)
{
	const struct password_scheme *s;
	const unsigned char *raw_password;
	enum password_encoding encoding;
	string_t *str;
	size_t size;

	s = password_scheme_lookup(scheme, &encoding);
	if (s == NULL)
		return FALSE;

	s->password_generate(plaintext, user, &raw_password, &size);
	switch (encoding) {
	case PW_ENCODING_NONE:
		*password_r = t_strndup(raw_password, size);
		break;
	case PW_ENCODING_BASE64:
		str = t_str_new(MAX_BASE64_ENCODED_SIZE(size) + 1);
		base64_encode(raw_password, size, str);
		*password_r = str_c(str);
		break;
	case PW_ENCODING_HEX:
		*password_r = binary_to_hex(raw_password, size);
		break;
	}
	return TRUE;
}

const char *password_generate_salt(size_t len)
{
	unsigned int i;
	char *salt;

	salt = t_malloc(len + 1);
	random_fill(salt, len);
	for (i = 0; i < len; i++)
		salt[i] = salt_chars[salt[i] % (sizeof(salt_chars)-1)];
	salt[len] = '\0';
	return salt;
}

bool password_scheme_is_alias(const char *scheme1, const char *scheme2)
{
	const struct password_scheme *const *schemes, *s1 = NULL, *s2 = NULL;

	scheme1 = t_strcut(scheme1, '.');
	scheme2 = t_strcut(scheme2, '.');

	if (strcasecmp(scheme1, scheme2) == 0)
		return TRUE;

	array_foreach(&password_schemes, schemes) {
		const struct password_scheme *scheme = *schemes;

		if (strcasecmp(scheme->name, scheme1) == 0)
			s1 = scheme;
		else if (strcasecmp(scheme->name, scheme2) == 0)
			s2 = scheme;
	}

	/* if they've the same generate function, they're equivalent */
	return s1 != NULL && s2 != NULL &&
		s1->password_generate == s2->password_generate;
}

const char *
password_scheme_detect(const char *plain_password, const char *crypted_password,
		       const char *user)
{
	const struct password_scheme *const *schemes;
	unsigned int i, count;
	const unsigned char *raw_password;
	size_t raw_password_size;

	schemes = array_get(&password_schemes, &count);
	for (i = 0; i < count; i++) {
		if (password_decode(crypted_password, schemes[i]->name,
				    &raw_password, &raw_password_size) <= 0)
			continue;

		if (password_verify(plain_password, user, schemes[i]->name,
				    raw_password, raw_password_size) > 0)
			return schemes[i]->name;
	}
	return NULL;
}

bool crypt_verify(const char *plaintext, const char *user ATTR_UNUSED,
		  const unsigned char *raw_password, size_t size)
{
	const char *password, *crypted;

	if (size == 0) {
		/* the default mycrypt() handler would return match */
		return FALSE;
	}

	password = t_strndup(raw_password, size);
	crypted = mycrypt(plaintext, password);
	if (crypted == NULL) {
		/* really shouldn't happen unless the system is broken */
		i_error("crypt() failed: %m");
		return FALSE;
	}

	return strcmp(crypted, password) == 0;
}

static void
crypt_generate(const char *plaintext, const char *user ATTR_UNUSED,
	       const unsigned char **raw_password_r, size_t *size_r)
{
#define	CRYPT_SALT_LEN 2
	const char *password, *salt;

	salt = password_generate_salt(CRYPT_SALT_LEN);
	password = t_strdup(mycrypt(plaintext, salt));
	*raw_password_r = (const unsigned char *)password;
	*size_r = strlen(password);
}

static bool
md5_verify(const char *plaintext, const char *user,
	   const unsigned char *raw_password, size_t size)
{
	const char *password, *str;
	const unsigned char *md5_password;
	size_t md5_size;

	password = t_strndup(raw_password, size);
	if (strncmp(password, "$1$", 3) == 0) {
		/* MD5-CRYPT */
		str = password_generate_md5_crypt(plaintext, password);
		return strcmp(str, password) == 0;
	} else if (password_decode(password, "PLAIN-MD5",
				   &md5_password, &md5_size) < 0) {
		i_error("md5_verify(%s): Not a valid MD5-CRYPT or "
			"PLAIN-MD5 password", user);
		return FALSE;
	} else {
		return password_verify(plaintext, user, "PLAIN-MD5",
				       md5_password, md5_size) > 0;
	}
}

static bool
md5_crypt_verify(const char *plaintext, const char *user ATTR_UNUSED,
		 const unsigned char *raw_password, size_t size)
{
	const char *password, *str;

	password = t_strndup(raw_password, size);
	str = password_generate_md5_crypt(plaintext, password);
	return strcmp(str, password) == 0;
}

static void
md5_crypt_generate(const char *plaintext, const char *user ATTR_UNUSED,
		   const unsigned char **raw_password_r, size_t *size_r)
{
	const char *password;
	char salt[9];
	unsigned int i;

	random_fill(salt, sizeof(salt)-1);
	for (i = 0; i < sizeof(salt)-1; i++)
		salt[i] = salt_chars[salt[i] % (sizeof(salt_chars)-1)];
	salt[sizeof(salt)-1] = '\0';

	password = password_generate_md5_crypt(plaintext, salt);
	*raw_password_r = (const unsigned char *)password;
	*size_r = strlen(password);
}

static void
sha1_generate(const char *plaintext, const char *user ATTR_UNUSED,
	      const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc(SHA1_RESULTLEN);
	sha1_get_digest(plaintext, strlen(plaintext), digest);

	*raw_password_r = digest;
	*size_r = SHA1_RESULTLEN;
}

static void
sha256_generate(const char *plaintext, const char *user ATTR_UNUSED,
		const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc(SHA256_RESULTLEN);
	sha256_get_digest(plaintext, strlen(plaintext), digest);

	*raw_password_r = digest;
	*size_r = SHA256_RESULTLEN;
}

static void
sha512_generate(const char *plaintext, const char *user ATTR_UNUSED,
		const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc(SHA512_RESULTLEN);
	sha512_get_digest(plaintext, strlen(plaintext), digest);

	*raw_password_r = digest;
	*size_r = SHA512_RESULTLEN;
}

static void
ssha_generate(const char *plaintext, const char *user ATTR_UNUSED,
	      const unsigned char **raw_password_r, size_t *size_r)
{
#define SSHA_SALT_LEN 4
	unsigned char *digest, *salt;
	struct sha1_ctxt ctx;

	digest = t_malloc(SHA1_RESULTLEN + SSHA_SALT_LEN);
	salt = digest + SHA1_RESULTLEN;
	random_fill(salt, SSHA_SALT_LEN);

	sha1_init(&ctx);
	sha1_loop(&ctx, plaintext, strlen(plaintext));
	sha1_loop(&ctx, salt, SSHA_SALT_LEN);
	sha1_result(&ctx, digest);

	*raw_password_r = digest;
	*size_r = SHA1_RESULTLEN + SSHA_SALT_LEN;
}

static bool ssha_verify(const char *plaintext, const char *user,
			const unsigned char *raw_password, size_t size)
{
	unsigned char sha1_digest[SHA1_RESULTLEN];
	struct sha1_ctxt ctx;

	/* format: <SHA1 hash><salt> */
	if (size <= SHA1_RESULTLEN) {
		i_error("ssha_verify(%s): SSHA password too short", user);
		return FALSE;
	}

	sha1_init(&ctx);
	sha1_loop(&ctx, plaintext, strlen(plaintext));
	sha1_loop(&ctx, raw_password + SHA1_RESULTLEN, size - SHA1_RESULTLEN);
	sha1_result(&ctx, sha1_digest);
	return memcmp(sha1_digest, raw_password, SHA1_RESULTLEN) == 0;
}

static void
ssha256_generate(const char *plaintext, const char *user ATTR_UNUSED,
		 const unsigned char **raw_password_r, size_t *size_r)
{
#define SSHA256_SALT_LEN 4
	unsigned char *digest, *salt;
	struct sha256_ctx ctx;

	digest = t_malloc(SHA256_RESULTLEN + SSHA256_SALT_LEN);
	salt = digest + SHA256_RESULTLEN;
	random_fill(salt, SSHA256_SALT_LEN);

	sha256_init(&ctx);
	sha256_loop(&ctx, plaintext, strlen(plaintext));
	sha256_loop(&ctx, salt, SSHA256_SALT_LEN);
	sha256_result(&ctx, digest);

	*raw_password_r = digest;
	*size_r = SHA256_RESULTLEN + SSHA256_SALT_LEN;
}

static bool ssha256_verify(const char *plaintext, const char *user,
			   const unsigned char *raw_password, size_t size)
{
	unsigned char sha256_digest[SHA256_RESULTLEN];
	struct sha256_ctx ctx;

	/* format: <SHA256 hash><salt> */
	if (size <= SHA256_RESULTLEN) {
		i_error("ssha256_verify(%s): SSHA256 password too short", user);
		return FALSE;
	}

	sha256_init(&ctx);
	sha256_loop(&ctx, plaintext, strlen(plaintext));
	sha256_loop(&ctx, raw_password + SHA256_RESULTLEN,
		    size - SHA256_RESULTLEN);
	sha256_result(&ctx, sha256_digest);
	return memcmp(sha256_digest, raw_password, SHA256_RESULTLEN) == 0;
}

static void
ssha512_generate(const char *plaintext, const char *user ATTR_UNUSED,
		 const unsigned char **raw_password_r, size_t *size_r)
{
#define SSHA512_SALT_LEN 4
	unsigned char *digest, *salt;
	struct sha512_ctx ctx;

	digest = t_malloc(SHA512_RESULTLEN + SSHA512_SALT_LEN);
	salt = digest + SHA512_RESULTLEN;
	random_fill(salt, SSHA512_SALT_LEN);

	sha512_init(&ctx);
	sha512_loop(&ctx, plaintext, strlen(plaintext));
	sha512_loop(&ctx, salt, SSHA512_SALT_LEN);
	sha512_result(&ctx, digest);

	*raw_password_r = digest;
	*size_r = SHA512_RESULTLEN + SSHA512_SALT_LEN;
}

static bool ssha512_verify(const char *plaintext, const char *user,
			   const unsigned char *raw_password, size_t size)
{
	unsigned char sha512_digest[SHA512_RESULTLEN];
	struct sha512_ctx ctx;

	/* format: <SHA512 hash><salt> */
	if (size <= SHA512_RESULTLEN) {
		i_error("ssha512_verify(%s): SSHA512 password too short", user);
		return FALSE;
	}

	sha512_init(&ctx);
	sha512_loop(&ctx, plaintext, strlen(plaintext));
	sha512_loop(&ctx, raw_password + SHA512_RESULTLEN,
		    size - SHA512_RESULTLEN);
	sha512_result(&ctx, sha512_digest);
	return memcmp(sha512_digest, raw_password, SHA512_RESULTLEN) == 0;
}

static void
smd5_generate(const char *plaintext, const char *user ATTR_UNUSED,
	      const unsigned char **raw_password_r, size_t *size_r)
{
#define SMD5_SALT_LEN 4
	unsigned char *digest, *salt;
	struct md5_context ctx;

	digest = t_malloc(MD5_RESULTLEN + SMD5_SALT_LEN);
	salt = digest + MD5_RESULTLEN;
	random_fill(salt, SMD5_SALT_LEN);

	md5_init(&ctx);
	md5_update(&ctx, plaintext, strlen(plaintext));
	md5_update(&ctx, salt, SMD5_SALT_LEN);
	md5_final(&ctx, digest);

	*raw_password_r = digest;
	*size_r = MD5_RESULTLEN + SMD5_SALT_LEN;
}

static bool smd5_verify(const char *plaintext, const char *user,
			const unsigned char *raw_password, size_t size)
{
	unsigned char md5_digest[MD5_RESULTLEN];
	struct md5_context ctx;

	/* format: <MD5 hash><salt> */
	if (size <= MD5_RESULTLEN) {
		i_error("smd5_verify(%s): SMD5 password too short", user);
		return FALSE;
	}

	md5_init(&ctx);
	md5_update(&ctx, plaintext, strlen(plaintext));
	md5_update(&ctx, raw_password + MD5_RESULTLEN, size - MD5_RESULTLEN);
	md5_final(&ctx, md5_digest);
	return memcmp(md5_digest, raw_password, MD5_RESULTLEN) == 0;
}

static void
plain_generate(const char *plaintext, const char *user ATTR_UNUSED,
	       const unsigned char **raw_password_r, size_t *size_r)
{
	*raw_password_r = (const unsigned char *)plaintext,
	*size_r = strlen(plaintext);
}

static void
cram_md5_generate(const char *plaintext, const char *user ATTR_UNUSED,
		  const unsigned char **raw_password_r, size_t *size_r)
{
	struct hmac_md5_context ctx;
	unsigned char *context_digest;

	context_digest = t_malloc(CRAM_MD5_CONTEXTLEN);
	hmac_md5_init(&ctx, (const unsigned char *)plaintext,
		      strlen(plaintext));
	hmac_md5_get_cram_context(&ctx, context_digest);

	*raw_password_r = context_digest;
	*size_r = CRAM_MD5_CONTEXTLEN;
}

static void
digest_md5_generate(const char *plaintext, const char *user,
		    const unsigned char **raw_password_r, size_t *size_r)
{
	const char *realm, *str;
	unsigned char *digest;

	if (user == NULL)
		i_fatal("digest_md5_generate(): username not given");


	/* assume user@realm format for username. If user@domain is wanted
	   in the username, allow also user@domain@realm. */
	realm = strrchr(user, '@');
	if (realm != NULL) {
		user = t_strdup_until(user, realm);
		realm++;
	} else {
		realm = "";
	}

	/* user:realm:passwd */
	digest = t_malloc(MD5_RESULTLEN);
	str = t_strdup_printf("%s:%s:%s", user, realm, plaintext);
	md5_get_digest(str, strlen(str), digest);

	*raw_password_r = digest;
	*size_r = MD5_RESULTLEN;
}

static void
plain_md4_generate(const char *plaintext, const char *user ATTR_UNUSED,
		   const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc(MD4_RESULTLEN);
	md4_get_digest(plaintext, strlen(plaintext), digest);

	*raw_password_r = digest;
	*size_r = MD4_RESULTLEN;
}

static void
plain_md5_generate(const char *plaintext, const char *user ATTR_UNUSED,
		   const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc(MD5_RESULTLEN);
	md5_get_digest(plaintext, strlen(plaintext), digest);

	*raw_password_r = digest;
	*size_r = MD5_RESULTLEN;
}

static void
lm_generate(const char *plaintext, const char *user ATTR_UNUSED,
	    const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc(LM_HASH_SIZE);
	lm_hash(plaintext, digest);

	*raw_password_r = digest;
	*size_r = LM_HASH_SIZE;
}

static void
ntlm_generate(const char *plaintext, const char *user ATTR_UNUSED,
	      const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc(NTLMSSP_HASH_SIZE);
	ntlm_v1_hash(plaintext, digest);

	*raw_password_r = digest;
	*size_r = NTLMSSP_HASH_SIZE;
}

static bool otp_verify(const char *plaintext, const char *user ATTR_UNUSED,
		       const unsigned char *raw_password, size_t size)
{
	const char *password;

	password = t_strndup(raw_password, size);
	return strcasecmp(password,
		password_generate_otp(plaintext, password, -1)) == 0;
}

static void
otp_generate(const char *plaintext, const char *user ATTR_UNUSED,
	     const unsigned char **raw_password_r, size_t *size_r)
{
	const char *password;

	password = password_generate_otp(plaintext, NULL, OTP_HASH_SHA1);
	*raw_password_r = (const unsigned char *)password;
	*size_r = strlen(password);
}

static void
skey_generate(const char *plaintext, const char *user ATTR_UNUSED,
	      const unsigned char **raw_password_r, size_t *size_r)
{
	const char *password;

	password = password_generate_otp(plaintext, NULL, OTP_HASH_MD4);
	*raw_password_r = (const unsigned char *)password;
	*size_r = strlen(password);
}

static void
rpa_generate(const char *plaintext, const char *user ATTR_UNUSED,
	     const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc(MD5_RESULTLEN);
	password_generate_rpa(plaintext, digest);

	*raw_password_r = digest;
	*size_r = MD5_RESULTLEN;
}

static const struct password_scheme builtin_schemes[] = {
	{ "CRYPT", PW_ENCODING_NONE, 0, crypt_verify, crypt_generate },
	{ "MD5", PW_ENCODING_NONE, 0, md5_verify, md5_crypt_generate },
	{ "MD5-CRYPT", PW_ENCODING_NONE, 0,
	  md5_crypt_verify, md5_crypt_generate },
 	{ "SHA", PW_ENCODING_BASE64, SHA1_RESULTLEN, NULL, sha1_generate },
 	{ "SHA1", PW_ENCODING_BASE64, SHA1_RESULTLEN, NULL, sha1_generate },
 	{ "SHA256", PW_ENCODING_BASE64, SHA256_RESULTLEN,
	  NULL, sha256_generate },
 	{ "SHA512", PW_ENCODING_BASE64, SHA512_RESULTLEN,
	  NULL, sha512_generate },
	{ "SMD5", PW_ENCODING_BASE64, 0, smd5_verify, smd5_generate },
	{ "SSHA", PW_ENCODING_BASE64, 0, ssha_verify, ssha_generate },
	{ "SSHA256", PW_ENCODING_BASE64, 0, ssha256_verify, ssha256_generate },
	{ "SSHA512", PW_ENCODING_BASE64, 0, ssha512_verify, ssha512_generate },
	{ "PLAIN", PW_ENCODING_NONE, 0, NULL, plain_generate },
	{ "CLEARTEXT", PW_ENCODING_NONE, 0, NULL, plain_generate },
	{ "CRAM-MD5", PW_ENCODING_HEX, CRAM_MD5_CONTEXTLEN,
	  NULL, cram_md5_generate },
	{ "HMAC-MD5", PW_ENCODING_HEX, CRAM_MD5_CONTEXTLEN,
	  NULL, cram_md5_generate },
	{ "DIGEST-MD5", PW_ENCODING_HEX, MD5_RESULTLEN,
	  NULL, digest_md5_generate },
	{ "PLAIN-MD4", PW_ENCODING_HEX, MD4_RESULTLEN,
	  NULL, plain_md4_generate },
	{ "PLAIN-MD5", PW_ENCODING_HEX, MD5_RESULTLEN,
	  NULL, plain_md5_generate },
	{ "LDAP-MD5", PW_ENCODING_BASE64, MD5_RESULTLEN,
	  NULL, plain_md5_generate },
	{ "LANMAN", PW_ENCODING_HEX, LM_HASH_SIZE, NULL, lm_generate },
	{ "NTLM", PW_ENCODING_HEX, NTLMSSP_HASH_SIZE, NULL, ntlm_generate },
	{ "OTP", PW_ENCODING_NONE, 0, otp_verify, otp_generate },
	{ "SKEY", PW_ENCODING_NONE, 0, otp_verify, skey_generate },
	{ "RPA", PW_ENCODING_HEX, MD5_RESULTLEN, NULL, rpa_generate }
};

void password_scheme_register(const struct password_scheme *scheme)
{
	if (password_scheme_lookup_name(scheme->name) != NULL) {
		i_panic("password_scheme_register(%s): Already registered",
			scheme->name);
	}
	array_append(&password_schemes, &scheme, 1);
}

void password_scheme_unregister(const struct password_scheme *scheme)
{
	const struct password_scheme *const *schemes;
	unsigned int idx;

	array_foreach(&password_schemes, schemes) {
		if (strcasecmp((*schemes)->name, scheme->name) == 0) {
			idx = array_foreach_idx(&password_schemes, schemes);
			array_delete(&password_schemes, idx, 1);
			return;
		}
	}
	i_panic("password_scheme_unregister(%s): Not registered", scheme->name);
}

void password_schemes_init(void)
{
	unsigned int i;

	i_array_init(&password_schemes, N_ELEMENTS(builtin_schemes) + 4);
	for (i = 0; i < N_ELEMENTS(builtin_schemes); i++)
		password_scheme_register(&builtin_schemes[i]);
	password_scheme_register_crypt();
}

void password_schemes_deinit(void)
{
	array_free(&password_schemes);
}
