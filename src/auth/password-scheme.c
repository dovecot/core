/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "base64.h"
#include "hex-binary.h"
#include "md4.h"
#include "md5.h"
#include "hmac.h"
#include "hmac-cram-md5.h"
#include "mycrypt.h"
#include "randgen.h"
#include "sha1.h"
#include "sha2.h"
#include "otp.h"
#include "str.h"
#include "password-scheme.h"

static const char salt_chars[] =
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static HASH_TABLE(const char*, const struct password_scheme *) password_schemes;

static bool g_allow_weak = FALSE;

void password_schemes_allow_weak(bool allow)
{
	g_allow_weak = allow;
}

static const struct password_scheme *
password_scheme_lookup_name(const char *name)
{
	return hash_table_lookup(password_schemes, name);
}

/* Lookup scheme and encoding by given name. The encoding is taken from
   ".base64", ".b64" or ".hex" suffix if it exists, otherwise the default
   encoding is used. */
static const struct password_scheme *
password_scheme_lookup(const char *name, enum password_encoding *encoding_r)
{
	const struct password_scheme *scheme;
	const char *encoding = NULL;

	*encoding_r = PW_ENCODING_NONE;
	if ((encoding = strchr(name, '.')) != NULL) {
		name = t_strdup_until(name, encoding);
		encoding++;
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

int password_verify(const char *plaintext,
		    const struct password_generate_params *params,
		    const char *scheme, const unsigned char *raw_password,
		    size_t size, const char **error_r)
{
	const struct password_scheme *s;
	enum password_encoding encoding;
	const unsigned char *generated;
	size_t generated_size;
	int ret;

	s = password_scheme_lookup(scheme, &encoding);
	if (s == NULL) {
		*error_r = "Unknown password scheme";
		return -1;
	}

	if (s->weak && !g_allow_weak) {
		*error_r = t_strdup_printf("Weak password scheme '%s' used and refused",
					   s->name);
		return -1;
	}

	if (s->password_verify != NULL) {
		ret = s->password_verify(plaintext, params, raw_password, size,
					 error_r);
	} else {
		/* generic verification handler: generate the password and
		   compare it to the one in database */
		s->password_generate(plaintext, params,
				     &generated, &generated_size);
		ret = size != generated_size ? 0 :
			mem_equals_timing_safe(generated, raw_password, size) ? 1 : 0;
	}

	if (ret == 0)
		*error_r = AUTH_LOG_MSG_PASSWORD_MISMATCH;
	return ret;
}

const char *password_get_scheme(const char **password)
{
	const char *p, *suffix, *scheme;

	if (*password == NULL)
		return NULL;

	if (str_begins(*password, "$1$", &suffix)) {
		/* $1$<salt>$<password>[$<ignored>] */
		p = strchr(suffix, '$');
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
		    const unsigned char **raw_password_r, size_t *size_r,
		    const char **error_r)
{
	const struct password_scheme *s;
	enum password_encoding encoding;
	buffer_t *buf;
	size_t len;
	bool guessed_encoding;

	*error_r = NULL;

	s = password_scheme_lookup(scheme, &encoding);
	if (s == NULL) {
		*error_r = "Unknown scheme";
		return 0;
	}

	len = strlen(password);
	if (encoding != PW_ENCODING_NONE && s->raw_password_len != 0 &&
	    strchr(scheme, '.') == NULL) {
		/* encoding not specified. we can guess quite well between
		   base64 and hex encodings. the only problem is distinguishing
		   2 character strings, but there shouldn't be any that short
		   raw_password_lens. */
		encoding = len == s->raw_password_len * 2 ?
			PW_ENCODING_HEX : PW_ENCODING_BASE64;
		guessed_encoding = TRUE;
	} else {
		guessed_encoding = FALSE;
	}

	switch (encoding) {
	case PW_ENCODING_NONE:
		*raw_password_r = (const unsigned char *)password;
		*size_r = len;
		break;
	case PW_ENCODING_HEX:
		buf = t_buffer_create(len / 2 + 1);
		if (hex_to_binary(password, buf) == 0) {
			*raw_password_r = buf->data;
			*size_r = buf->used;
			break;
		}
		if (!guessed_encoding) {
			*error_r = "Input isn't valid HEX encoded data";
			return -1;
		}
		/* check if it's base64-encoded after all. some input lengths
		   produce matching hex and base64 encoded lengths. */
		/* fall through */
	case PW_ENCODING_BASE64:
		buf = t_buffer_create(MAX_BASE64_DECODED_SIZE(len));
		if (base64_decode(password, len, buf) < 0) {
			*error_r = "Input isn't valid base64 encoded data";
			return -1;
		}

		*raw_password_r = buf->data;
		*size_r = buf->used;
		break;
	}
	if (s->raw_password_len != *size_r && s->raw_password_len != 0) {
		/* password has invalid length */
		*error_r = t_strdup_printf(
			"Input length isn't valid (%u instead of %u)",
			(unsigned int)*size_r, s->raw_password_len);
		return -1;
	}
	return 1;
}

bool password_generate(const char *plaintext, const struct password_generate_params *params,
		       const char *scheme,
		       const unsigned char **raw_password_r, size_t *size_r)
{
	const struct password_scheme *s;
	enum password_encoding encoding;

	s = password_scheme_lookup(scheme, &encoding);
	if (s == NULL)
		return FALSE;

	s->password_generate(plaintext, params, raw_password_r, size_r);
	return TRUE;
}

bool password_generate_encoded(const char *plaintext, const struct password_generate_params *params,
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

	s->password_generate(plaintext, params, &raw_password, &size);
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
	char *salt;
	salt = t_malloc_no0(len + 1);
	for (size_t i = 0; i < len; i++)
		salt[i] = salt_chars[i_rand_limit(sizeof(salt_chars) - 1)];
	salt[len] = '\0';
	return salt;
}

bool password_scheme_is_alias(const char *scheme1, const char *scheme2)
{
	const struct password_scheme *s1 = NULL, *s2 = NULL;

	if (*scheme1 == '\0' || *scheme2 == '\0')
		return FALSE;

	scheme1 = t_strcut(scheme1, '.');
	scheme2 = t_strcut(scheme2, '.');

	if (strcasecmp(scheme1, scheme2) == 0)
		return TRUE;

	s1 = hash_table_lookup(password_schemes, scheme1);
	s2 = hash_table_lookup(password_schemes, scheme2);

	/* if they've the same generate function, they're equivalent */
	return s1 != NULL && s2 != NULL &&
		s1->password_generate == s2->password_generate;
}

const char *
password_scheme_detect(const char *plain_password, const char *crypted_password,
		       const struct password_generate_params *params)
{
	struct hash_iterate_context *ctx;
	const char *key;
	const struct password_scheme *scheme;
	const unsigned char *raw_password;
	size_t raw_password_size;
	const char *error;

	ctx = hash_table_iterate_init(password_schemes);
	while (hash_table_iterate(ctx, password_schemes, &key, &scheme)) {
		if (password_decode(crypted_password, scheme->name,
				    &raw_password, &raw_password_size,
				    &error) <= 0)
			continue;

		if (password_verify(plain_password, params, scheme->name,
				    raw_password, raw_password_size,
				    &error) > 0)
			break;
		key = NULL;
	}
	hash_table_iterate_deinit(&ctx);
	return key;
}

int crypt_verify(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		 const unsigned char *raw_password, size_t size,
		 const char **error_r)
{
	const char *password, *crypted;

	if (size > 4 && raw_password[0] == '$' && raw_password[1] == '2' &&
	    raw_password[3] == '$')
		return password_verify(plaintext, params, "BLF-CRYPT",
				       raw_password, size, error_r);

	if (size == 0) {
		/* the default mycrypt() handler would return match */
		return 0;
	}

	if (size > 1 && !g_allow_weak) {
		if (raw_password[0] != '$') {
			*error_r = "Weak password scheme 'DES-CRYPT' used and refused";
			return -1;
		} else if (raw_password[1] == '1') {
			*error_r = "Weak password scheme 'MD5-CRYPT' used and refused";
			return -1;
		}
	}

	password = t_strndup(raw_password, size);
	crypted = mycrypt(plaintext, password);
	if (crypted == NULL) {
		/* really shouldn't happen unless the system is broken */
		*error_r = t_strdup_printf("crypt() failed: %m");
		return -1;
	}

	return str_equals_timing_almost_safe(crypted, password) ? 1 : 0;
}

static int
md5_verify(const char *plaintext, const struct password_generate_params *params,
	   const unsigned char *raw_password, size_t size, const char **error_r)
{
	const char *password, *str, *error;
	const unsigned char *md5_password;
	size_t md5_size;

	password = t_strndup(raw_password, size);
	if (str_begins_with(password, "$1$")) {
		/* MD5-CRYPT */
		str = password_generate_md5_crypt(plaintext, password);
		return str_equals_timing_almost_safe(str, password) ? 1 : 0;
	} else if (password_decode(password, "PLAIN-MD5",
				   &md5_password, &md5_size, &error) <= 0) {
		*error_r = "Not a valid MD5-CRYPT or PLAIN-MD5 password";
		return -1;
	} else {
		return password_verify(plaintext, params, "PLAIN-MD5",
				       md5_password, md5_size, error_r);
	}
}

static int
md5_crypt_verify(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		 const unsigned char *raw_password, size_t size,
		 const char **error_r ATTR_UNUSED)
{
	const char *password, *str;

	password = t_strndup(raw_password, size);
	str = password_generate_md5_crypt(plaintext, password);
	return str_equals_timing_almost_safe(str, password) ? 1 : 0;
}

static void
md5_crypt_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		   const unsigned char **raw_password_r, size_t *size_r)
{
	const char *password;
	const char *salt;

	salt = password_generate_salt(8);

	password = password_generate_md5_crypt(plaintext, salt);
	*raw_password_r = (const unsigned char *)password;
	*size_r = strlen(password);
}

static void
sha1_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
	      const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc_no0(SHA1_RESULTLEN);
	sha1_get_digest(plaintext, strlen(plaintext), digest);

	*raw_password_r = digest;
	*size_r = SHA1_RESULTLEN;
}

static void
sha256_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc_no0(SHA256_RESULTLEN);
	sha256_get_digest(plaintext, strlen(plaintext), digest);

	*raw_password_r = digest;
	*size_r = SHA256_RESULTLEN;
}

static void
sha512_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc_no0(SHA512_RESULTLEN);
	sha512_get_digest(plaintext, strlen(plaintext), digest);

	*raw_password_r = digest;
	*size_r = SHA512_RESULTLEN;
}

static void
ssha_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
	      const unsigned char **raw_password_r, size_t *size_r)
{
#define SSHA_SALT_LEN 4
	unsigned char *digest, *salt;
	struct sha1_ctxt ctx;

	digest = t_malloc_no0(SHA1_RESULTLEN + SSHA_SALT_LEN);
	salt = digest + SHA1_RESULTLEN;
	random_fill(salt, SSHA_SALT_LEN);

	sha1_init(&ctx);
	sha1_loop(&ctx, plaintext, strlen(plaintext));
	sha1_loop(&ctx, salt, SSHA_SALT_LEN);
	sha1_result(&ctx, digest);

	*raw_password_r = digest;
	*size_r = SHA1_RESULTLEN + SSHA_SALT_LEN;
}

static int ssha_verify(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		       const unsigned char *raw_password, size_t size,
		       const char **error_r)
{
	unsigned char sha1_digest[SHA1_RESULTLEN];
	struct sha1_ctxt ctx;

	/* format: <SHA1 hash><salt> */
	if (size <= SHA1_RESULTLEN) {
		*error_r = "SSHA password is too short";
		return -1;
	}

	sha1_init(&ctx);
	sha1_loop(&ctx, plaintext, strlen(plaintext));
	sha1_loop(&ctx, raw_password + SHA1_RESULTLEN, size - SHA1_RESULTLEN);
	sha1_result(&ctx, sha1_digest);
	return mem_equals_timing_safe(sha1_digest, raw_password, SHA1_RESULTLEN) ? 1 : 0;
}

static void
ssha256_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		 const unsigned char **raw_password_r, size_t *size_r)
{
#define SSHA256_SALT_LEN 4
	unsigned char *digest, *salt;
	struct sha256_ctx ctx;

	digest = t_malloc_no0(SHA256_RESULTLEN + SSHA256_SALT_LEN);
	salt = digest + SHA256_RESULTLEN;
	random_fill(salt, SSHA256_SALT_LEN);

	sha256_init(&ctx);
	sha256_loop(&ctx, plaintext, strlen(plaintext));
	sha256_loop(&ctx, salt, SSHA256_SALT_LEN);
	sha256_result(&ctx, digest);

	*raw_password_r = digest;
	*size_r = SHA256_RESULTLEN + SSHA256_SALT_LEN;
}

static int ssha256_verify(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
			  const unsigned char *raw_password, size_t size,
			  const char **error_r)
{
	unsigned char sha256_digest[SHA256_RESULTLEN];
	struct sha256_ctx ctx;

	/* format: <SHA256 hash><salt> */
	if (size <= SHA256_RESULTLEN) {
		*error_r = "SSHA256 password is too short";
		return -1;
	}

	sha256_init(&ctx);
	sha256_loop(&ctx, plaintext, strlen(plaintext));
	sha256_loop(&ctx, raw_password + SHA256_RESULTLEN,
		    size - SHA256_RESULTLEN);
	sha256_result(&ctx, sha256_digest);
	return mem_equals_timing_safe(sha256_digest, raw_password,
				      SHA256_RESULTLEN) ? 1 : 0;
}

static void
ssha512_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		 const unsigned char **raw_password_r, size_t *size_r)
{
#define SSHA512_SALT_LEN 4
	unsigned char *digest, *salt;
	struct sha512_ctx ctx;

	digest = t_malloc_no0(SHA512_RESULTLEN + SSHA512_SALT_LEN);
	salt = digest + SHA512_RESULTLEN;
	random_fill(salt, SSHA512_SALT_LEN);

	sha512_init(&ctx);
	sha512_loop(&ctx, plaintext, strlen(plaintext));
	sha512_loop(&ctx, salt, SSHA512_SALT_LEN);
	sha512_result(&ctx, digest);

	*raw_password_r = digest;
	*size_r = SHA512_RESULTLEN + SSHA512_SALT_LEN;
}

static int ssha512_verify(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
			  const unsigned char *raw_password, size_t size,
			  const char **error_r)
{
	unsigned char sha512_digest[SHA512_RESULTLEN];
	struct sha512_ctx ctx;

	/* format: <SHA512 hash><salt> */
	if (size <= SHA512_RESULTLEN) {
		*error_r = "SSHA512 password is too short";
		return -1;
	}

	sha512_init(&ctx);
	sha512_loop(&ctx, plaintext, strlen(plaintext));
	sha512_loop(&ctx, raw_password + SHA512_RESULTLEN,
		    size - SHA512_RESULTLEN);
	sha512_result(&ctx, sha512_digest);
	return mem_equals_timing_safe(sha512_digest, raw_password,
				      SHA512_RESULTLEN) ? 1 : 0;
}

static void
smd5_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
	      const unsigned char **raw_password_r, size_t *size_r)
{
#define SMD5_SALT_LEN 4
	unsigned char *digest, *salt;
	struct md5_context ctx;

	digest = t_malloc_no0(MD5_RESULTLEN + SMD5_SALT_LEN);
	salt = digest + MD5_RESULTLEN;
	random_fill(salt, SMD5_SALT_LEN);

	md5_init(&ctx);
	md5_update(&ctx, plaintext, strlen(plaintext));
	md5_update(&ctx, salt, SMD5_SALT_LEN);
	md5_final(&ctx, digest);

	*raw_password_r = digest;
	*size_r = MD5_RESULTLEN + SMD5_SALT_LEN;
}

static int smd5_verify(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		       const unsigned char *raw_password, size_t size,
		       const char **error_r)
{
	unsigned char md5_digest[MD5_RESULTLEN];
	struct md5_context ctx;

	/* format: <MD5 hash><salt> */
	if (size <= MD5_RESULTLEN) {
		*error_r = "SMD5 password is too short";
		return -1;
	}

	md5_init(&ctx);
	md5_update(&ctx, plaintext, strlen(plaintext));
	md5_update(&ctx, raw_password + MD5_RESULTLEN, size - MD5_RESULTLEN);
	md5_final(&ctx, md5_digest);
	return mem_equals_timing_safe(md5_digest, raw_password, MD5_RESULTLEN) ? 1 : 0;
}

static void
plain_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
	       const unsigned char **raw_password_r, size_t *size_r)
{
	*raw_password_r = (const unsigned char *)plaintext,
	*size_r = strlen(plaintext);
}

static int
plain_verify(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
	     const unsigned char *raw_password, size_t size,
	     const char **error_r ATTR_UNUSED)
{
	size_t plaintext_len = strlen(plaintext);

	if (plaintext_len != size)
		return 0;
	return mem_equals_timing_safe(plaintext, raw_password, size) ? 1 : 0;
}

static int
plain_trunc_verify(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		   const unsigned char *raw_password, size_t size,
		   const char **error_r)
{
	size_t i, plaintext_len, trunc_len = 0;

	/* format: <length>-<password> */
	for (i = 0; i < size; i++) {
		if (raw_password[i] >= '0' && raw_password[i] <= '9')
			trunc_len = trunc_len*10 + raw_password[i]-'0';
		else
			break;
	}
	if (i == size || raw_password[i] != '-') {
		*error_r = "PLAIN-TRUNC missing length: prefix";
		return -1;
	}
	i++;

	plaintext_len = strlen(plaintext);
	if (size-i == trunc_len && plaintext_len >= trunc_len) {
		/* possibly truncated password. allow the given password as
		   long as the prefix matches. */
		return mem_equals_timing_safe(raw_password+i, plaintext, trunc_len) ? 1 : 0;
	}
	return plaintext_len == size-i &&
		mem_equals_timing_safe(raw_password+i, plaintext, plaintext_len) ? 1 : 0;
}

static void
cram_md5_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		  const unsigned char **raw_password_r, size_t *size_r)
{
	struct hmac_context ctx;
	unsigned char *context_digest;

	context_digest = t_malloc_no0(CRAM_MD5_CONTEXTLEN);
	hmac_init(&ctx, (const unsigned char *)plaintext,
		  strlen(plaintext), &hash_method_md5);
	hmac_md5_get_cram_context(&ctx, context_digest);

	*raw_password_r = context_digest;
	*size_r = CRAM_MD5_CONTEXTLEN;
}

static void
digest_md5_generate(const char *plaintext, const struct password_generate_params *params,
		    const unsigned char **raw_password_r, size_t *size_r)
{
	const char *realm, *str, *user;
	unsigned char *digest;

	if (params->user == NULL)
		i_fatal("digest_md5_generate(): username not given");

	user = params->user;


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
	digest = t_malloc_no0(MD5_RESULTLEN);
	str = t_strdup_printf("%s:%s:%s", user, realm, plaintext);
	md5_get_digest(str, strlen(str), digest);

	*raw_password_r = digest;
	*size_r = MD5_RESULTLEN;
}

static void
plain_md4_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		   const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc_no0(MD4_RESULTLEN);
	md4_get_digest(plaintext, strlen(plaintext), digest);

	*raw_password_r = digest;
	*size_r = MD4_RESULTLEN;
}

static void
plain_md5_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		   const unsigned char **raw_password_r, size_t *size_r)
{
	unsigned char *digest;

	digest = t_malloc_no0(MD5_RESULTLEN);
	md5_get_digest(plaintext, strlen(plaintext), digest);

	*raw_password_r = digest;
	*size_r = MD5_RESULTLEN;
}

static int otp_verify(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
		      const unsigned char *raw_password, size_t size,
		      const char **error_r)
{
	const char *password, *generated;

	password = t_strndup(raw_password, size);
	if (password_generate_otp(plaintext, password, UINT_MAX, &generated) < 0) {
		*error_r = "Invalid OTP data in passdb";
		return -1;
	}

	return strcasecmp(password, generated) == 0 ? 1 : 0;
}

static void
otp_generate(const char *plaintext, const struct password_generate_params *params ATTR_UNUSED,
	     const unsigned char **raw_password_r, size_t *size_r)
{
	const char *password;

	if (password_generate_otp(plaintext, NULL, OTP_HASH_SHA1, &password) < 0)
		i_unreached();
	*raw_password_r = (const unsigned char *)password;
	*size_r = strlen(password);
}

static const struct password_scheme builtin_schemes[] = {
	{
		.name = "MD5",
		.default_encoding = PW_ENCODING_NONE,
		.raw_password_len = 0,
		.weak = TRUE,
		.password_verify = md5_verify,
		.password_generate = md5_crypt_generate,
	},
	{
		.name = "MD5-CRYPT",
		.default_encoding = PW_ENCODING_NONE,
		.weak = TRUE,
		.raw_password_len = 0,
		.password_verify = md5_crypt_verify,
		.password_generate = md5_crypt_generate,
	},
	{
		.name = "SHA",
		.default_encoding = PW_ENCODING_BASE64,
		.raw_password_len = SHA1_RESULTLEN,
		.password_verify = NULL,
		.password_generate = sha1_generate,
	},
	{
		.name = "SHA1",
		.default_encoding = PW_ENCODING_BASE64,
		.raw_password_len = SHA1_RESULTLEN,
		.password_verify = NULL,
		.password_generate = sha1_generate,
	},
	{
		.name = "SHA256",
		.default_encoding = PW_ENCODING_BASE64,
		.raw_password_len = SHA256_RESULTLEN,
		.password_verify = NULL,
		.password_generate = sha256_generate,
	},
	{
		.name = "SHA512",
		.default_encoding = PW_ENCODING_BASE64,
		.raw_password_len = SHA512_RESULTLEN,
		.password_verify = NULL,
		.password_generate = sha512_generate,
	},
	{
		.name = "SMD5",
		.default_encoding = PW_ENCODING_BASE64,
		.raw_password_len = 0,
		.weak = TRUE,
		.password_verify = smd5_verify,
		.password_generate = smd5_generate,
	},
	{
		.name = "SSHA",
		.default_encoding = PW_ENCODING_BASE64,
		.raw_password_len = 0,
		.password_verify = ssha_verify,
		.password_generate = ssha_generate,
	},
	{
		.name = "SSHA256",
		.default_encoding = PW_ENCODING_BASE64,
		.raw_password_len = 0,
		.password_verify = ssha256_verify,
		.password_generate = ssha256_generate,
	},
	{
		.name = "SSHA512",
		.default_encoding = PW_ENCODING_BASE64,
		.raw_password_len = 0,
		.password_verify = ssha512_verify,
		.password_generate = ssha512_generate,
	},
	{
		.name = "PLAIN",
		.default_encoding = PW_ENCODING_NONE,
		.raw_password_len = 0,
		.password_verify = plain_verify,
		.password_generate = plain_generate,
	},
	{
		.name = "CLEAR",
		.default_encoding = PW_ENCODING_NONE,
		.raw_password_len = 0,
		.password_verify = plain_verify,
		.password_generate = plain_generate,
	},
	{
		.name = "CLEARTEXT",
		.default_encoding = PW_ENCODING_NONE,
		.raw_password_len = 0,
		.password_verify = plain_verify,
		.password_generate = plain_generate,
	},
	{
		.name = "PLAIN-TRUNC",
		.default_encoding = PW_ENCODING_NONE,
		.raw_password_len = 0,
		.password_verify = plain_trunc_verify,
		.password_generate = plain_generate,
	},
	{
		.name = "CRAM-MD5",
		.default_encoding = PW_ENCODING_HEX,
		.raw_password_len = CRAM_MD5_CONTEXTLEN,
		.password_verify = NULL,
		.password_generate = cram_md5_generate,
	},
	{
		.name = "SCRAM-SHA-1",
		.default_encoding = PW_ENCODING_NONE,
		.raw_password_len = 0,
		.password_verify = scram_sha1_verify,
		.password_generate = scram_sha1_generate,
	},
	{
		.name = "SCRAM-SHA-256",
		.default_encoding = PW_ENCODING_NONE,
		.raw_password_len = 0,
		.password_verify = scram_sha256_verify,
		.password_generate = scram_sha256_generate,
	},
	{
		.name = "HMAC-MD5",
		.default_encoding = PW_ENCODING_HEX,
		.raw_password_len = CRAM_MD5_CONTEXTLEN,
		.weak = TRUE,
		.password_verify = NULL,
		.password_generate = cram_md5_generate,
	},
	{
		.name = "DIGEST-MD5",
		.default_encoding = PW_ENCODING_HEX,
		.raw_password_len = MD5_RESULTLEN,
		.password_verify = NULL,
		.password_generate = digest_md5_generate,
	},
	{
		.name = "PLAIN-MD4",
		.default_encoding = PW_ENCODING_HEX,
		.raw_password_len = MD4_RESULTLEN,
		.weak = TRUE,
		.password_verify = NULL,
		.password_generate = plain_md4_generate,
	},
	{
		.name = "PLAIN-MD5",
		.default_encoding = PW_ENCODING_HEX,
		.raw_password_len = MD5_RESULTLEN,
		.weak = TRUE,
		.password_verify = NULL,
		.password_generate = plain_md5_generate,
	},
	{
		.name = "LDAP-MD5",
		.default_encoding = PW_ENCODING_BASE64,
		.raw_password_len = MD5_RESULTLEN,
		.weak = TRUE,
		.password_verify = NULL,
		.password_generate = plain_md5_generate,
	},
	{
		.name = "OTP",
		.default_encoding = PW_ENCODING_NONE,
		.raw_password_len = 0,
		.password_verify = otp_verify,
		.password_generate = otp_generate,
	},
	{
		.name = "PBKDF2",
		.default_encoding = PW_ENCODING_NONE,
		.raw_password_len = 0,
		.password_verify = pbkdf2_verify,
		.password_generate = pbkdf2_generate,
	},
};

void password_scheme_register(const struct password_scheme *scheme)
{
	if (password_scheme_lookup_name(scheme->name) != NULL) {
		i_panic("password_scheme_register(%s): Already registered",
			scheme->name);
	}
	hash_table_insert(password_schemes, scheme->name, scheme);
}

void password_scheme_unregister(const struct password_scheme *scheme)
{
	if (!hash_table_try_remove(password_schemes, scheme->name))
		i_panic("password_scheme_unregister(%s): Not registered", scheme->name);
}

void password_schemes_get(ARRAY_TYPE(password_scheme_p) *schemes_r)
{
        struct hash_iterate_context *ctx;
        const char *key;
        const struct password_scheme *scheme;
        ctx = hash_table_iterate_init(password_schemes);
        while(hash_table_iterate(ctx, password_schemes, &key, &scheme)) {
		array_push_back(schemes_r, &scheme);
        }
	hash_table_iterate_deinit(&ctx);
}

void password_schemes_init(void)
{
	unsigned int i;

	hash_table_create(&password_schemes, default_pool,
			  N_ELEMENTS(builtin_schemes)*2, strfastcase_hash,
			  strcasecmp);
	for (i = 0; i < N_ELEMENTS(builtin_schemes); i++)
		password_scheme_register(&builtin_schemes[i]);
	password_scheme_register_crypt();
#ifdef HAVE_LIBSODIUM
	password_scheme_register_sodium();
#endif
}

void password_schemes_deinit(void)
{
	hash_table_destroy(&password_schemes);
}
