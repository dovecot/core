/*
 * SCRAM-SHA-1 SASL authentication, see RFC-5802
 *
 * Copyright (c) 2012 Florian Zeitz <florob@babelmonkeys.de>
 *
 * This software is released under the MIT license.
 */


#include "lib.h"
#include "safe-memset.h"
#include "base64.h"
#include "buffer.h"
#include "hmac.h"
#include "hash-method.h"
#include "sha1.h"
#include "sha2.h"
#include "str.h"
#include "auth-scram.h"
#include "password-scheme.h"

int scram_verify(const struct hash_method *hmethod, const char *scheme_name,
		 const char *plaintext, const unsigned char *raw_password,
		 size_t size, const char **error_r)
{
	struct hmac_context ctx;
	const char *salt_base64;
	unsigned int iter_count;
	const unsigned char *salt;
	size_t salt_len;
	unsigned char salted_password[hmethod->digest_size];
	unsigned char client_key[hmethod->digest_size];
	unsigned char stored_key[hmethod->digest_size];
	unsigned char calculated_stored_key[hmethod->digest_size];
	unsigned char server_key[hmethod->digest_size];
	int ret;

	if (scram_scheme_parse(hmethod, scheme_name, raw_password, size,
			       &iter_count, &salt_base64,
			       stored_key, server_key, error_r) < 0)
		return -1;

	salt = buffer_get_data(t_base64_decode_str(salt_base64), &salt_len);

	/* FIXME: credentials should be SASLprepped UTF8 data here */
	auth_scram_hi(hmethod,
		      (const unsigned char *)plaintext, strlen(plaintext),
		      salt, salt_len, iter_count, salted_password);

	/* Calculate ClientKey */
	hmac_init(&ctx, salted_password, sizeof(salted_password), hmethod);
	hmac_update(&ctx, "Client Key", 10);
	hmac_final(&ctx, client_key);

	/* Calculate StoredKey */
	hash_method_get_digest(hmethod, client_key, sizeof(client_key),
			       calculated_stored_key);
	ret = mem_equals_timing_safe(stored_key, calculated_stored_key,
				     sizeof(stored_key)) ? 1 : 0;

	safe_memset(salted_password, 0, sizeof(salted_password));
	safe_memset(client_key, 0, sizeof(client_key));
	safe_memset(stored_key, 0, sizeof(stored_key));

	return ret;
}

void scram_generate(const struct hash_method *hmethod, const char *plaintext,
		    unsigned int rounds, const unsigned char **raw_password_r,
		    size_t *size_r)
{
	string_t *str;
	unsigned int iter_count;
	const char *salt;
	unsigned char server_key[hmethod->digest_size];
	unsigned char stored_key[hmethod->digest_size];

	auth_scram_generate_key_data(hmethod, plaintext, rounds,
				     &iter_count, &salt,
				     stored_key, server_key);

	str = t_str_new(strlen(salt) + 256);
	str_printfa(str, "%d,", iter_count);
	str_append(str, salt);
	str_append_c(str, ',');
	base64_encode(stored_key, sizeof(stored_key), str);
	str_append_c(str, ',');
	base64_encode(server_key, sizeof(server_key), str);

	safe_memset(server_key, 0, sizeof(server_key));
	safe_memset(stored_key, 0, sizeof(stored_key));

	*raw_password_r = (const unsigned char *)str_c(str);
	*size_r = str_len(str);
}

int scram_sha1_verify(const char *plaintext,
		      const struct password_generate_params *params ATTR_UNUSED,
		      const unsigned char *raw_password, size_t size,
		      const char **error_r)
{
	return scram_verify(&hash_method_sha1, "SCRAM-SHA-1", plaintext,
			    raw_password, size, error_r);
}

void scram_sha1_generate(const char *plaintext,
			 const struct password_generate_params *params,
                         const unsigned char **raw_password_r, size_t *size_r)
{
	scram_generate(&hash_method_sha1, plaintext, params->rounds,
		       raw_password_r, size_r);
}

int scram_sha256_verify(const char *plaintext,
			const struct password_generate_params *params ATTR_UNUSED,
			const unsigned char *raw_password, size_t size,
			const char **error_r)
{
	return scram_verify(&hash_method_sha256, "SCRAM-SHA-256", plaintext,
			    raw_password, size, error_r);
}

void scram_sha256_generate(const char *plaintext,
			   const struct password_generate_params *params,
			   const unsigned char **raw_password_r, size_t *size_r)
{
	scram_generate(&hash_method_sha256, plaintext, params->rounds,
		       raw_password_r, size_r);
}
