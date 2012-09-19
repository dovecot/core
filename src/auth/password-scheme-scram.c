/*
 * SCRAM-SHA-1 SASL authentication, see RFC-5802
 *
 * Copyright (c) 2012 Florian Zeitz <florob@babelmonkeys.de>
 *
 * This software is released under the MIT license.
 */

#include <stdlib.h>

#include "lib.h"
#include "safe-memset.h"
#include "base64.h"
#include "buffer.h"
#include "hmac.h"
#include "randgen.h"
#include "sha1.h"
#include "str.h"
#include "password-scheme.h"

/* SCRAM hash iteration count. RFC says it SHOULD be at least 4096 */
#define SCRAM_ITERATE_COUNT 4096

static void Hi(const unsigned char *str, size_t str_size,
	       const unsigned char *salt, size_t salt_size, unsigned int i,
	       unsigned char result[SHA1_RESULTLEN])
{
	struct hmac_context ctx;
	unsigned char U[SHA1_RESULTLEN];
	unsigned int j, k;

	/* Calculate U1 */
	hmac_init(&ctx, str, str_size, &hash_method_sha1);
	hmac_update(&ctx, salt, salt_size);
	hmac_update(&ctx, "\0\0\0\1", 4);
	hmac_final(&ctx, U);

	memcpy(result, U, SHA1_RESULTLEN);

	/* Calculate U2 to Ui and Hi */
	for (j = 2; j <= i; j++) {
		hmac_init(&ctx, str, str_size, &hash_method_sha1);
		hmac_update(&ctx, U, sizeof(U));
		hmac_final(&ctx, U);
		for (k = 0; k < SHA1_RESULTLEN; k++)
			result[k] ^= U[k];
	}
}

/* password string format: iter,salt,stored_key,server_key */

int scram_sha1_verify(const char *plaintext, const char *user ATTR_UNUSED,
		      const unsigned char *raw_password, size_t size,
		      const char **error_r ATTR_UNUSED)
{
	struct hmac_context ctx;
	string_t *str;
	const char *const *fields;
	int iter;
	const unsigned char *salt;
	size_t salt_len;
	unsigned char salted_password[SHA1_RESULTLEN];
	unsigned char client_key[SHA1_RESULTLEN];
	unsigned char stored_key[SHA1_RESULTLEN];

	fields = t_strsplit(t_strndup(raw_password, size), ",");
	iter = atoi(fields[0]);
	salt = buffer_get_data(t_base64_decode_str(fields[1]), &salt_len);
	str = t_str_new(strlen(fields[2]));

	/* FIXME: credentials should be SASLprepped UTF8 data here */
	Hi((const unsigned char *)plaintext, strlen(plaintext), salt, salt_len,
	   iter, salted_password);

	/* Calculate ClientKey */
	hmac_init(&ctx, salted_password, sizeof(salted_password),
		  &hash_method_sha1);
	hmac_update(&ctx, "Client Key", 10);
	hmac_final(&ctx, client_key);

	/* Calculate StoredKey */
	sha1_get_digest(client_key, sizeof(client_key), stored_key);
	base64_encode(stored_key, sizeof(stored_key), str);

	safe_memset(salted_password, 0, sizeof(salted_password));
	safe_memset(client_key, 0, sizeof(client_key));
	safe_memset(stored_key, 0, sizeof(stored_key));

	return strcmp(fields[2], str_c(str)) == 0 ? 1 : 0;
}

void scram_sha1_generate(const char *plaintext, const char *user ATTR_UNUSED,
			 const unsigned char **raw_password_r, size_t *size_r)
{
	string_t *str;
	struct hmac_context ctx;
	unsigned char salt[16];
	unsigned char salted_password[SHA1_RESULTLEN];
	unsigned char client_key[SHA1_RESULTLEN];
	unsigned char server_key[SHA1_RESULTLEN];
	unsigned char stored_key[SHA1_RESULTLEN];

	random_fill(salt, sizeof(salt));

	str = t_str_new(MAX_BASE64_ENCODED_SIZE(sizeof(salt)));
	str_printfa(str, "%i,", SCRAM_ITERATE_COUNT);
	base64_encode(salt, sizeof(salt), str);

	/* FIXME: credentials should be SASLprepped UTF8 data here */
	Hi((const unsigned char *)plaintext, strlen(plaintext), salt,
	   sizeof(salt), SCRAM_ITERATE_COUNT, salted_password);

	/* Calculate ClientKey */
	hmac_init(&ctx, salted_password, sizeof(salted_password),
		  &hash_method_sha1);
	hmac_update(&ctx, "Client Key", 10);
	hmac_final(&ctx, client_key);

	/* Calculate StoredKey */
	sha1_get_digest(client_key, sizeof(client_key), stored_key);
	str_append_c(str, ',');
	base64_encode(stored_key, sizeof(stored_key), str);

	/* Calculate ServerKey */
	hmac_init(&ctx, salted_password, sizeof(salted_password),
		  &hash_method_sha1);
	hmac_update(&ctx, "Server Key", 10);
	hmac_final(&ctx, server_key);
	str_append_c(str, ',');
	base64_encode(server_key, sizeof(server_key), str);

	safe_memset(salted_password, 0, sizeof(salted_password));
	safe_memset(client_key, 0, sizeof(client_key));
	safe_memset(server_key, 0, sizeof(server_key));
	safe_memset(stored_key, 0, sizeof(stored_key));

	*raw_password_r = (const unsigned char *)str_c(str);
	*size_r = str_len(str);
}
