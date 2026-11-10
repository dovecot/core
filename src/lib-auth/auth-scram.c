/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "safe-memset.h"
#include "base64.h"
#include "hmac.h"
#include "randgen.h"
#include "str.h"

#include "auth-scram.h"

void auth_scram_key_data_clear(struct auth_scram_key_data *data)
{
	if (data->hmethod != NULL) {
		if (data->stored_key != NULL) {
			safe_memset(data->stored_key, 0,
				    data->hmethod->digest_size);
		}
		if (data->server_key != NULL) {
			safe_memset(data->server_key, 0,
				    data->hmethod->digest_size);
		}
	} else {
		i_assert(data->stored_key == NULL);
		i_assert(data->server_key == NULL);
	}
}

void auth_scram_hi(const struct hash_method *hmethod,
		   const unsigned char *str, size_t str_size,
		   const unsigned char *salt, size_t salt_size, unsigned int i,
		   unsigned char *result)
{
	struct hmac_context ctx;
	unsigned char U[hmethod->digest_size];
	unsigned int j, k;

	/* Hi(str, salt, i):

	   U1   := HMAC(str, salt + INT(1))
	   U2   := HMAC(str, U1)
	   ...
	   Ui-1 := HMAC(str, Ui-2)
	   Ui   := HMAC(str, Ui-1)

	   Hi := U1 XOR U2 XOR ... XOR Ui

	    where "i" is the iteration count, "+" is the string concatenation
	    operator, and INT(g) is a 4-octet encoding of the integer g, most
	    significant octet first.
	*/

	/* Calculate U1 */
	hmac_init(&ctx, str, str_size, hmethod);
	hmac_update(&ctx, salt, salt_size);
	hmac_update(&ctx, "\0\0\0\1", 4);
	hmac_final(&ctx, U);

	memcpy(result, U, hmethod->digest_size);

	/* Calculate U2 to Ui and Hi */
	for (j = 2; j <= i; j++) {
		hmac_init(&ctx, str, str_size, hmethod);
		hmac_update(&ctx, U, sizeof(U));
		hmac_final(&ctx, U);
		for (k = 0; k < hmethod->digest_size; k++)
			result[k] ^= U[k];
	}
}

void auth_scram_generate_key_data(const struct hash_method *hmethod,
				  const char *plaintext, unsigned int rounds,
				  unsigned int *iter_count_r,
				  const char **salt_r,
				  unsigned char stored_key_r[],
				  unsigned char server_key_r[])
{
	struct hmac_context ctx;
	unsigned char salt[16];
	unsigned char salted_password[hmethod->digest_size];
	unsigned char client_key[hmethod->digest_size];

	if (rounds == 0)
		rounds = AUTH_SCRAM_DEFAULT_ITERATE_COUNT;
	else {
		rounds = I_MAX(I_MIN(AUTH_SCRAM_MAX_ITERATE_COUNT, rounds),
			       AUTH_SCRAM_MIN_ITERATE_COUNT);
	}
	*iter_count_r = rounds;

	random_fill(salt, sizeof(salt));
	*salt_r = str_c(t_base64_encode(0, 0, salt, sizeof(salt)));

	/* FIXME: credentials should be SASLprepped UTF8 data here */
	auth_scram_hi(hmethod,
		      (const unsigned char *)plaintext, strlen(plaintext),
		      salt, sizeof(salt), rounds, salted_password);

	/* Calculate ClientKey */
	hmac_init(&ctx, salted_password, sizeof(salted_password), hmethod);
	hmac_update(&ctx, "Client Key", 10);
	hmac_final(&ctx, client_key);

	/* Calculate StoredKey */
	hash_method_get_digest(hmethod, client_key, sizeof(client_key),
			       stored_key_r);

	/* Calculate ServerKey */
	hmac_init(&ctx, salted_password, sizeof(salted_password), hmethod);
	hmac_update(&ctx, "Server Key", 10);
	hmac_final(&ctx, server_key_r);

	safe_memset(salted_password, 0, sizeof(salted_password));
	safe_memset(client_key, 0, sizeof(client_key));
}

int auth_scram_credentials_parse(const struct hash_method *hmethod,
				 const char *name,
				 const unsigned char *credentials, size_t size,
				 unsigned int *iter_count_r,
				 const char **salt_r,
				 unsigned char stored_key_r[],
				 unsigned char server_key_r[],
				 const char **error_r)
{
	const char *const *fields;
	unsigned int iter_count;
	buffer_t *stored_key, *server_key;
	int ret = -1;

	/* password string format: iter,salt,stored_key,server_key */
	fields = t_strsplit(t_strndup(credentials, size), ",");

	if (str_array_length(fields) != 4) {
		*error_r = t_strdup_printf(
			"Invalid %s passdb entry format", name);
		return -1;
	}
	if (str_to_uint(fields[0], &iter_count) < 0 ||
	    iter_count < AUTH_SCRAM_MIN_ITERATE_COUNT ||
	    iter_count > AUTH_SCRAM_MAX_ITERATE_COUNT) {
		*error_r = t_strdup_printf(
			"Invalid %s iteration count in passdb", name);
		return -1;
	}

	stored_key = t_buffer_create(
		MAX_BASE64_DECODED_SIZE(strlen(fields[2])));
	server_key = t_buffer_create(
		MAX_BASE64_DECODED_SIZE(strlen(fields[3])));
	if (base64_decode(fields[2], strlen(fields[2]), stored_key) < 0 ||
	    stored_key->used != hmethod->digest_size) {
		*error_r = t_strdup_printf(
			"Invalid %s StoredKey in passdb", name);
	} else if (base64_decode(fields[3], strlen(fields[3]), server_key) < 0 ||
		   server_key->used != hmethod->digest_size) {
		*error_r = t_strdup_printf(
			"Invalid %s ServerKey in passdb", name);
	} else {
		*iter_count_r = iter_count;
		*salt_r = fields[1];
		memcpy(stored_key_r, stored_key->data, hmethod->digest_size);
		memcpy(server_key_r, server_key->data, hmethod->digest_size);
		ret = 0;
	}
	buffer_clear_safe(stored_key);
	buffer_clear_safe(server_key);
	return ret;
}
