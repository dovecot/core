/* Copyright (c) 2022-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "safe-memset.h"
#include "hmac.h"

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
