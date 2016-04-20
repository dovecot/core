#include "lib.h"
#include "buffer.h"
#include "hash-method.h"
#include "hmac.h"
#include "pkcs5.h"

#include <stdint.h>
#include <arpa/inet.h>

static
int pkcs5_pbkdf1(const struct hash_method *hash,
	const unsigned char *password, size_t password_len,
	const unsigned char *salt, size_t salt_len,
	unsigned int iter, uint32_t length,
	buffer_t *result)
{
	if (length < 1 ||
		length > hash->digest_size) return -1;
	if (iter < 1) return -1;

	unsigned char dk[hash->digest_size];
	unsigned char ctx[hash->context_size];

	hash->init(ctx);
	hash->loop(ctx, password, password_len);
	hash->loop(ctx, salt, salt_len);
	hash->result(ctx, dk);
	length--;

	for(;length>0;length--) {
		hash->init(ctx);
		hash->loop(ctx, dk, hash->digest_size);
		hash->result(ctx, dk);
	}

	buffer_append(result, dk, hash->digest_size);

	return 0;
}

static
int pkcs5_pbkdf2(const struct hash_method *hash,
	const unsigned char *password, size_t password_len,
	const unsigned char *salt, size_t salt_len,
	unsigned int iter, uint32_t length,
	buffer_t *result)
{
	if (length < 1 || iter < 1) return -1;

	size_t l = (length + hash->digest_size - 1)/hash->digest_size; /* same as ceil(length/hash->digest_size) */
	unsigned char dk[l * hash->digest_size];
	unsigned char *block;
	struct hmac_context hctx;
	unsigned int c,i,t;
	unsigned char U_c[hash->digest_size];

	for(t = 0; t < l; t++) {
		block = &(dk[t*hash->digest_size]);
		/* U_1 = PRF(Password, Salt|| INT_BE32(Block_Number)) */
		c = htonl(t+1);
		hmac_init(&hctx, password, password_len, hash);
		hmac_update(&hctx, salt, salt_len);
		hmac_update(&hctx, &c, sizeof(c));
		hmac_final(&hctx, U_c);
		/* block = U_1 ^ .. ^ U_iter */
		memcpy(block, U_c, hash->digest_size);
		/* U_c = PRF(Password, U_c-1) */
		for(c = 1; c < iter; c++) {
			hmac_init(&hctx, password, password_len, hash);
			hmac_update(&hctx, U_c, hash->digest_size);
			hmac_final(&hctx, U_c);
			for(i = 0; i < hash->digest_size; i++)
				block[i] ^= U_c[i];
		}
	}

	buffer_append(result, dk, length);

	return 0;
}

int pkcs5_pbkdf(enum pkcs5_pbkdf_mode mode, const struct hash_method *hash,
	const unsigned char *password, size_t password_len,
	const unsigned char *salt, size_t salt_len,
	unsigned int iterations, uint32_t dk_len,
	buffer_t *result)
{
	if (mode == PKCS5_PBKDF1)
		return pkcs5_pbkdf1(hash,password,password_len,
			salt,salt_len,iterations,dk_len,result);
	else if (mode == PKCS5_PBKDF2)
		return pkcs5_pbkdf2(hash,password,password_len,
			salt,salt_len,iterations,dk_len,result);
	i_unreached();
}
