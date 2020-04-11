/*
 * NTLM and NTLMv2 hash generation.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "buffer.h"
#include "compat.h"
#include "safe-memset.h"
#include "md4.h"
#include "md5.h"
#include "hmac.h"
#include "ntlm.h"
#include "ntlm-des.h"

#include <ctype.h>

static unsigned char *
t_unicode_str(const char *src, bool ucase, size_t *size)
{
	buffer_t *wstr;

	wstr = buffer_create_dynamic(unsafe_data_stack_pool, 32);
	for ( ; *src != '\0'; src++) {
		buffer_append_c(wstr, ucase ? i_toupper(*src) : *src);
		buffer_append_c(wstr, '\0');
	}

	*size = wstr->used;
	return buffer_free_without_data(&wstr);
}

void lm_hash(const char *passwd, unsigned char hash[LM_HASH_SIZE])
{
	static const unsigned char lm_magic[8] = "KGS!@#$%";
	unsigned char buffer[14];
	unsigned int i;

	i_zero(&buffer);
	memcpy(buffer, passwd, I_MIN(sizeof(buffer), strlen(passwd)));

	for (i = 0; i < sizeof(buffer); i++)
		buffer[i] = i_toupper(buffer[i]);

	deshash(hash, buffer, lm_magic);
	deshash(hash + 8, buffer + 7, lm_magic);

	safe_memset(buffer, 0, sizeof(buffer));
}

void ntlm_v1_hash(const char *passwd, unsigned char hash[NTLMSSP_HASH_SIZE])
{
	size_t len;
	void *wpwd = t_unicode_str(passwd, FALSE, &len);

	md4_get_digest(wpwd, len, hash);

	safe_memset(wpwd, 0, len);
}

static void
hmac_md5_ucs2le_string_ucase(struct hmac_context *ctx, const char *str)
{
	size_t len;
	unsigned char *wstr = t_unicode_str(str, TRUE, &len);

	hmac_update(ctx, wstr, len);
}

static void ATTR_NULL(2)
ntlm_v2_hash(const char *user, const char *target,
	     const unsigned char *hash_v1,
	     unsigned char hash[NTLMSSP_V2_HASH_SIZE])
{
	struct hmac_context ctx;

	hmac_init(&ctx, hash_v1, NTLMSSP_HASH_SIZE, &hash_method_md5);
	hmac_md5_ucs2le_string_ucase(&ctx, user);
	if (target != NULL)
		hmac_md5_ucs2le_string_ucase(&ctx, target);
	hmac_final(&ctx, hash);
}

void
ntlmssp_v1_response(const unsigned char *hash,
		    const unsigned char *challenge,
		    unsigned char response[NTLMSSP_RESPONSE_SIZE])
{
	unsigned char des_hash[NTLMSSP_DES_KEY_LENGTH * 3];

	memcpy(des_hash, hash, NTLMSSP_HASH_SIZE);
	memset(des_hash + NTLMSSP_HASH_SIZE, 0,
	       sizeof(des_hash) - NTLMSSP_HASH_SIZE);

	deshash(response, des_hash, challenge);
	deshash(response + 8, des_hash + 7, challenge);
	deshash(response + 16, des_hash + 14, challenge);

	safe_memset(des_hash, 0, sizeof(des_hash));
}

void
ntlmssp2_response(const unsigned char *hash,
		  const unsigned char *server_challenge,
		  const unsigned char *client_challenge,
		  unsigned char response[NTLMSSP_RESPONSE_SIZE])
{
	struct md5_context ctx;
	unsigned char session_hash[MD5_RESULTLEN];

	md5_init(&ctx);
	md5_update(&ctx, server_challenge, NTLMSSP_CHALLENGE_SIZE);
	md5_update(&ctx, client_challenge, NTLMSSP_CHALLENGE_SIZE);
	md5_final(&ctx, session_hash);

	ntlmssp_v1_response(hash, session_hash, response);
}

void
ntlmssp_v2_response(const char *user, const char *target,
		    const unsigned char *hash_v1,
		    const unsigned char *challenge,
		    const unsigned char *blob, size_t blob_size,
		    unsigned char response[NTLMSSP_V2_RESPONSE_SIZE])
{
	struct hmac_context ctx;
	unsigned char hash[NTLMSSP_V2_HASH_SIZE];

	ntlm_v2_hash(user, target, hash_v1, hash);

	hmac_init(&ctx, hash, NTLMSSP_V2_HASH_SIZE, &hash_method_md5);
	hmac_update(&ctx, challenge, NTLMSSP_CHALLENGE_SIZE);
	hmac_update(&ctx, blob, blob_size);
	hmac_final(&ctx, response);

	safe_memset(hash, 0, sizeof(hash));
}
