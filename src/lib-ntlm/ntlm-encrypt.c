/*
 * NTLM and NTLMv2 hash generation.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published 
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <ctype.h>

#include "lib.h"
#include "buffer.h"
#include "compat.h"
#include "safe-memset.h"
#include "md4.h"
#include "hmac-md5.h"
#include "ntlm.h"
#include "ntlm-des.h"

static unsigned char *
t_unicode_str(const char *src, int ucase, size_t *size)
{
	buffer_t *wstr;

	wstr = buffer_create_dynamic(unsafe_data_stack_pool, 32, (size_t)-1);
	for ( ; *src; src++) {
		buffer_append_c(wstr, ucase ? i_toupper(*src) : *src);
		buffer_append_c(wstr, '\0');
	}

	*size = buffer_get_used_size(wstr);
	return buffer_free_without_data(wstr);
}

static void
ntlmssp_des_encrypt_triad(const unsigned char *hash,
		 	  const unsigned char *challenge,
			  unsigned char *response)
{
	deshash(response, hash, challenge);
	deshash(response + 8, hash + 7, challenge);
	deshash(response + 16, hash + 14, challenge);
}

const unsigned char *
ntlm_v1_hash(const char *passwd, unsigned char hash[NTLMSSP_HASH_SIZE])
{
	size_t len;
	void *wpwd = t_unicode_str(passwd, 0, &len);

	md4_get_digest(wpwd, len, hash);

	safe_memset(wpwd, 0, len);

	return hash;
}

static void
hmac_md5_ucs2le_string_ucase(struct hmac_md5_context *ctx, const char *str)
{
	size_t len;
	unsigned char *wstr = t_unicode_str(str, 1, &len);

	hmac_md5_update(ctx, wstr, len);
}

static void
ntlm_v2_hash(const char *user, const char *target,
	     const unsigned char *hash_v1,
	     unsigned char hash[NTLMSSP_V2_HASH_SIZE])
{
	struct hmac_md5_context ctx;

	hmac_md5_init(&ctx, hash_v1, NTLMSSP_HASH_SIZE);
	hmac_md5_ucs2le_string_ucase(&ctx, user);
	if (target)
		hmac_md5_ucs2le_string_ucase(&ctx, target);
	hmac_md5_final(&ctx, hash);
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

	ntlmssp_des_encrypt_triad(des_hash, challenge, response);
}

void
ntlmssp_v2_response(const char *user, const char *target,
		    const unsigned char *hash_v1,
		    const unsigned char *challenge,
		    const unsigned char *blob, size_t blob_size,
		    unsigned char response[NTLMSSP_V2_RESPONSE_SIZE])
{
	struct hmac_md5_context ctx;
	unsigned char hash[NTLMSSP_V2_HASH_SIZE];

	ntlm_v2_hash(user, target, hash_v1, hash);

	hmac_md5_init(&ctx, hash, NTLMSSP_V2_HASH_SIZE);
	hmac_md5_update(&ctx, challenge, NTLMSSP_CHALLENGE_SIZE);
	hmac_md5_update(&ctx, blob, blob_size);
	hmac_md5_final(&ctx, response);
}
