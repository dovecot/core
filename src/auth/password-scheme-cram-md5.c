/* Copyright (C) 2003 Timo Sirainen / Joshua Goodall */

#include "lib.h"
#include "hmac-md5.h"
#include "hex-binary.h"
#include "password-scheme.h"

const char *password_generate_cram_md5(const char *plaintext)
{
	struct hmac_md5_context ctx;
	unsigned char context_digest[CRAM_MD5_CONTEXTLEN];

	hmac_md5_init(&ctx, (const unsigned char *)plaintext,
		      strlen(plaintext));
	hmac_md5_get_cram_context(&ctx, context_digest);
	return binary_to_hex(context_digest, sizeof(context_digest));
}
