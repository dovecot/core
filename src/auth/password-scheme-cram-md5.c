/* Copyright (C) 2003 Timo Sirainen / Joshua Goodall */

#include "lib.h"
#include "md5.h"
#include "hex-binary.h"
#include "password-scheme.h"

const char *password_generate_cram_md5(const char *plaintext)
{
	unsigned char digest[16], ipad[64], opad[64], context_digest[32], *cdp;
	struct md5_context ctxo, ctxi;
	size_t len;
	int i;

	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));

	/* Hash excessively long passwords */
	len = strlen(plaintext);
	if (len > 64) {
		md5_get_digest(plaintext, len, digest);
		memcpy(ipad, digest, 16);
		memcpy(opad, digest, 16);
	} else {
		memcpy(ipad, plaintext, len);
		memcpy(opad, plaintext, len);
	}

	/* ipad/opad operation */
	for (i = 0; i < 64; i++) {
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	md5_init(&ctxi);
	md5_init(&ctxo);
	md5_update(&ctxi, ipad, 64);
	md5_update(&ctxo, opad, 64);

	/* Make HMAC-MD5 hex digest */
#define CDPUT(p, c) STMT_START {   \
	*(p)++ = (c) & 0xff;       \
	*(p)++ = (c) >> 8 & 0xff;  \
	*(p)++ = (c) >> 16 & 0xff; \
	*(p)++ = (c) >> 24 & 0xff; \
} STMT_END
	cdp = context_digest;
	CDPUT(cdp, ctxo.a);
	CDPUT(cdp, ctxo.b);
	CDPUT(cdp, ctxo.c);
	CDPUT(cdp, ctxo.d);
	CDPUT(cdp, ctxi.a);
	CDPUT(cdp, ctxi.b);
	CDPUT(cdp, ctxi.c);
	CDPUT(cdp, ctxi.d);

	return binary_to_hex(context_digest, sizeof(context_digest));
}
