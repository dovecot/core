#ifndef HMAC_CRAM_MD5_H
#define HMAC_CRAM_MD5_H

#include "hmac.h"

#define CRAM_MD5_CONTEXTLEN 32

void hmac_md5_get_cram_context(struct hmac_context *ctx,
		unsigned char context_digest[CRAM_MD5_CONTEXTLEN]);
void hmac_md5_set_cram_context(struct hmac_context *ctx,
		const unsigned char context_digest[CRAM_MD5_CONTEXTLEN]);


#endif
