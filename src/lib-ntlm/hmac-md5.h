#ifndef __HMAC_MD5_H__
#define __HMAC_MD5_H__

#include "md5.h"

struct hmac_md5_context {
	struct md5_context ctx;
	unsigned char k_ipad[64];
	unsigned char k_opad[64];
};

void hmac_md5_init(struct hmac_md5_context *ctx, const unsigned char* key, size_t key_len);
void hmac_md5_final(struct hmac_md5_context *ctx, unsigned char *digest);

static inline void
hmac_md5_update(struct hmac_md5_context *ctx, const void * data, size_t size)
{
	md5_update(&ctx->ctx, data, size);
}

#endif /* __HMAC_MD5_H__ */
