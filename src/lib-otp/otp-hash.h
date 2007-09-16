#ifndef OTP_HASH_H
#define OTP_HASH_H

struct digest_context;

enum {
	OTP_HASH_MD4,
	OTP_HASH_MD5,
	OTP_HASH_SHA1,
};

int digest_find(const char *name);
int digest_init(struct digest_context *ctx, const unsigned int algo);
void digest_update(struct digest_context *ctx, const void *data,
		   const size_t size);
void digest_final(struct digest_context *ctx, unsigned char *result);
void digest_otp_final(struct digest_context *ctx, unsigned char *result);
const char *digest_name(unsigned int algo);

void otp_hash(unsigned int algo, const char *seed, const char *passphrase,
	      unsigned int step, unsigned char *result);

void otp_next_hash(unsigned int algo, const unsigned char *prev,
		   unsigned char *result);

#endif
