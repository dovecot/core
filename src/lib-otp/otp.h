#ifndef OTP_H
#define OTP_H

#define OTP_MAX_SEED_LEN	16
#define OTP_MAX_WORD_LEN	4
#define OTP_WORDS_NUMBER	6

#define OTP_HASH_SIZE		8

struct otp_state {
	unsigned int algo;
	int seq;
	unsigned char hash[OTP_HASH_SIZE];
	char seed[OTP_MAX_SEED_LEN + 1];
};

#include "otp-hash.h"
#include "otp-dictionary.h"
#include "otp-parity.h"
#include "otp-parse.h"

#endif
