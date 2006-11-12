#ifndef __OTP_PARITY_H__
#define __OTP_PARITY_H__

const unsigned char parity_table[256];

static inline unsigned int otp_parity(unsigned char *data)
{
	unsigned int i, parity = 0;

	for (i = 0; i < OTP_HASH_SIZE; i++)
		parity += parity_table[*data++];

	return parity & 3;
}

#endif	/* __OTP_PARITY_H__ */
