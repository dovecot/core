/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "hex-dec.h"

void dec2hex(unsigned char *hexstr, uintmax_t dec, unsigned int hexstr_size)
{
	unsigned int i;

	for (i = 0; i < hexstr_size; i++) {
		unsigned int value = dec & 0x0f;
		if (value < 10)
			hexstr[hexstr_size-i-1] = value + '0';
		else
			hexstr[hexstr_size-i-1] = value - 10 + 'A';
		dec >>= 4;
	}
}

int hex2dec_case(const unsigned char *data, unsigned int len,
		 enum hex_allowed_case allowed_case, uintmax_t *value_r)
{
	uintmax_t value = 0;

	for (unsigned int i = 0; i < len; i++) {
		value *= 0x10;
		if (data[i] >= '0' && data[i] <= '9')
			value += data[i]-'0';
		else if (HAS_ANY_BITS(allowed_case, HEX_ALLOWED_CASE_UPPER) &&
			 data[i] >= 'A' && data[i] <= 'F')
			value += data[i]-'A' + 10;
		else if (HAS_ANY_BITS(allowed_case, HEX_ALLOWED_CASE_LOWER) &&
			 data[i] >= 'a' && data[i] <= 'f')
			value += data[i]-'a' + 10;
		else
			return -1;
	}
	*value_r = value;
	return 0;
}

