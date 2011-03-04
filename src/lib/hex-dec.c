/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

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

uintmax_t hex2dec(const unsigned char *data, unsigned int len)
{
	unsigned int i;
	uintmax_t value = 0;

	for (i = 0; i < len; i++) {
		value = value*0x10;
		if (data[i] >= '0' && data[i] <= '9')
			value += data[i]-'0';
		else if (data[i] >= 'A' && data[i] <= 'F')
			value += data[i]-'A' + 10;
		else
			return 0;
	}
	return value;
}

