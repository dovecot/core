/* Copyright (C) 2005-2007 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "unichar.h"

static const uint8_t utf8_non1_bytes[256 - 192 - 2] = {
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,6,6,1,1
};

const uint8_t *const uni_utf8_non1_bytes = utf8_non1_bytes;

unsigned int uni_strlen(const unichar_t *str)
{
	unsigned int len = 0;

	for (len = 0; str[len] != 0; len++) ;

	return len;
}

int uni_utf8_get_char(const char *input, unichar_t *chr_r)
{
	return uni_utf8_get_char_n((const unsigned char *)input, (size_t)-1,
				   chr_r);
}

int uni_utf8_get_char_n(const void *_input, size_t max_len, unichar_t *chr_r)
{
	const unsigned char *input = _input;
	unichar_t chr;
	unsigned int i, len;
	int ret;

	i_assert(max_len > 0);

	if (*input < 0x80) {
		*chr_r = *input;
		return 1;
	}

	/* first byte has len highest bits set, followed by zero bit.
	   the rest of the bits are used as the highest bits of the value. */
	chr = *input;
	len = uni_utf8_char_bytes(*input);
	switch (len) {
	case 2:
		chr &= 0x1f;
		break;
	case 3:
		chr &= 0x0f;
		break;
	case 4:
		chr &= 0x07;
		break;
	case 5:
		chr &= 0x03;
		break;
	case 6:
		chr &= 0x01;
		break;
	default:
		/* only 7bit chars should have len==1 */
		i_assert(len == 1);
		return -1;
	}

	if (len <= max_len)
		ret = 1;
	else {
		/* check first if the input is invalid before returning 0 */
		ret = 0;
		len = max_len;
	}

	/* the following bytes must all be 10xxxxxx */
	for (i = 1; i < len; i++) {
		if ((input[i] & 0xc0) != 0x80)
			return input[i] == '\0' ? 0 : -1;

		chr <<= 6;
		chr |= input[i] & 0x3f;
	}

	*chr_r = chr;
	return ret;
}

int uni_utf8_to_ucs4(const char *input, buffer_t *output)
{
	unichar_t chr;

	while (*input != '\0') {
		if (uni_utf8_get_char(input, &chr) <= 0) {
			/* invalid input */
			return -1;
		}
                input += uni_utf8_char_bytes(*input);

		buffer_append(output, &chr, sizeof(chr));
	}
	return 0;
}

void uni_ucs4_to_utf8(const unichar_t *input, size_t len, buffer_t *output)
{
	for (; *input != '\0' && len > 0; input++, len--)
		uni_ucs4_to_utf8_c(*input, output);
}

void uni_ucs4_to_utf8_c(unichar_t chr, buffer_t *output)
{
	unsigned char first;
	int bitpos;

	if (chr < 0x80) {
		buffer_append_c(output, chr);
		return;
	}

	i_assert(chr <= 0x40000000); /* 1 << (5 * 6) */

	if (chr < (1 << (6 + 5))) {
		/* 110xxxxx */
		bitpos = 6;
		first = 0x80 | 0x40;
	} else if (chr < (1 << ((2*6) + 4))) {
		/* 1110xxxx */
		bitpos = 2*6;
		first = 0x80 | 0x40 | 0x20;
	} else if (chr < (1 << ((3*6) + 3))) {
		/* 11110xxx */
		bitpos = 3*6;
		first = 0x80 | 0x40 | 0x20 | 0x10;
	} else if (chr < (1 << ((4*6) + 2))) {
		/* 111110xx */
		bitpos = 4*6;
		first = 0x80 | 0x40 | 0x20 | 0x10 | 0x08;
	} else {
		/* 1111110x */
		bitpos = 5*6;
		first = 0x80 | 0x40 | 0x20 | 0x10 | 0x08 | 0x04;
	}
	buffer_append_c(output, first | (chr >> bitpos));

	do {
		bitpos -= 6;
		buffer_append_c(output, 0x80 | ((chr >> bitpos) & 0x3f));
	} while (bitpos > 0);
}

unsigned int uni_utf8_strlen_n(const void *_input, size_t size)
{
	const unsigned char *input = _input;
	unsigned int len = 0;
	size_t i;

	for (i = 0; i < size && input[i] != '\0'; ) {
		i += uni_utf8_char_bytes(input[i]);
		if (i > size)
			break;
		len++;
	}
	return len;
}
