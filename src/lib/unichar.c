/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "bsearch-insert-pos.h"
#include "unichar.h"

#include "unicodemap.c"

#define HANGUL_FIRST 0xac00
#define HANGUL_LAST 0xd7a3

const unsigned char utf8_replacement_char[UTF8_REPLACEMENT_CHAR_LEN] =
	{ 0xef, 0xbf, 0xbd }; /* 0xfffd */

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

int uni_utf8_to_ucs4(const char *input, ARRAY_TYPE(unichars) *output)
{
	unichar_t chr;

	while (*input != '\0') {
		if (uni_utf8_get_char(input, &chr) <= 0) {
			/* invalid input */
			return -1;
		}
                input += uni_utf8_char_bytes(*input);

		array_append(output, &chr, 1);
	}
	return 0;
}

void uni_ucs4_to_utf8(const unichar_t *input, size_t len, buffer_t *output)
{
	for (; len > 0 && *input != '\0'; input++, len--)
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

	i_assert(chr < 0x80000000); /* 1 << (5*6 + 1) */

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

static bool uint16_find(const uint16_t *data, unsigned int count,
			uint16_t value, unsigned int *idx_r)
{
	BINARY_NUMBER_SEARCH(data, count, value, idx_r);
}

static bool uint32_find(const uint32_t *data, unsigned int count,
			uint32_t value, unsigned int *idx_r)
{
	BINARY_NUMBER_SEARCH(data, count, value, idx_r);
}

unichar_t uni_ucs4_to_titlecase(unichar_t chr)
{
	unsigned int idx;

	if (chr <= 0xff)
		return titlecase8_map[chr];
	else if (chr <= 0xffff) {
		if (!uint16_find(titlecase16_keys, N_ELEMENTS(titlecase16_keys),
				 chr, &idx))
			return chr;
		else
			return titlecase16_values[idx];
	} else {
		if (!uint32_find(titlecase32_keys, N_ELEMENTS(titlecase32_keys),
				 chr, &idx))
			return chr;
		else
			return titlecase32_values[idx];
	}
}

static bool uni_ucs4_decompose_uni(unichar_t *chr)
{
	unsigned int idx;

	if (*chr <= 0xff) {
		if (uni8_decomp_map[*chr] == *chr)
			return FALSE;
		*chr = uni8_decomp_map[*chr];
	} else if (*chr <= 0xffff) {
		if (*chr < uni16_decomp_keys[0])
			return FALSE;

		if (!uint16_find(uni16_decomp_keys,
				 N_ELEMENTS(uni16_decomp_keys), *chr, &idx))
			return FALSE;
		*chr = uni16_decomp_values[idx];
	} else {
		if (!uint32_find(uni32_decomp_keys,
				 N_ELEMENTS(uni32_decomp_keys), *chr, &idx))
			return FALSE;
		*chr = uni32_decomp_values[idx];
	}
	return TRUE;
}

static void uni_ucs4_decompose_hangul_utf8(unichar_t chr, buffer_t *output)
{
#define SBase HANGUL_FIRST
#define LBase 0x1100 
#define VBase 0x1161 
#define TBase 0x11A7
#define LCount 19 
#define VCount 21
#define TCount 28
#define NCount (VCount * TCount)
	unsigned int SIndex = chr - SBase;
        unichar_t L = LBase + SIndex / NCount;
        unichar_t V = VBase + (SIndex % NCount) / TCount;
        unichar_t T = TBase + SIndex % TCount;

	uni_ucs4_to_utf8_c(L, output);
	uni_ucs4_to_utf8_c(V, output);
	if (T != TBase) uni_ucs4_to_utf8_c(T, output);
}

static bool uni_ucs4_decompose_multi_utf8(unichar_t chr, buffer_t *output)
{
	const uint16_t *value;
	unsigned int idx;

	if (chr < multidecomp_keys[0] || chr > 0xffff)
		return FALSE;

	if (!uint32_find(multidecomp_keys, N_ELEMENTS(multidecomp_keys),
			 chr, &idx))
		return FALSE;

	value = &multidecomp_values[multidecomp_offsets[idx]];
	for (; *value != 0; value++)
		uni_ucs4_to_utf8_c(*value, output);
	return TRUE;
}

static void output_add_replacement_char(buffer_t *output)
{
	if (output->used >= UTF8_REPLACEMENT_CHAR_LEN &&
	    memcmp(CONST_PTR_OFFSET(output->data,
				    output->used - UTF8_REPLACEMENT_CHAR_LEN),
		   utf8_replacement_char, UTF8_REPLACEMENT_CHAR_LEN) == 0) {
		/* don't add the replacement char multiple times */
		return;
	}
	buffer_append(output, utf8_replacement_char, UTF8_REPLACEMENT_CHAR_LEN);
}

int uni_utf8_to_decomposed_titlecase(const void *_input, size_t max_len,
				     buffer_t *output)
{
	const unsigned char *input = _input;
	unsigned int bytes;
	unichar_t chr;
	int ret = 0;

	while (max_len > 0 && *input != '\0') {
		if (uni_utf8_get_char_n(input, max_len, &chr) <= 0) {
			/* invalid input. try the next byte. */
			ret = -1;
			input++; max_len--;
			output_add_replacement_char(output);
			continue;
		}
		bytes = uni_utf8_char_bytes(*input);
		input += bytes;
		max_len -= bytes;

		chr = uni_ucs4_to_titlecase(chr);
		if (chr >= HANGUL_FIRST && chr <= HANGUL_LAST)
			uni_ucs4_decompose_hangul_utf8(chr, output);
		else if (uni_ucs4_decompose_uni(&chr) ||
			 !uni_ucs4_decompose_multi_utf8(chr, output))
			uni_ucs4_to_utf8_c(chr, output);
	}
	return ret;
}

static inline unsigned int
is_valid_utf8_seq(const unsigned char *input, unsigned int size)
{
	unsigned int i, len;

	len = uni_utf8_char_bytes(input[0]);
	if (unlikely(len > size || len == 1))
		return 0;

	/* the rest of the chars should be in 0x80..0xbf range.
	   anything else is start of a sequence or invalid */
	for (i = 1; i < len; i++) {
		if (unlikely(input[i] < 0x80 || input[i] > 0xbf))
			return 0;
	}
	return len;
}

static int uni_utf8_find_invalid_pos(const unsigned char *input, size_t size,
				     size_t *pos_r)
{
	size_t i, len;

	/* find the first invalid utf8 sequence */
	for (i = 0; i < size;) {
		if (input[i] < 0x80)
			i++;
		else {
			len = is_valid_utf8_seq(input + i, size-i);
			if (unlikely(len == 0)) {
				*pos_r = i;
				return -1;
			}
			i += len;
		}
	}
	return 0;
}

bool uni_utf8_get_valid_data(const unsigned char *input, size_t size,
			     buffer_t *buf)
{
	size_t i, len;

	if (uni_utf8_find_invalid_pos(input, size, &i) == 0)
		return TRUE;

	/* broken utf-8 input - skip the broken characters */
	buffer_append(buf, input, i++);

	output_add_replacement_char(buf);
	while (i < size) {
		if (input[i] < 0x80) {
			buffer_append_c(buf, input[i++]);
			continue;
		}

		len = is_valid_utf8_seq(input + i, size-i);
		if (len == 0) {
			i++;
			output_add_replacement_char(buf);
			continue;
		}
		buffer_append(buf, input + i, len);
		i += len;
	}
	return FALSE;
}

bool uni_utf8_str_is_valid(const char *str)
{
	size_t i;

	return uni_utf8_find_invalid_pos((const unsigned char *)str,
					 strlen(str), &i) == 0;
}

bool uni_utf8_data_is_valid(const unsigned char *data, size_t size)
{
	size_t i;

	return uni_utf8_find_invalid_pos(data, size, &i) == 0;
}
