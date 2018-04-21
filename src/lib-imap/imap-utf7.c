/* Copyright (c) 2008-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "unichar.h"
#include "imap-utf7.h"

static const char imap_b64enc[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

#define XX 0xff
static const unsigned char imap_b64dec[256] = {
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, 63,XX,XX,XX,
	52,53,54,55, 56,57,58,59, 60,61,XX,XX, XX,XX,XX,XX,
	XX, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
	15,16,17,18, 19,20,21,22, 23,24,25,XX, XX,XX,XX,XX,
	XX,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
	41,42,43,44, 45,46,47,48, 49,50,51,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
	XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX
};

static void
mbase64_encode(string_t *dest, const unsigned char *in, size_t len)
{
	str_append_c(dest, '&');
	while (len >= 3) {
		str_append_c(dest, imap_b64enc[in[0] >> 2]);
		str_append_c(dest, imap_b64enc[((in[0] & 3) << 4) |
					       (in[1] >> 4)]);
		str_append_c(dest, imap_b64enc[((in[1] & 0x0f) << 2) |
					       ((in[2] & 0xc0) >> 6)]);
		str_append_c(dest, imap_b64enc[in[2] & 0x3f]);
		in += 3;
		len -= 3;
	}
	if (len > 0) {
		str_append_c(dest, imap_b64enc[in[0] >> 2]);
		if (len == 1)
			str_append_c(dest, imap_b64enc[(in[0] & 0x03) << 4]);
		else {
			str_append_c(dest, imap_b64enc[((in[0] & 0x03) << 4) |
						       (in[1] >> 4)]);
			str_append_c(dest, imap_b64enc[(in[1] & 0x0f) << 2]);
		}
	}
	str_append_c(dest, '-');
}

static const char *imap_utf8_first_encode_char(const char *str)
{
	const char *p;

	for (p = str; *p != '\0'; p++) {
		if (*p == '&' || *p < 0x20 || *p >= 0x7f)
			return p;
	}
	return NULL;
}

int imap_utf8_to_utf7(const char *src, string_t *dest)
{
	const char *p;
	unichar_t chr;
	uint8_t *utf16, *u;
	uint16_t u16;

	p = imap_utf8_first_encode_char(src);
	if (p == NULL) {
		/* no characters that need to be encoded */
		str_append(dest, src);
		return 0;
	}

	/* at least one encoded character */
	str_append_data(dest, src, p-src);
	utf16 = t_malloc0(MALLOC_MULTIPLY(strlen(p), 2));
	while (*p != '\0') {
		if (*p == '&') {
			str_append(dest, "&-");
			p++;
			continue;
		}
		if (*p >= 0x20 && *p < 0x7f) {
			str_append_c(dest, *p);
			p++;
			continue;
		}

		u = utf16;
		while (*p != '\0' && (*p < 0x20 || *p >= 0x7f)) {
			if (uni_utf8_get_char(p, &chr) <= 0)
				return -1;
			/* @UNSAFE */
			if (chr < UTF16_SURROGATE_BASE) {
				*u++ = chr >> 8;
				*u++ = chr & 0xff;
			} else {
				u16 = UTF16_SURROGATE_HIGH(chr);
				*u++ = u16 >> 8;
				*u++ = u16 & 0xff;
				u16 = UTF16_SURROGATE_LOW(chr);
				*u++ = u16 >> 8;
				*u++ = u16 & 0xff;
			}
			p += uni_utf8_char_bytes(*p);
		}
		mbase64_encode(dest, utf16, u-utf16);
	}
	return 0;
}

int t_imap_utf8_to_utf7(const char *src, const char **dest_r)
{
	string_t *str;
	int ret;

	if (imap_utf8_first_encode_char(src) == NULL) {
		*dest_r = src;
		return 0;
	}

	str = t_str_new(64);
	ret = imap_utf8_to_utf7(src, str);
	*dest_r = str_c(str);
	return ret;
}

static int utf16buf_to_utf8(string_t *dest, const unsigned char output[4],
			    unsigned int *_pos, unsigned int len)
{
	unsigned int pos = *_pos;
	uint16_t high, low;
	unichar_t chr;

	if (len % 2 != 0)
		return -1;
	
	high = (output[pos % 4] << 8) | output[(pos+1) % 4];
	if (high < UTF16_SURROGATE_HIGH_FIRST ||
	    high > UTF16_SURROGATE_HIGH_MAX) {
		/* single byte */
		size_t oldlen = str_len(dest);

		if (high == 0) {
			/* Encoded NUL isn't going to work in Dovecot code,
			   even though it's technically valid. Return failure
			   so the callers don't even get a chance to handle the
			   NUL in the string inconsistently. */
			return -1;
		}
		uni_ucs4_to_utf8_c(high, dest);
		if (str_len(dest) - oldlen == 1) {
			unsigned char last = str_data(dest)[oldlen];
			if (last >= 0x20 && last < 0x7f)
				return -1;
		}
		*_pos = (pos + 2) % 4;
		return 0;
	}

	if (high > UTF16_SURROGATE_HIGH_LAST)
		return -1;
	if (len != 4) {
		/* missing the second character */
		return -1;
	}

	low = (output[(pos+2)%4] << 8) | output[(pos+3) % 4];
	if (low < UTF16_SURROGATE_LOW_FIRST || low > UTF16_SURROGATE_LOW_LAST)
		return -1;

	chr = UTF16_SURROGATE_BASE +
		(((high & UTF16_SURROGATE_MASK) << UTF16_SURROGATE_SHIFT) |
		 (low & UTF16_SURROGATE_MASK));
	uni_ucs4_to_utf8_c(chr, dest);
	return 0;
}

static int mbase64_decode_to_utf8(string_t *dest, const char **_src)
{
	const char *src = *_src;
	unsigned char input[4], output[4];
	unsigned int outstart = 0, outpos = 0;

	while (*src != '-') {
		input[0] = imap_b64dec[(uint8_t)src[0]];
		if (input[0] == 0xff)
			return -1;
		input[1] = imap_b64dec[(uint8_t)src[1]];
		if (input[1] == 0xff)
			return -1;

		output[outpos % 4] = (input[0] << 2) | (input[1] >> 4);
		if (++outpos % 4 == outstart) {
			if (utf16buf_to_utf8(dest, output, &outstart, 4) < 0)
				return -1;
		}

		input[2] = imap_b64dec[(uint8_t)src[2]];
		if (input[2] == 0xff) {
			if (src[2] != '-')
				return -1;

			src += 2;
			break;
		}

		output[outpos % 4] = (input[1] << 4) | (input[2] >> 2);
		if (++outpos % 4 == outstart) {
			if (utf16buf_to_utf8(dest, output, &outstart, 4) < 0)
				return -1;
		}

		input[3] = imap_b64dec[(uint8_t)src[3]];
		if (input[3] == 0xff) {
			if (src[3] != '-')
				return -1;

			src += 3;
			break;
		}

		output[outpos % 4] = ((input[2] << 6) & 0xc0) | input[3];
		if (++outpos % 4 == outstart) {
			if (utf16buf_to_utf8(dest, output, &outstart, 4) < 0)
				return -1;
		}

		src += 4;
	}
	if (outstart != outpos % 4) {
		if (utf16buf_to_utf8(dest, output, &outstart,
				     (4 + outpos - outstart) % 4) < 0)
			return -1;
	}

	/* found ending '-' */
	*_src = src + 1;
	return 0;
}

int imap_utf7_to_utf8(const char *src, string_t *dest)
{
	const char *p;

	for (p = src; *p != '\0'; p++) {
		if (*p < 0x20 || *p >= 0x7f)
			return -1;
		if (*p == '&')
			break;
	}
	if (*p == '\0') {
		/* no IMAP-UTF-7 encoded characters */
		str_append(dest, src);
		return 0;
	}

	/* at least one encoded character */
	str_append_data(dest, src, p-src);
	while (*p != '\0') {
		if (*p == '&') {
			if (*++p == '-') {
				str_append_c(dest, '&');
				p++;
			} else {
				if (mbase64_decode_to_utf8(dest, &p) < 0)
					return -1;
				if (p[0] == '&' && p[1] != '-') {
					/* &...-& */
					return -1;
				}
			}
		} else {
			str_append_c(dest, *p++);
		}
	}
	return 0;
}

bool imap_utf7_is_valid(const char *src)
{
	const char *p;
	int ret;

	for (p = src; *p != '\0'; p++) {
		if (*p < 0x20 || *p >= 0x7f)
			return FALSE;
		if (*p == '&') {
			/* slow scan */
			T_BEGIN {
				string_t *tmp = t_str_new(128);
				ret = imap_utf7_to_utf8(p, tmp);
			} T_END;
			if (ret < 0)
				return FALSE;
		}
	}
	return TRUE;
}
