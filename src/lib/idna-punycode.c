/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
#include "idna.h"
#include "idna-punycode.h"

/* Based on punycode.c from RFC 3492

   http://www.nicemice.net/idn/
   Adam M. Costello
   http://www.nicemice.net/amc/
*/

/* Boot string parameters for Punycode */

static const uint32_t base = 36; /* maximum basic code point */
static const uint32_t tmin = 1;
static const uint32_t tmax = 26;
static const uint32_t skew = 38;
static const uint32_t damp = 700;
static const uint32_t initialBias = 72;
static const uint32_t initialN = 0x80;
static const uint32_t delimiter = u'-';

/*
      code points    digit-values
      ------------   ----------------------
      41..5A (A-Z) =  0 to 25, respectively
      61..7A (a-z) =  0 to 25, respectively
      30..39 (0-9) = 26 to 35, respectively
*/
static inline uint32_t decode_digit(uint32_t cp)
{
	if (cp >= '0' && cp <= '9')
		return cp - u'0' + 26;
	else if (cp >= 'A' && cp <= 'Z')
		return cp - u'A';
	else if (cp >= 'a' && cp <= 'z')
		return cp - u'a';
	else
		return base;
}

static inline uint32_t encode_digit(uint32_t d)
{
	return d + 22 + 75 * (d < 26 ? 1 : 0);
}

/* Bias adaptation function */
static uint32_t adapt(uint32_t delta, uint32_t numpoints, bool firsttime)
{
	uint32_t k;

	delta = firsttime ? delta / damp : delta >> 1;
	/* delta >> 1 is a faster way of doing delta / 2 */
	delta += delta / numpoints;

	for (k = 0;  delta > ((base - tmin) * tmax) / 2;  k += base)
		delta /= base - tmin;

	return k + (base - tmin + 1) * delta / (delta + skew);
}

/* Encodes a Unicode string into punycode output, or returns -1 on error. */
ssize_t idna_punycode_encode(const uint32_t *in, size_t in_len,
			     uint32_t *out, size_t out_max)
{
	buffer_t out_buf;
	ARRAY(uint32_t) output;
	uint32_t n = initialN, bias = initialBias;
	uint32_t delta = 0;
	uint32_t h, b, j, m, q, k, t;

	buffer_create_from_data(&out_buf, out,
				MALLOC_MULTIPLY(sizeof(uint32_t), out_max));
	array_create_from_buffer(&output, &out_buf, sizeof(uint32_t));

	/* Handle the basic code points: */
	for (j = 0; j < in_len; j++) {
		if (in[j] < 0x80) {
			i_assert(array_count(&output) <= out_max);
			if (out_max - array_count(&output) < 2)
				return -1;
			array_push_back(&output, &in[j]);
		}
	}

	h = b = array_count(&output);

	/* h is the number of code points that have been handled, b is the
	   number of basic code points, and out is the number of characters that
	   have been output. */

	if (b > 0) {
		if (array_count(&output) == out_max)
			return -1;
		array_push_back(&output, &delimiter);
	}

	/* Main encoding loop: */

	while (h < in_len) {
		/* All non-basic code points < n have been handled already. Find
		   the next larger one: */

		for (m = UINT32_MAX, j = 0; j < in_len; j++) {
			if (in[j] >= n && in[j] < m)
				m = in[j];
		}

		/* Increase delta enough to advance the decoder's  <n,i> state
		   to <m,0>, but guard against overflow: */
		i_assert(m - n <= (UINT32_MAX - delta) / (h + 1));
		delta += (m - n) * (h + 1);
		n = m;

		for (j = 0; j < in_len; j++) {
			if (in[j] < n) {
				delta++;
				i_assert(delta > 0);
			}
			if (in[j] == n) {
				uint32_t digit;

				/* Represent delta as a generalized variable-length integer:
				 */
				for (q = delta, k = base;; k += base) {
					if (array_count(&output) == out_max)
						return -1;

					t = (k <= bias ? tmin :
					     (k >= bias + tmax ? tmax : k - bias));
					if (q < t)
						break;
					
					digit = encode_digit(t + (q - t) % (base - t));
					array_push_back(&output, &digit);
					q = (q - t) / (base - t);
				}

				if (array_count(&output) == out_max)
					return -1;
				digit = encode_digit(q);
				array_push_back(&output, &digit);
				bias = adapt(delta, h + 1, h == b);
				delta = 0;
				h++;
			}
		}
		delta++;
		n++;
	}

	return array_count(&output);
}

/* Decodes a punycoded string into output, or returns -1 on error. */
int idna_punycode_decode_utf8(const unsigned char *in, size_t in_len,
			      string_t *output)
{
	uint32_t *in32 = NULL;
	uint32_t out32[IDNA_DNS_MAX_NAME_LENGTH + 1];
	ssize_t sret;

	T_BEGIN {
		size_t i;

		if (in_len > 0) {
			in32 = t_malloc_no0(
				MALLOC_MULTIPLY(sizeof(uint32_t), in_len));
		}
		sret = 0;
		for (i = 0; i < in_len; i++) {
			if ((in[i] & 0x80) != 0x00) {
				sret = -1;
				break;
			}
			in32[i] = in[i];
		}
		if (sret == 0) {
			sret = idna_punycode_decode(in32, in_len,
						    out32, N_ELEMENTS(out32));
		}
	} T_END;
	if (sret < 0)
		return -1;

	uni_ucs4_to_utf8(out32, sret, output);
	return 0;
}
ssize_t idna_punycode_decode(const uint32_t *in, size_t in_len,
			     uint32_t *out, size_t out_max)
{
	buffer_t out_buf;
	ARRAY(uint32_t) output;
	size_t out_pos;
	size_t i = 0, k;
	uint32_t n = initialN, bias = initialBias;
	const uint32_t *delim = NULL;
	const uint32_t *end = &in[in_len];
	const uint32_t *ptr = in;

	buffer_create_from_data(&out_buf, out,
				MALLOC_MULTIPLY(sizeof(uint32_t), out_max));
	array_create_from_buffer(&output, &out_buf, sizeof(uint32_t));

	/* find the rightmost delimiter, if present in string */
	for (k = in_len; k > 0; k--) {
		if (in[k - 1] == delimiter) {
			delim = &in[k - 1];
			break;
		}
	}
	i_assert(delim == NULL || delim < end);

	/* no delimiter found, reset to start of string */
	if (delim == NULL)
		delim = in;
	i_assert(delim <= end);

	for (ptr = in; ptr < delim; ptr++) {
		if (*ptr >= 0x80) {
			/* Has non-ascii input, this cannot be punycoded. */
			return -1;
		}
		i_assert(array_count(&output) < in_len);
		/* Add basic code points to label */
		if (array_count(&output) == out_max)
			return -1;
		array_push_back(&output, ptr);
	}

	out_pos = array_count(&output);

	/* Main decoding loop: start from after delimiter */
	if (delim != in)
		ptr = delim + 1;
	else
		ptr = in;
	if (ptr == end)
		return -1;

	i_assert(ptr < end);
	while (ptr < end) {
		uint32_t oldi, w, k, digit, t;
		/* Decode a generalized variable-length integer into delta,
		   which gets added to i.  The overflow checking is easier if
		   we increase i as we go, then subtract off its starting
		   value at the end to obtain delta.  */

		oldi = i;
		w = 1;

		/* Iterate over digits of the variable-length integer. If we
		   exhaust the input before the terminating digit (digit < t),
		   the input is malformed. */
		for (k = base; ; k += base) {
			if (ptr >= end)
				return -1;
			/* ptr points to next digit to decode */
			digit = decode_digit(*ptr++);
			if (digit >= base)
				return -1;
			if (digit > (UINT32_MAX - i) / w)
				return -1;
			i += digit * w;
			t = k <= bias ? tmin :
				k >= bias + tmax ? tmax : k - bias;
			if (digit < t)
				break;
			if (w > UINT32_MAX / (base - t))
				return -1;
			w *= (base - t);
		}

		bias = adapt(i - oldi, out_pos + 1, oldi == 0);

		/* i was supposed to wrap around from out_pos + 1 to 0,
		   incrementing n each time, so we'll fix that now: */

		if (i / (out_pos + 1) > UINT32_MAX - n)
			return -1;

		n += i / (out_pos + 1);
		i %= (out_pos + 1);

		if (n < initialN)
			return -1;

		/* The decoded code point must be a valid Unicode scalar
		   value. Reject surrogates and values above U+10FFFF here,
		   otherwise the uni_ucs4_to_utf8() sink in a caller like
		   idna_punycode_decode_utf8() would i_assert() (i_panic) on
		   attacker-supplied input. Callers treat a negative return as
		   "consider it as data", so this fails safe. */
		if (!uni_is_valid_ucs4(n))
			return -1;

		/* Insert n at position i of the output: */
		if (i <= out_pos) {
			out_pos++;
			if (array_count(&output) == out_max)
				return -1;
			array_insert(&output, i, &n, 1);
		} else
			return -1;

		i++;
	}
	return (ssize_t)array_count(&output);
}
