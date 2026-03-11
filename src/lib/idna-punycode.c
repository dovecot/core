/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
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
static inline uint32_t decode_digit(unsigned char cp)
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

/* Decodes a punycoded string into output, or returns -1 on error. */
int idna_punycode_decode(const unsigned char *input, size_t len,
			 string_t *output)
{
	ARRAY(unichar_t) label;
	size_t i = 0;
	size_t out = 0;
	uint32_t n = initialN, bias = initialBias;
	const unsigned char *delim = NULL;
	const unsigned char *end = CONST_PTR_OFFSET(input, len);
	const unsigned char *ptr = input;
	t_array_init(&label, len);

	/* Find the rightmost delimiter within the first len bytes. input is not
	   necessarily NUL-terminated at len - callers such as
	   rfc822_decode_punycode() pass a pointer into a longer string and a
	   per-label len - so we must not scan past len (strrchr() would, and
	   could return a delimiter belonging to a later label). */
	delim = i_memrchr(input, delimiter, len);

	/* no delimiter found, reset to start of string */
	if (delim == NULL)
		delim = input;
	i_assert(delim <= end);

	for (ptr = input; ptr < delim; ptr++) {
		if (*ptr >= 0x80) {
			/* Has non-ascii input, this cannot be punycoded. */
			return -1;
		}
		i_assert(array_count(&label) < len);
		/* Add basic code points to label */
		unichar_t ch = *ptr;
		array_push_back(&label, &ch);
	}

	out = array_count(&label);

	/* Main decoding loop: start from after delimiter */
	if (delim != input)
		ptr = delim + 1;
	else
		ptr = input;
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

		bias = adapt(i - oldi, out + 1, oldi == 0);

		/* i was supposed to wrap around from out+1 to 0, incrementing
		   n each time, so we'll fix that now: */

		if (i / (out + 1) > UINT32_MAX - n)
			return -1;

		n += i / (out + 1);
		i %= (out + 1);

		if (n < initialN)
			return -1;

		/* The decoded code point must be a valid Unicode scalar
		   value. Reject surrogates and values above U+10FFFF here,
		   otherwise the uni_ucs4_to_utf8() sink below would
		   i_assert() (i_panic) on attacker-supplied input. Callers
		   treat a negative return as "consider it as data", so this
		   fails safe. */
		if (!uni_is_valid_ucs4(n))
			return -1;

		/* Insert n at position i of the output: */
		if (i <= out) {
			out++;
			array_insert(&label, i, &n, 1);
		} else
			return -1;

		i++;
	}

	uni_ucs4_to_utf8(array_front(&label), out, output);
	return 0;
}
