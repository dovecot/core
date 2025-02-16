/* Copyright (c) 2024 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
#include "punycode.h"

/* Boot string parameters for Punycode */

static const unsigned int base = 36; /* maximum basic code point */
static const unsigned int tmin = 1;
static const unsigned int tmax = 26;
static const unsigned int skew = 38;
static const unsigned int damp = 700;
static const unsigned int initialBias = 72;
static const unsigned int initialN = 0x80;
static const unsigned int delimiter = u'-';

/*
      code points    digit-values
      ------------   ----------------------
      41..5A (A-Z) =  0 to 25, respectively
      61..7A (a-z) =  0 to 25, respectively
      30..39 (0-9) = 26 to 35, respectively
*/
static inline unsigned int decode_digit(unsigned char cp)
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

static unsigned int adapt(unsigned int delta, unsigned int numpoints, bool firsttime)
{
	unsigned int k;

	delta = firsttime ? delta / damp : delta >> 1;
	/* delta >> 1 is a faster way of doing delta / 2 */
	delta += delta / numpoints;

	for (k = 0;  delta > ((base - tmin) * tmax) / 2;  k += base)
		delta /= base - tmin;

	return k + (base - tmin + 1) * delta / (delta + skew);
}

/* Decodes a punycoded string into output, or returns -1 on error. */
int punycode_decode(const char *input, size_t len, string_t *output)
{
	ARRAY(unichar_t) label;
	size_t i = 0;
	size_t out = 0;
	unsigned int n = initialN, bias = initialBias;
	const char *delim = NULL;
	const char *end = CONST_PTR_OFFSET(input, len);
	const char *ptr = input;
	t_array_init(&label, len);

	/* find the rightmost delimiter, if present in string */
	delim = strrchr(ptr, delimiter);
	i_assert(delim == NULL || delim < end);

	/* no delimiter found, reset to start of string */
	if (delim == NULL)
		delim = input;
	i_assert(delim <= end);

	for (ptr = input; ptr < delim; ptr++) {
		if ((unsigned char)*ptr >= 0x80)
			/* Has non-ascii input, this cannot be punycoded. */
			return -1;
		i_assert(out < sizeof(label));
		/* Add basic code points to label */
		unichar_t ch = (unsigned char)*ptr;
		array_push_back(&label, &ch);
	}

	out = array_count(&label);

	/* Main decoding loop: start from after delimiter */
	if (delim != input)
		ptr = delim + 1;
	else
		ptr = input;

	i_assert(ptr < end);
	while (ptr < end) {
		unsigned int oldi, w, k, digit, t;
		/* Decode a generalized variable-length integer into delta,
		   which gets added to i.  The overflow checking is easier if
		   we increase i as we go, then subtract off its starting
		   value at the end to obtain delta.  */

		oldi = i;
		w = 1;
		k = base;

		while (ptr <= end) {
			/* ptr points to next digit to decode */
			digit = decode_digit(*ptr++);
			if (digit >= base)
				return -1;
			if (digit > (UINT_MAX - i) / w)
				return -1;
			i += digit * w;
			t = k <= bias ? tmin :
				k >= bias + tmax ? tmax : k - bias;
			if (digit < t)
				break;
			if (w > UINT_MAX / (base - t))
				return -1;
			w *= (base - t);
			k += base;
		}

		bias = adapt(i - oldi, out + 1, oldi == 0);

		/* i was supposed to wrap around from out+1 to 0, incrementing
		   n each time, so we'll fix that now: */

		if (i / (out + 1) > UINT_MAX - n)
			return -1;

		n += i / (out + 1);
		i %= (out + 1);

		if (n < initialN)
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
