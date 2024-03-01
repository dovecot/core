/* This file is a slight adaption of the sample code in RFC 3492;
   no copyright is claimed. */

#include "lib.h"
#include "str.h"
#include "unichar.h"
#include "punycode.h"

#include <limits.h>
#include <stddef.h>

/*** Bootstring parameters for Punycode ***/

static const uint base = 36;
static const uint tmin = 1;
static const uint tmax = 26;
static const uint skew = 38;
static const uint damp = 700;
static const uint initialBias = 72;
static const uint initialN = 0x80;
static const uint delimiter = 0x2D;

/* basic(cp) tests whether cp is a basic code point: */
static inline bool basic(uint cp) {
    return cp < 0x80;
}

/* delim(cp) tests whether cp is a delimiter: */
static inline bool delim(uint cp) {
    return cp == delimiter;
}

/* decode_digit(cp) returns the numeric value of a basic code point
 (for use in representing integers) in the range 0 to base-1, or base
 if cp does not represent a value.  */

static inline uint decode_digit(uint cp)
{
  return  cp - 48 < 10 ? cp - 22 :  cp - 65 < 26 ? cp - 65 :
          cp - 97 < 26 ? cp - 97 :  base;
}

/*** Bias adaptation function ***/

static uint adapt(uint delta, uint numpoints, int firsttime )
{
    uint k;

    delta = firsttime ? delta / damp : delta >> 1;
    /* delta >> 1 is a faster way of doing delta / 2 */
    delta += delta / numpoints;

    for (k = 0;  delta > ((base - tmin) * tmax) / 2;  k += base) {
        delta /= base - tmin;
    }

    return k + (base - tmin + 1) * delta / (delta + skew);
}


/*! Decodes a punycoded string and returns the result, or its input if
    there's any failure. */

string_t *punycode_decode(string_t *input) {
    unichar_t label[64];
    uint n, i, bias, oldi, w, k, digit, t;
    size_t b, j, in, out;
    const char * input_c;

    input_c = str_c(input);
    out = 0;

    /* Initialize the state: */

    n = initialN;
    i = 0;
    bias = initialBias;

    /* Handle the basic code points: Let b be the number of input code
       points before the last delimiter, or 0 if there is none, then
       copy the first b code points to the output.  */

    for (b = j = 0; j < str_len(input); ++j)
        if (delim(input_c[j]))
            b = j;

    for (j = 0; j < b; ++j) {
        if (!basic(input_c[j]))
            return input;
        label[out++] = input_c[j];
    }

    /* Main decoding loop: Start just after the last delimiter if any
       basic code points were copied; start at the beginning
       otherwise. */

    in = b > 0 ? b + 1 : 0;
    while (in < str_len(input)) {
        /* in is the index of the next ASCII code point to be
           consumed, and out is the number of code points in the
           output array.  */

        /* Decode a generalized variable-length integer into delta,
           which gets added to i.  The overflow checking is easier if
           we increase i as we go, then subtract off its starting
           value at the end to obtain delta.  */

        oldi = i;
        w = 1;
        k = base;
        while (true) {
            digit = decode_digit( input_c[in++] );
            if (digit >= base)
                return input;
            if (digit > (UINT_MAX - i) / w)
                return input;
            i += digit * w;
            t = k <= bias /* + tmin */ ? tmin :     /* +tmin not needed */
                k >= bias + tmax ? tmax : k - bias;
            if (digit < t)
                break;
            if (w > UINT_MAX / (base - t))
                return input;
            w *= (base - t);
            k += base;
        }

        bias = adapt( i - oldi, out + 1, oldi == 0);

        /* i was supposed to wrap around from out+1 to 0, incrementing
           n each time, so we'll fix that now: */

        if (i / (out + 1) > UINT_MAX - n)
            return input;
        n += i / (out + 1);
        i %= (out + 1);

        /* Insert n at position i of the output: */

        if (i <= out) {
            uint j = out++;
            while (j-- > i)
                label[j+1] = label[j];
            label[i] = n;
        } else {
            return input;
        }

        i++;
    }

    string_t *result = t_str_new(out*2);
    uni_ucs4_to_utf8(label, out, result);
    return result;
}
