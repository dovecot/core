/* Based on the sources of Cyrus IMAP:
 *
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "lib.h"
#include "base64.h"

static const char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const char *base64_encode(const unsigned char *data, size_t size)
{
	char *buffer, *p;
	int c1, c2, c3;

	buffer = p = t_malloc(size*2 + 5);
	while (size > 0) {
		c1 = *data++; size--;
		*p++ = basis_64[c1 >> 2];

		c2 = size == 0 ? 0 : *data++;
		*p++ = basis_64[((c1 & 0x03) << 4) | ((c2 & 0xf0) >> 4)];
		if (size-- == 0) {
			*p++ = '=';
			*p++ = '=';
			break;
		}

		c3 = size == 0 ? 0 : *data++;
		*p++ = basis_64[((c2 & 0x0f) << 2) | ((c3 & 0xc0) >> 6)];
		if (size-- == 0) {
			*p++ = '=';
			break;
		}

		*p++ = basis_64[c3 & 0x3f];
	}

	*p = '\0';
	return buffer;
}

#define XX 127

/* Table for decoding base64 */
static const char index_64[256] = {
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,62, XX,XX,XX,63,
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
    XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX, XX,XX,XX,XX,
};
#define CHAR64(c)  (index_64[(int)(unsigned char)(c)])

ssize_t base64_decode(const char *src, size_t size, unsigned char *dest)
{
	unsigned char *p;
	int c1, c2, c3, c4;

	p = dest;
	while (size >= 4) {
		c1 = *src++;

		if (CHAR64(c1) == XX)
			return -1;

		c2 = *src++;
		if (CHAR64(c2) == XX)
			return -1;

		c3 = *src++;
		if (c3 != '=' && CHAR64(c3) == XX)
			return -1;

		c4 = *src++;
		if (c4 != '=' && CHAR64(c4) == XX)
			return -1;

		size -= 4;

		*p++ = ((CHAR64(c1) << 2) | ((CHAR64(c2) & 0x30) >> 4));

		if (c3 == '=') {
			if (size != 0 || c4 != '=')
				return -1;
			break;
		}

		*p++ = (((CHAR64(c2) & 0xf) << 4) | ((CHAR64(c3) & 0x3c) >> 2));
		if (c4 == '=') {
			if (size != 0)
				return -1;
			break;
		}
		*p++ = (((CHAR64(c3) & 0x3) << 6) | CHAR64(c4));
	}

	return (ssize_t) (p-dest);
}
