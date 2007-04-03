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
#include "buffer.h"

static const char basis_64[] =
   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const void *src, size_t src_size, buffer_t *dest)
{
	const unsigned char *src_c = src;
	size_t src_pos;
	int c1, c2, c3;

	for (src_pos = 0; src_pos < src_size; ) {
		c1 = src_c[src_pos++];
		buffer_append_c(dest, basis_64[c1 >> 2]);

		c2 = src_pos == src_size ? 0 : src_c[src_pos];
		buffer_append_c(dest, basis_64[((c1 & 0x03) << 4) |
					       ((c2 & 0xf0) >> 4)]);

		if (src_pos++ == src_size) {
			buffer_append(dest, "==", 2);
			break;
		}

		c3 = src_pos == src_size ? 0 : src_c[src_pos];
		buffer_append_c(dest, basis_64[((c2 & 0x0f) << 2) |
					       ((c3 & 0xc0) >> 6)]);

		if (src_pos++ == src_size) {
			buffer_append_c(dest, '=');
			break;
		}

		buffer_append_c(dest, basis_64[c3 & 0x3f]);
	}
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

#define IS_EMPTY(c) \
	((c) == '\n' || (c) == '\r' || (c) == ' ' || (c) == '\t')

int base64_decode(const void *src, size_t src_size,
		  size_t *src_pos_r, buffer_t *dest)
{
	const unsigned char *src_c = src;
	size_t src_pos;
	unsigned char buf[4];
	int c1, c2, c3, c4;
	size_t size;

	for (src_pos = 0; src_pos+3 < src_size; ) {
		c1 = src_c[src_pos++];

		if (IS_EMPTY(c1))
			continue;

		if (index_64[c1] == XX)
			return -1;

		c2 = src_c[src_pos++];
		if (index_64[c2] == XX)
			return -1;

		c3 = src_c[src_pos++];
		if (c3 != '=' && index_64[c3] == XX)
			return -1;

		c4 = src_c[src_pos++];
		if (c4 != '=' && index_64[c4] == XX)
			return -1;

		buf[0] = (index_64[c1] << 2) | ((index_64[c2] & 0x30) >> 4);
		if (c3 == '=') {
			if (c4 != '=')
				return -1;
			size = 1;
		} else {
			buf[1] = ((index_64[c2] & 0xf) << 4) |
				((index_64[c3] & 0x3c) >> 2);

			if (c4 == '=')
				size = 2;
			else {
				buf[2] = ((index_64[c3] & 0x3) << 6) |
					index_64[c4];
				size = 3;
			}
		}

		buffer_append(dest, buf, size);
		if (size < 3) {
			/* end of base64 data */
			break;
		}
	}

	for (; src_pos < src_size; src_pos++) {
		if (!IS_EMPTY(src_c[src_pos]))
			break;
	}

	if (src_pos_r != NULL)
		*src_pos_r = src_pos;

	return 0;
}
