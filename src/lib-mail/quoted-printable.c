/* Copyright (c) 2002-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"
#include "quoted-printable.h"

#define QP_IS_TRAILING_SPACE(c) \
	((c) == ' ' || (c) == '\t')

static int
qp_is_end_of_line(const unsigned char *src, size_t *src_pos, size_t size)
{
	size_t i = *src_pos;

	i_assert(src[i] == '=');
	for (i++; i < size; i++) {
		if (QP_IS_TRAILING_SPACE(src[i]) || src[i] == '\r')
			continue;

		if (src[i] != '\n')
			return 0;

		*src_pos = i;
		return 1;
	}
	return -1;
}

void quoted_printable_decode(const unsigned char *src, size_t src_size,
			     size_t *src_pos_r, buffer_t *dest)
{
	char hexbuf[3];
	size_t src_pos, pos, next;
	int ret;

	hexbuf[2] = '\0';

	next = 0;
	for (src_pos = 0; src_pos < src_size; src_pos++) {
		if (src[src_pos] != '=' && src[src_pos] != '\n')
			continue;

		if (src[src_pos] == '\n') {
			/* drop trailing whitespace */
			pos = src_pos;
			if (pos > 0 && src[pos-1] == '\r')
				pos--;
			while (pos > 0 && QP_IS_TRAILING_SPACE(src[pos-1]))
				pos--;
			buffer_append(dest, src + next, pos - next);
			next = src_pos+1;
			buffer_append(dest, "\r\n", 2);
			continue;
		}

		/* '=' */
		buffer_append(dest, src + next, src_pos - next);
		next = src_pos;

		if ((ret = qp_is_end_of_line(src, &src_pos, src_size)) > 0) {
			/* =[whitespace][\r]\n */
			next = src_pos+1;
			continue;
		}
		if (ret < 0) {
			/* unknown yet if this is end of line */
			break;
		}
		if (src_pos+2 >= src_size)
			break;

		/* =<hex> */
		hexbuf[0] = src[src_pos+1];
		hexbuf[1] = src[src_pos+2];

		if (hex_to_binary(hexbuf, dest) == 0) {
			src_pos += 2;
			next = src_pos + 1;
		} else {
			/* non-hex data, show as-is */
			next = src_pos;
		}
	}
	if (src_pos == src_size) {
		/* add everything but trailing spaces */
		if (src_pos > 0 && src[src_pos-1] == '\r')
			src_pos--;
		while (src_pos > 0 && QP_IS_TRAILING_SPACE(src[src_pos-1]))
			src_pos--;
		buffer_append(dest, src + next, src_pos - next);
		next = src_pos;
	}

	*src_pos_r = next;
}

void quoted_printable_q_decode(const unsigned char *src, size_t src_size,
			       buffer_t *dest)
{
	char hexbuf[3];
	size_t src_pos, next;

	hexbuf[2] = '\0';

	next = 0;
	for (src_pos = 0; src_pos < src_size; src_pos++) {
		if (src[src_pos] != '_' && src[src_pos] != '=')
			continue;

		buffer_append(dest, src + next, src_pos - next);
		next = src_pos;

		if (src[src_pos] == '_') {
			buffer_append_c(dest, ' ');
			next++;
			continue;
		}

		if (src_pos+2 >= src_size)
			break;

		/* =<hex> */
		hexbuf[0] = src[src_pos+1];
		hexbuf[1] = src[src_pos+2];

		if (hex_to_binary(hexbuf, dest) == 0) {
			src_pos += 2;
			next = src_pos+1;
		} else {
			/* non-hex data, show as-is */
			next = src_pos;
		}
	}
	buffer_append(dest, src + next, src_size - next);
}
