/* Copyright (c) 2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "istream-private.h"
#include "qp-encoder.h"
#include <ctype.h>

struct qp_encoder {
	const char *linebreak;
	string_t *dest;
	size_t line_len;
	size_t max_len;
	enum qp_encoder_flag flags;
	bool add_header_preamble:1;
	bool cr_last:1;
};

struct qp_encoder *
qp_encoder_init(string_t *dest, unsigned int max_len, enum qp_encoder_flag flags)
{
	i_assert(max_len > 0);

	if ((flags & QP_ENCODER_FLAG_HEADER_FORMAT) != 0 &&
	    (flags & QP_ENCODER_FLAG_BINARY_DATA) != 0)
		i_panic("qp encoder cannot do header format with binary data");

	struct qp_encoder *qp = i_new(struct qp_encoder, 1);
	qp->flags = flags;
	qp->dest = dest;
	qp->max_len = max_len;

	if ((flags & QP_ENCODER_FLAG_HEADER_FORMAT) != 0) {
		qp->linebreak = "?=\r\n =?utf-8?Q?";
		qp->add_header_preamble = TRUE;
	} else {
		qp->linebreak = "=\r\n";
	}
	return qp;
}

void qp_encoder_deinit(struct qp_encoder **qp)
{
	i_free(*qp);
}

static inline void
qp_encode_or_break(struct qp_encoder *qp, unsigned char c)
{
	bool encode = FALSE;

	if ((qp->flags & QP_ENCODER_FLAG_HEADER_FORMAT) != 0) {
		if (c == ' ')
			c = '_';
		else if (c != '\t' &&
			 (c == '?' || c == '_' || c == '=' || c < 33 || c > 126))
			encode = TRUE;
	} else if (c != ' ' && c != '\t' &&
		   (c == '=' || c < 33 || c > 126)) {
		encode = TRUE;
	}

	/* Include terminating = as well */
	if ((c == ' ' || c == '\t') && qp->line_len + 4 >= qp->max_len) {
		const char *ptr = strchr(qp->linebreak, '\n');
		str_printfa(qp->dest, "=%02X%s", c, qp->linebreak);
		if (ptr != NULL)
			qp->line_len = strlen(ptr+1);
		else
			qp->line_len = 0;
		return;
	}

	/* Include terminating = as well */
	if (qp->line_len + (encode?4:2) >= qp->max_len) {
		str_append(qp->dest, qp->linebreak);
		qp->line_len = 0;
	}

	if (encode) {
		str_printfa(qp->dest, "=%02X", c);
		qp->line_len += 3;
	} else {
		str_append_c(qp->dest, c);
		qp->line_len += 1;
	}
}

void qp_encoder_more(struct qp_encoder *qp, const void *_src, size_t src_size)
{
	const unsigned char *src = _src;
	i_assert(_src != NULL || src_size == 0);
	if (src_size == 0)
		return;
	if (qp->add_header_preamble) {
		size_t used = qp->dest->used;
		qp->add_header_preamble = FALSE;
		str_append(qp->dest, "=?utf-8?Q?");
		qp->line_len = qp->dest->used - used;
	}
	for(unsigned int i = 0; i < src_size; i++) {
		unsigned char c = src[i];
		/* if input is not binary data and we encounter newline
		   convert it as crlf, or if the last byte was CR, preserve
		   CRLF */
		if (c == '\n' &&
		    ((qp->flags & (QP_ENCODER_FLAG_BINARY_DATA|QP_ENCODER_FLAG_HEADER_FORMAT)) == 0 ||
		      qp->cr_last)) {
			str_append_c(qp->dest, '\r');
			str_append_c(qp->dest, '\n');
			/* reset line length here */
			qp->line_len = 0;
			qp->cr_last = FALSE;
			continue;
		} else if (qp->cr_last) {
			qp_encode_or_break(qp, '\r');
			qp->cr_last = FALSE;
		}
		if (c == '\r') {
			qp->cr_last = TRUE;
		} else {
			qp_encode_or_break(qp, c);
		}
	}
}

void qp_encoder_finish(struct qp_encoder *qp)
{
	if (qp->cr_last)
		qp_encode_or_break(qp, '\r');

	if ((qp->flags & QP_ENCODER_FLAG_HEADER_FORMAT) != 0 &&
	    !qp->add_header_preamble)
		str_append(qp->dest, "?=");
	if ((qp->flags & QP_ENCODER_FLAG_HEADER_FORMAT) != 0)
		qp->add_header_preamble = TRUE;
	qp->line_len = 0;
	qp->cr_last = FALSE;
}
