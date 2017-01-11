/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"
#include "qp-decoder.h"

/* quoted-printable lines can be max 76 characters. if we've seen more than
   that much whitespace, it means there really shouldn't be anything else left
   in the line except trailing whitespace. */
#define QP_MAX_WHITESPACE_LEN 76

#define QP_IS_TRAILING_WHITESPACE(c) \
	((c) == ' ' || (c) == '\t')

enum qp_state {
	STATE_TEXT = 0,
	STATE_WHITESPACE,
	STATE_EQUALS,
	STATE_EQUALS_WHITESPACE,
	STATE_HEX2,
	STATE_CR,
	STATE_SOFTCR
};

struct qp_decoder {
	buffer_t *dest;
	buffer_t *whitespace;
	enum qp_state state;
	char hexchar;
};

struct qp_decoder *qp_decoder_init(buffer_t *dest)
{
	struct qp_decoder *qp;

	qp = i_new(struct qp_decoder, 1);
	qp->dest = dest;
	qp->whitespace = buffer_create_dynamic(default_pool, 80);
	return qp;
}

void qp_decoder_deinit(struct qp_decoder **_qp)
{
	struct qp_decoder *qp = *_qp;

	buffer_free(&qp->whitespace);
	i_free(qp);
}

static size_t
qp_decoder_more_text(struct qp_decoder *qp, const unsigned char *src,
		     size_t src_size)
{
	size_t i, start = 0, ret = src_size;

	for (i = 0; i < src_size; i++) {
		if (src[i] > '=') {
			/* fast path */
			continue;
		}
		switch (src[i]) {
		case '=':
			qp->state = STATE_EQUALS;
			break;
		case '\r':
			qp->state = STATE_CR;
			break;
		case '\n':
			/* LF without preceding CR */
			buffer_append(qp->dest, src+start, i-start);
			buffer_append(qp->dest, "\r\n", 2);
			start = i+1;
			continue;
		case ' ':
		case '\t':
			i_assert(qp->whitespace->used == 0);
			qp->state = STATE_WHITESPACE;
			buffer_append_c(qp->whitespace, src[i]);
			break;
		default:
			continue;
		}
		ret = i+1;
		break;
	}
	buffer_append(qp->dest, src+start, i-start);
	return ret;
}

static void qp_decoder_invalid(struct qp_decoder *qp, const char **error_r)
{
	switch (qp->state) {
	case STATE_EQUALS:
		buffer_append_c(qp->dest, '=');
		*error_r = "'=' not followed by two hex digits";
		break;
	case STATE_HEX2:
		buffer_append_c(qp->dest, '=');
		buffer_append_c(qp->dest, qp->hexchar);
		*error_r = "'=<hex>' not followed by a hex digit";
		break;
	case STATE_EQUALS_WHITESPACE:
		buffer_append_c(qp->dest, '=');
		buffer_append_buf(qp->dest, qp->whitespace, 0, (size_t)-1);
		buffer_set_used_size(qp->whitespace, 0);
		*error_r = "'=<whitespace>' not followed by newline";
		break;
	case STATE_CR:
		buffer_append_buf(qp->dest, qp->whitespace, 0, (size_t)-1);
		buffer_set_used_size(qp->whitespace, 0);
		buffer_append_c(qp->dest, '\r');
		*error_r = "CR not followed by LF";
		break;
	case STATE_SOFTCR:
		buffer_append_c(qp->dest, '=');
		buffer_append_buf(qp->dest, qp->whitespace, 0, (size_t)-1);
		buffer_set_used_size(qp->whitespace, 0);
		buffer_append_c(qp->dest, '\r');
		*error_r = "CR not followed by LF";
		break;
	case STATE_TEXT:
	case STATE_WHITESPACE:
		i_unreached();
	}
	qp->state = STATE_TEXT;
	i_assert(*error_r != NULL);
}

int qp_decoder_more(struct qp_decoder *qp, const unsigned char *src,
		    size_t src_size, size_t *invalid_src_pos_r,
		    const char **error_r)
{
	const char *error;
	size_t i;

	*invalid_src_pos_r = (size_t)-1;
	*error_r = NULL;

	for (i = 0; i < src_size; ) {
		switch (qp->state) {
		case STATE_TEXT:
			i += qp_decoder_more_text(qp, src+i, src_size-i);
			/* don't increment i any more than we already did,
			   so continue instead of break */
			continue;
		case STATE_WHITESPACE:
			if (QP_IS_TRAILING_WHITESPACE(src[i])) {
				/* more whitespace */
				if (qp->whitespace->used <= QP_MAX_WHITESPACE_LEN)
					buffer_append_c(qp->whitespace, src[i]);
			} else if (src[i] == '\r') {
				qp->state = STATE_CR;
			} else if (src[i] == '\n') {
				/* drop the trailing whitespace */
				buffer_append(qp->dest, "\r\n", 2);
				buffer_set_used_size(qp->whitespace, 0);
			} else {
				/* this wasn't trailing whitespace.
				   put it back. */
				buffer_append_buf(qp->dest, qp->whitespace,
						  0, (size_t)-1);
				if (qp->whitespace->used > QP_MAX_WHITESPACE_LEN) {
					/* we already truncated some of the
					   whitespace away, because the line
					   is too long */
					if (*invalid_src_pos_r == (size_t)-1) {
						*invalid_src_pos_r = i;
						*error_r = "Too much whitespace";
					}
				}
				buffer_set_used_size(qp->whitespace, 0);
				qp->state = STATE_TEXT;
				continue; /* don't increment i */
			}
			break;
		case STATE_EQUALS:
			if ((src[i] >= '0' && src[i] <= '9') ||
			    (src[i] >= 'A' && src[i] <= 'F') ||
			    /* lowercase hex isn't strictly valid, but allow */
			    (src[i] >= 'a' && src[i] <= 'f')) {
				qp->hexchar = src[i];
				qp->state = STATE_HEX2;
			} else if (QP_IS_TRAILING_WHITESPACE(src[i])) {
				i_assert(qp->whitespace->used == 0);
				buffer_append_c(qp->whitespace, src[i]);
				qp->state = STATE_EQUALS_WHITESPACE;
			} else if (src[i] == '\r')
				qp->state = STATE_SOFTCR;
			else if (src[i] == '\n') {
				qp->state = STATE_TEXT;
			} else {
				/* invalid input */
				qp_decoder_invalid(qp, &error);
				if (*invalid_src_pos_r == (size_t)-1) {
					*invalid_src_pos_r = i;
					*error_r = error;
				}
				continue; /* don't increment i */
			}
			break;
		case STATE_HEX2:
			if ((src[i] >= '0' && src[i] <= '9') ||
			    (src[i] >= 'A' && src[i] <= 'F') ||
			    (src[i] >= 'a' && src[i] <= 'f')) {
				char data[3];

				data[0] = qp->hexchar;
				data[1] = src[i];
				data[2] = '\0';
				if (hex_to_binary(data, qp->dest) < 0)
					i_unreached();
				qp->state = STATE_TEXT;
			} else {
				/* invalid input */
				qp_decoder_invalid(qp, &error);
				if (*invalid_src_pos_r == (size_t)-1) {
					*invalid_src_pos_r = i;
					*error_r = error;
				}
				continue; /* don't increment i */
			}
			break;
		case STATE_EQUALS_WHITESPACE:
			if (QP_IS_TRAILING_WHITESPACE(src[i])) {
				if (qp->whitespace->used <= QP_MAX_WHITESPACE_LEN)
					buffer_append_c(qp->whitespace, src[i]);
				else {
					/* if this isn't going to get truncated
					   anyway, it's going to be an error */
				}
			} else if (src[i] == '\r')
				qp->state = STATE_SOFTCR;
			else if (src[i] == '\n') {
				buffer_set_used_size(qp->whitespace, 0);
				qp->state = STATE_TEXT;
			} else {
				/* =<whitespace> not followed by [CR]LF
				   is invalid. */
				qp_decoder_invalid(qp, &error);
				if (*invalid_src_pos_r == (size_t)-1) {
					*invalid_src_pos_r = i;
					*error_r = error;
				}
				continue; /* don't increment i */
			}
			break;
		case STATE_CR:
		case STATE_SOFTCR:
			if (src[i] == '\n') {
				buffer_set_used_size(qp->whitespace, 0);
				if (qp->state != STATE_SOFTCR)
					buffer_append(qp->dest, "\r\n", 2);
				qp->state = STATE_TEXT;
			} else {
				qp_decoder_invalid(qp, &error);
				if (*invalid_src_pos_r == (size_t)-1) {
					*invalid_src_pos_r = i;
					*error_r = error;
				}
				continue; /* don't increment i */
			}
			break;
		}
		i++;
	}
	i_assert((*invalid_src_pos_r == (size_t)-1) == (*error_r == NULL));
	return *invalid_src_pos_r == (size_t)-1 ? 0 : -1;
}

int qp_decoder_finish(struct qp_decoder *qp, const char **error_r)
{
	int ret;

	if (qp->state == STATE_TEXT || qp->state == STATE_WHITESPACE) {
		ret = 0;
		*error_r = NULL;
	} else {
		qp_decoder_invalid(qp, error_r);
		ret = -1;
	}
	qp->state = STATE_TEXT;
	buffer_set_used_size(qp->whitespace, 0);
	return ret;
}
