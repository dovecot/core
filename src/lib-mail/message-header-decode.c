/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "base64.h"
#include "buffer.h"
#include "unichar.h"
#include "charset-utf8.h"
#include "quoted-printable.h"
#include "message-header-decode.h"

static size_t
message_header_decode_encoded(const unsigned char *data, size_t size,
			      buffer_t *decodebuf, size_t *charsetlen_r)
{
#define QCOUNT 3
	unsigned int num = 0;
	size_t i, start_pos[QCOUNT] = {0, 0, 0};

	/* data should contain "charset?encoding?text?=" */
	for (i = 0; i < size; i++) {
		if (data[i] == '?') {
			start_pos[num++] = i;
			if (num == QCOUNT)
				break;
		}
	}
	if (i+1 >= size || data[i+1] != '=') {
		/* invalid block */
		return 0;
	}

	buffer_append(decodebuf, data, start_pos[0]);
	buffer_append_c(decodebuf, '\0');
	*charsetlen_r = decodebuf->used;

	switch (data[start_pos[0]+1]) {
	case 'q':
	case 'Q':
		if (quoted_printable_q_decode(data + start_pos[1] + 1,
					      start_pos[2] - start_pos[1] - 1,
					      decodebuf) < 0) {
			/* we skipped over some invalid data */
		}
		break;
	case 'b':
	case 'B':
		if (base64_decode(data + start_pos[1] + 1,
				  start_pos[2] - start_pos[1] - 1,
				  NULL, decodebuf) < 0) {
			/* contains invalid data. show what we got so far. */
		}
		break;
	default:
		/* unknown encoding */
		return 0;
	}

	return start_pos[2] + 2;
}

static bool is_only_lwsp(const unsigned char *data, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		if (!(data[i] == ' ' || data[i] == '\t' ||
		      data[i] == '\r' || data[i] == '\n'))
			return FALSE;
	}
	return TRUE;
}

void message_header_decode(const unsigned char *data, size_t size,
			   message_header_decode_callback_t *callback,
			   void *context)
{
	buffer_t *decodebuf = NULL;
	size_t charsetlen = 0;
	size_t pos, start_pos, ret;

	/* =?charset?Q|B?text?= */
	start_pos = 0;
	for (pos = 0; pos + 1 < size; ) {
		if (data[pos] != '=' || data[pos+1] != '?') {
			pos++;
			continue;
		}

		/* encoded string beginning */
		if (pos != start_pos &&
		    !is_only_lwsp(data+start_pos, pos-start_pos)) {
			/* send the unencoded data so far */
			if (!callback(data + start_pos, pos - start_pos,
				      NULL, context)) {
				start_pos = size;
				break;
			}
		}

		if (decodebuf == NULL) {
			decodebuf = buffer_create_dynamic(default_pool,
							  size - pos);
		} else {
			buffer_set_used_size(decodebuf, 0);
		}

		pos += 2;
		ret = message_header_decode_encoded(data + pos, size - pos,
						    decodebuf, &charsetlen);
		if (ret == 0) {
			start_pos = pos-2;
			continue;
		}
		pos += ret;

		if (decodebuf->used > charsetlen) {
			/* decodebuf contains <charset> NUL <text> */
			if (!callback(CONST_PTR_OFFSET(decodebuf->data,
						       charsetlen),
				      decodebuf->used - charsetlen,
				      decodebuf->data, context)) {
				start_pos = size;
				break;
			}
		}

		start_pos = pos;
	}

	if (size != start_pos) {
		i_assert(size > start_pos);
		(void)callback(data + start_pos, size - start_pos,
			       NULL, context);
	}
	buffer_free(&decodebuf);
}

struct decode_utf8_context {
	buffer_t *dest;
	normalizer_func_t *normalizer;
	bool changed:1;
};

static bool
decode_utf8_callback(const unsigned char *data, size_t size,
		     const char *charset, void *context)
{
	struct decode_utf8_context *ctx = context;
	struct charset_translation *t;

	if (charset == NULL || charset_is_utf8(charset)) {
		/* ASCII / UTF-8 */
		if (ctx->normalizer != NULL) {
			(void)ctx->normalizer(data, size, ctx->dest);
		} else {
			if (uni_utf8_get_valid_data(data, size, ctx->dest))
				buffer_append(ctx->dest, data, size);
		}
		return TRUE;
	}

	if (charset_to_utf8_begin(charset, ctx->normalizer, &t) < 0) {
		/* data probably still contains some valid ASCII characters.
		   append them. */
		if (uni_utf8_get_valid_data(data, size, ctx->dest))
			buffer_append(ctx->dest, data, size);
		return TRUE;
	}

	/* ignore any errors */
	(void)charset_to_utf8(t, data, &size, ctx->dest);
	charset_to_utf8_end(&t);
	return TRUE;
}

void message_header_decode_utf8(const unsigned char *data, size_t size,
				buffer_t *dest, normalizer_func_t *normalizer)
{
	struct decode_utf8_context ctx;

	i_zero(&ctx);
	ctx.dest = dest;
	ctx.normalizer = normalizer;
	message_header_decode(data, size, decode_utf8_callback, &ctx);
}
