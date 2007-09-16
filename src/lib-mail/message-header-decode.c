/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "base64.h"
#include "buffer.h"
#include "unichar.h"
#include "charset-utf8.h"
#include "quoted-printable.h"
#include "message-header-decode.h"

static size_t
message_header_decode_encoded(const unsigned char *data, size_t size,
			      buffer_t *decodebuf, unsigned int *charsetlen_r)
{
#define QCOUNT 3
	unsigned int num = 0;
	size_t i, start_pos[QCOUNT];

	/* data should contain "charset?encoding?text?=" */
	for (i = 0; i < size; i++) {
		if (data[i] == '?') {
			start_pos[num++] = i;
			if (num == QCOUNT)
				break;
		}
	}
	if (i == size || data[i+1] != '=') {
		/* invalid block */
		return 0;
	}

	buffer_append(decodebuf, data, start_pos[0]);
	buffer_append_c(decodebuf, '\0');
	*charsetlen_r = decodebuf->used;

	switch (data[start_pos[0]+1]) {
	case 'q':
	case 'Q':
		quoted_printable_decode(data + start_pos[1] + 1,
					start_pos[2] - start_pos[1] - 1,
					NULL, decodebuf);
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

void message_header_decode(const unsigned char *data, size_t size,
			   message_header_decode_callback_t *callback,
			   void *context)
{
	buffer_t *decodebuf = NULL;
	unsigned int charsetlen = 0;
	size_t pos, start_pos;

	/* =?charset?Q|B?text?= */
	t_push();
	start_pos = pos = 0;
	for (pos = 0; pos + 1 < size; ) {
		if (data[pos] != '=' || data[pos+1] != '?') {
			pos++;
			continue;
		}

		/* encoded string beginning */
		if (pos != start_pos) {
			/* send the unencoded data so far */
			if (!callback(data + start_pos, pos - start_pos,
				      NULL, context)) {
				start_pos = size;
				break;
			}
		}

		if (decodebuf == NULL) {
			decodebuf =
				buffer_create_dynamic(pool_datastack_create(),
						      size - pos);
		} else {
			buffer_set_used_size(decodebuf, 0);
		}

		pos += 2;
		pos += message_header_decode_encoded(data + pos, size - pos,
						     decodebuf, &charsetlen);

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
		(void)callback(data + start_pos, size - start_pos,
			       NULL, context);
	}
	t_pop();
}

struct decode_utf8_context {
	buffer_t *dest;
	unsigned int changed:1;
	unsigned int called:1;
	unsigned int dtcase:1;
};

static bool
decode_utf8_callback(const unsigned char *data, size_t size,
		     const char *charset, void *context)
{
	struct decode_utf8_context *ctx = context;
	struct charset_translation *t;

	/* one call with charset=NULL means nothing changed */
	if (!ctx->called && charset == NULL)
		ctx->called = TRUE;
	else
		ctx->changed = TRUE;

	if (charset == NULL || charset_is_utf8(charset)) {
		/* ASCII / UTF-8 */
		if (ctx->dtcase) {
			(void)uni_utf8_to_decomposed_titlecase(data, size,
							       ctx->dest);
		} else {
			buffer_append(ctx->dest, data, size);
		}
		return TRUE;
	}

	if (charset_to_utf8_begin(charset, ctx->dtcase, &t) < 0) {
		/* let's just ignore this part */
		return TRUE;
	}

	/* ignore any errors */
	(void)charset_to_utf8(t, data, &size, ctx->dest);
	charset_to_utf8_end(&t);
	return TRUE;
}

bool message_header_decode_utf8(const unsigned char *data, size_t size,
				buffer_t *dest, bool dtcase)
{
	struct decode_utf8_context ctx;
	size_t used = dest->used;

	memset(&ctx, 0, sizeof(ctx));
	ctx.dest = dest;
	ctx.dtcase = dtcase;
	message_header_decode(data, size, decode_utf8_callback, &ctx);
	return ctx.changed || (dest->used - used != size);
}
