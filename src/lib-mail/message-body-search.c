/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "base64.h"
#include "ibuffer.h"
#include "charset-utf8.h"
#include "rfc822-tokenize.h"
#include "quoted-printable.h"
#include "message-parser.h"
#include "message-content-parser.h"
#include "message-header-search.h"
#include "message-body-search.h"

#define DECODE_BLOCK_SIZE 8192

typedef struct {
	Pool pool;

	const char *key;
	size_t key_len;

	const char *charset;
	unsigned int unknown_charset:1;
	unsigned int search_header:1;
} BodySearchContext;

typedef struct {
	BodySearchContext *body_ctx;

	HeaderSearchContext *hdr_search_ctx;
	CharsetTranslation *translation;

	unsigned char decode_buf[DECODE_BLOCK_SIZE];
	size_t decode_buf_used;

	size_t *matches;
	ssize_t match_count;

	const char *content_type;
	const char *content_charset;

	unsigned int content_qp:1;
	unsigned int content_base64:1;
	unsigned int content_unknown:1;
	unsigned int content_type_text:1; /* text/any or message/any */
	unsigned int ignore_header:1;
	unsigned int found:1;
} PartSearchContext;

static void parse_content_type(const Rfc822Token *tokens, int count,
			       void *context)
{
	PartSearchContext *ctx = context;

	if (ctx->content_type != NULL && tokens[0].token == 'A') {
		ctx->content_type = rfc822_tokens_get_value(tokens, count);
		ctx->content_type_text =
			strncasecmp(ctx->content_type, "text/", 5) == 0 ||
			strncasecmp(ctx->content_type, "message/", 8) == 0;
	}
}

static void parse_content_type_param(const Rfc822Token *name,
				     const Rfc822Token *value,
				     int value_count, void *context)
{
	PartSearchContext *ctx = context;

	if (name->len != 7 || strncasecmp(name->ptr, "charset", 7) != 0)
		return;

	if (ctx->content_charset == NULL) {
		ctx->content_charset =
			rfc822_tokens_get_value(value, value_count);
	}
}

static void parse_content_encoding(const Rfc822Token *tokens,
				   int count __attr_unused__, void *context)
{
	PartSearchContext *ctx = context;

	if (tokens[0].token != 'A')
		return;

	switch (tokens[0].len) {
	case 4:
		if (strncasecmp(tokens[0].ptr, "7bit", 4) != 0 &&
		    strncasecmp(tokens[0].ptr, "8bit", 4) != 0)
			ctx->content_unknown = TRUE;
		break;
	case 6:
		if (strncasecmp(tokens[0].ptr, "base64", 6) == 0)
			ctx->content_base64 = TRUE;
		else if (strncasecmp(tokens[0].ptr, "binary", 6) != 0)
			ctx->content_unknown = TRUE;
		break;
	case 16:
		if (strncasecmp(tokens[0].ptr, "quoted-printable", 16) == 0)
			ctx->content_qp = TRUE;
		else
			ctx->content_unknown = TRUE;
		break;
	default:
		ctx->content_unknown = TRUE;
		break;
	}
}

static void header_find(MessagePart *part __attr_unused__,
			const char *name, size_t name_len,
			const char *value, size_t value_len, void *context)
{
	PartSearchContext *ctx = context;

	if (ctx->found)
		return;

	if (!ctx->ignore_header) {
		ctx->found = message_header_search(value, &value_len,
						   ctx->hdr_search_ctx);
	}

	if (name_len == 12 && strncasecmp(name, "Content-Type", 12) == 0) {
		(void)message_content_parse_header(t_strndup(value, value_len),
						   parse_content_type,
						   parse_content_type_param,
						   ctx);
	} else if (name_len == 25 &&
		   strncasecmp(name, "Content-Transfer-Encoding", 25) == 0) {
		(void)message_content_parse_header(t_strndup(value, value_len),
						   parse_content_encoding,
						   NULL, ctx);
	}
}

static int message_search_header(PartSearchContext *ctx, IBuffer *inbuf)
{
	ctx->hdr_search_ctx = message_header_search_init(data_stack_pool,
							 ctx->body_ctx->key,
							 ctx->body_ctx->charset,
							 NULL);

	/* we default to text content-type */
	ctx->content_type_text = TRUE;
	message_parse_header(NULL, inbuf, NULL, header_find, ctx);

	return ctx->found;
}

static int message_search_decoded_block(PartSearchContext *ctx,
					const unsigned char *data, size_t size)
{
	const unsigned char *p, *end, *key;
	size_t key_len;
	ssize_t i;
	int found;

	key = (const unsigned char *) ctx->body_ctx->key;
	key_len = ctx->body_ctx->key_len;

	end = data + size; found = 0;
	for (p = data; p != end; p++) {
		for (i = ctx->match_count-1; i >= 0; i--) {
			if (key[ctx->matches[i]] == *p) {
				if (++ctx->matches[i] == key_len) {
					/* full match */
					p++;
					found = TRUE;
					break;
				}
			} else {
				/* non-match */
				ctx->match_count--;
				if (i != ctx->match_count) {
					memmove(ctx->matches + i,
						ctx->matches + i + 1,
						ctx->match_count - i);
				}
			}
		}

		if (found)
			break;

		if (*p == key[0]) {
			if (key_len == 1) {
				/* only one character in search key */
				p++;
				found = 1;
				break;
			}
			i_assert((size_t)ctx->match_count < key_len);
			ctx->matches[ctx->match_count++] = 1;
		}
	}

	return found;
}

static int message_search_body_block(PartSearchContext *ctx,
				     const unsigned char *data, size_t size)
{
	const unsigned char *inbuf;
	unsigned char outbuf[DECODE_BLOCK_SIZE];
	size_t inbuf_size, outbuf_size, max_size;

	while (size > 0) {
		if (ctx->decode_buf_used == 0) {
			inbuf = data;
			inbuf_size = I_MIN(size, sizeof(ctx->decode_buf));

			data += inbuf_size;
			size -= inbuf_size;
		} else {
			/* some characters already in buffer, ie. last
			   conversion contained partial data */
			max_size = sizeof(ctx->decode_buf) -
				ctx->decode_buf_used;
			if (max_size > size)
				max_size = size;

			memcpy(ctx->decode_buf + ctx->decode_buf_used,
			       data, max_size);
			ctx->decode_buf_used += max_size;

			inbuf = ctx->decode_buf;
			inbuf_size = ctx->decode_buf_used;

			data += max_size;
			size -= max_size;
		}

		outbuf_size = sizeof(outbuf);
		if (!charset_to_ucase_utf8(ctx->translation,
					   &inbuf, &inbuf_size,
					   outbuf, &outbuf_size)) {
			/* something failed */
			return -1;
		}

		if (message_search_decoded_block(ctx, outbuf, outbuf_size))
			return 1;

		if (inbuf_size > 0) {
			/* partial input, save it */
			memmove(ctx->decode_buf, inbuf, inbuf_size);
			ctx->decode_buf_used = inbuf_size;
		}
	}

	return 0;
}

static int message_search_body(PartSearchContext *ctx, IBuffer *inbuf,
			       MessagePart *part)
{
	const unsigned char *data, *decoded;
	unsigned char *decodebuf;
	size_t data_size, decoded_size, pos;
	uoff_t old_limit;
	ssize_t ret;
	int found;

	if (ctx->content_unknown) {
		/* unknown content-encoding-type, ignore */
		return FALSE;
	}

	if (!ctx->content_type_text) {
		/* non-text content, ignore - FIXME: should be configurable? */
		return FALSE;
	}

	ctx->translation = ctx->content_charset == NULL ? NULL :
		charset_to_utf8_begin(ctx->content_charset, NULL);
	if (ctx->translation == NULL)
		ctx->translation = charset_to_utf8_begin("ascii", NULL);

	ctx->match_count = 0;
	ctx->matches = t_malloc(sizeof(size_t) * ctx->body_ctx->key_len);

	i_buffer_skip(inbuf, part->physical_pos +
		      part->header_size.physical_size - inbuf->v_offset);

	old_limit = inbuf->v_limit;
	i_buffer_set_read_limit(inbuf, inbuf->v_offset +
				part->body_size.physical_size);

	found = FALSE; pos = 0;
	while (i_buffer_read_data(inbuf, &data, &data_size, pos) > 0) {
		/* limit the size of t_malloc()s */
		if (data_size > DECODE_BLOCK_SIZE)
			data_size = DECODE_BLOCK_SIZE;
		pos = data_size;

		t_push();
		if (ctx->content_qp) {
			decoded = decodebuf = t_malloc(data_size);
			decoded_size = quoted_printable_decode(data, &data_size,
							       decodebuf);
		} else if (ctx->content_base64) {
			decoded_size = MAX_BASE64_DECODED_SIZE(data_size);
			decoded = decodebuf = t_malloc(decoded_size);

			ret = base64_decode(data, &data_size, decodebuf);
			decoded_size = ret < 0 ? 0 : (size_t)decoded_size;
		} else {
			decoded = data;
			decoded_size = data_size;
		}

		ret = message_search_body_block(ctx, decoded, decoded_size);
		if (ret != 0) {
			t_pop();
			found = ret > 0;
			break;
		}

		t_pop();
		i_buffer_skip(inbuf, data_size);
		pos -= data_size;
	}

	i_buffer_set_read_limit(inbuf, old_limit);

	if (ctx->translation != NULL)
		charset_to_utf8_end(ctx->translation);
	return found;
}

static int message_body_search_init(BodySearchContext *ctx, const char *key,
				    const char *charset, int *unknown_charset,
				    int search_header)
{
	size_t size;

	memset(ctx, 0, sizeof(BodySearchContext));

	/* get the key uppercased */
	size = strlen(key);
	key = charset_to_ucase_utf8_string(charset, unknown_charset,
					   (const unsigned char *) key, &size);
	if (key == NULL)
		return FALSE;

	i_assert(size <= SSIZE_T_MAX/sizeof(size_t));

	ctx->key = key;
	ctx->key_len = size;
	ctx->charset = charset;
	ctx->unknown_charset = charset == NULL;
	ctx->search_header = search_header;

	return TRUE;
}

static int message_body_search_ctx(BodySearchContext *ctx, IBuffer *inbuf,
				   MessagePart *part)
{
	PartSearchContext part_ctx;
	int found;

	found = FALSE;
	while (part != NULL && !found) {
		i_assert(inbuf->v_offset <= part->physical_pos);

		i_buffer_skip(inbuf, part->physical_pos - inbuf->v_offset);

		memset(&part_ctx, 0, sizeof(part_ctx));
		part_ctx.body_ctx = ctx;
		part_ctx.ignore_header =
			part->parent == NULL && !ctx->search_header;

		t_push();

		if (message_search_header(&part_ctx, inbuf)) {
			found = TRUE;
		} else if (part->children != NULL) {
			/* multipart/xxx or message/rfc822 */
			if (message_body_search_ctx(ctx, inbuf, part->children))
				found = TRUE;
		} else {
			if (message_search_body(&part_ctx, inbuf, part))
				found = TRUE;
		}

		t_pop();

		part = part->next;
	}

	return found;
}

int message_body_search(const char *key, const char *charset,
			int *unknown_charset, IBuffer *inbuf,
			MessagePart *part, int search_header)
{
        BodySearchContext ctx;

	if (!message_body_search_init(&ctx, key, charset, unknown_charset,
				      search_header))
		return -1;

	return message_body_search_ctx(&ctx, inbuf, part);
}
