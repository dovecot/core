/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "base64.h"
#include "buffer.h"
#include "istream.h"
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

	Buffer *decode_buf;

	size_t *matches;
	ssize_t match_count;

	char *content_type;
	char *content_charset;

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
		ctx->content_type =
			i_strdup(rfc822_tokens_get_value(tokens, count));
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
			i_strdup(rfc822_tokens_get_value(value, value_count));
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
		ctx->found = message_header_search(value, value_len,
						   ctx->hdr_search_ctx);
	}

	t_push();

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

	t_pop();
}

static int message_search_header(PartSearchContext *ctx, IStream *input)
{
	ctx->hdr_search_ctx = message_header_search_init(data_stack_pool,
							 ctx->body_ctx->key,
							 ctx->body_ctx->charset,
							 NULL);

	/* we default to text content-type */
	ctx->content_type_text = TRUE;
	message_parse_header(NULL, input, NULL, header_find, ctx);

	return ctx->found;
}

static int message_search_decoded_block(PartSearchContext *ctx, Buffer *block)
{
	const unsigned char *p, *end, *key;
	size_t key_len, block_size;
	ssize_t i;

	key = (const unsigned char *) ctx->body_ctx->key;
	key_len = ctx->body_ctx->key_len;

	p = buffer_get_data(block, &block_size);
	end = p + block_size;
	for (; p != end; p++) {
		for (i = ctx->match_count-1; i >= 0; i--) {
			if (key[ctx->matches[i]] == *p) {
				if (++ctx->matches[i] == key_len) {
					/* full match */
					p++;
					return TRUE;
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

		if (*p == key[0]) {
			if (key_len == 1) {
				/* only one character in search key */
				p++;
				return TRUE;
			}

			i_assert((size_t)ctx->match_count < key_len);
			ctx->matches[ctx->match_count++] = 1;
		}
	}

	return FALSE;
}

/* returns 1 = found, 0 = not found, -1 = error in input data */
static int message_search_body_block(PartSearchContext *ctx, Buffer *block)
{
	Buffer *inbuf, *outbuf;
        CharsetResult result;
	size_t block_pos, inbuf_pos, inbuf_left, ret;

	outbuf = buffer_create_static(data_stack_pool, DECODE_BLOCK_SIZE);
	for (block_pos = 0; block_pos < buffer_get_used_size(block); ) {
		if (buffer_get_used_size(ctx->decode_buf) == 0) {
			/* we can use the buffer directly without copying */
			inbuf = block;
			inbuf_pos = block_pos;
			block_pos += buffer_get_used_size(block);
		} else {
			/* some characters already in buffer, ie. last
			   conversion contained partial data */
			block_pos += buffer_append_buf(ctx->decode_buf,
						       block, block_pos,
						       (size_t)-1);

			inbuf = ctx->decode_buf;
			inbuf_pos = 0;
		}

		buffer_set_used_size(outbuf, 0);
		result = charset_to_ucase_utf8(ctx->translation,
					       inbuf, &inbuf_pos, outbuf);
		inbuf_left = buffer_get_used_size(inbuf) - inbuf_pos;

		switch (result) {
		case CHARSET_RET_OUTPUT_FULL:
			/* we should have copied the incomplete sequence.. */
			i_assert(inbuf_left <= block_pos);
			/* fall through */
		case CHARSET_RET_OK:
			buffer_set_used_size(ctx->decode_buf, 0);
			block_pos -= inbuf_left;
			break;
		case CHARSET_RET_INCOMPLETE_INPUT:
			/* save the partial sequence to buffer */
			ret = buffer_copy(ctx->decode_buf, 0,
					  inbuf, inbuf_pos, inbuf_left);
			i_assert(ret == inbuf_left);

			buffer_set_used_size(ctx->decode_buf, ret);
			break;

		case CHARSET_RET_INVALID_INPUT:
			return -1;
		}

		if (message_search_decoded_block(ctx, outbuf))
			return 1;
	}

	return 0;
}

static int message_search_body(PartSearchContext *ctx, IStream *input,
			       MessagePart *part)
{
	const unsigned char *data;
	Buffer *decodebuf;
	size_t data_size, pos;
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

	ctx->decode_buf = buffer_create_static(data_stack_pool, 256);

	ctx->match_count = 0;
	ctx->matches = t_malloc(sizeof(size_t) * ctx->body_ctx->key_len);

	i_stream_skip(input, part->physical_pos +
		      part->header_size.physical_size - input->v_offset);

	old_limit = input->v_limit;
	i_stream_set_read_limit(input, input->v_offset +
				part->body_size.physical_size);

	found = FALSE; pos = 0;
	while (i_stream_read_data(input, &data, &data_size, pos) > 0) {
		/* limit the size of t_malloc()s */
		if (data_size > DECODE_BLOCK_SIZE)
			data_size = DECODE_BLOCK_SIZE;
		pos = data_size;

		t_push();
		if (ctx->content_qp) {
			decodebuf = buffer_create_static_hard(data_stack_pool,
							      data_size);
			quoted_printable_decode(data, data_size,
						&data_size, decodebuf);
		} else if (ctx->content_base64) {
			size_t size = MAX_BASE64_DECODED_SIZE(data_size);
			decodebuf = buffer_create_static_hard(data_stack_pool,
							      size);

			if (base64_decode(data, data_size,
					  &data_size, decodebuf) < 0) {
				/* corrupted base64 data, don't bother with
				   the rest of it */
				t_pop();
				break;
			}
		} else {
			decodebuf = buffer_create_const_data(data_stack_pool,
							     data, data_size);
		}

		ret = message_search_body_block(ctx, decodebuf);
		t_pop();

		if (ret != 0) {
			found = ret > 0;
			break;
		}

		i_stream_skip(input, data_size);
		pos -= data_size;
	}

	i_stream_set_read_limit(input, old_limit);

	if (ctx->translation != NULL)
		charset_to_utf8_end(ctx->translation);
	return found;
}

static int message_body_search_init(BodySearchContext *ctx, const char *key,
				    const char *charset, int *unknown_charset,
				    int search_header)
{
	Buffer *keybuf;
	size_t key_len;

	memset(ctx, 0, sizeof(BodySearchContext));

	/* get the key uppercased */
        keybuf = buffer_create_const_data(data_stack_pool, key, strlen(key));
	key = charset_to_ucase_utf8_string(charset, unknown_charset,
					   keybuf, &key_len);
	if (key == NULL)
		return FALSE;

	ctx->key = key;
	ctx->key_len = key_len;
	ctx->charset = charset;
	ctx->unknown_charset = charset == NULL;
	ctx->search_header = search_header;

	i_assert(ctx->key_len <= SSIZE_T_MAX/sizeof(size_t));

	return TRUE;
}

static int message_body_search_ctx(BodySearchContext *ctx, IStream *input,
				   MessagePart *part)
{
	PartSearchContext part_ctx;
	int found;

	found = FALSE;
	while (part != NULL && !found) {
		i_assert(input->v_offset <= part->physical_pos);

		i_stream_skip(input, part->physical_pos - input->v_offset);

		memset(&part_ctx, 0, sizeof(part_ctx));
		part_ctx.body_ctx = ctx;
		part_ctx.ignore_header =
			part->parent == NULL && !ctx->search_header;

		t_push();

		if (message_search_header(&part_ctx, input)) {
			found = TRUE;
		} else if (part->children != NULL) {
			/* multipart/xxx or message/rfc822 */
			if (message_body_search_ctx(ctx, input, part->children))
				found = TRUE;
		} else {
			if (message_search_body(&part_ctx, input, part))
				found = TRUE;
		}

		i_free(part_ctx.content_type);
		i_free(part_ctx.content_charset);

		t_pop();

		part = part->next;
	}

	return found;
}

int message_body_search(const char *key, const char *charset,
			int *unknown_charset, IStream *input,
			MessagePart *part, int search_header)
{
        BodySearchContext ctx;

	if (!message_body_search_init(&ctx, key, charset, unknown_charset,
				      search_header))
		return -1;

	return message_body_search_ctx(&ctx, input, part);
}
