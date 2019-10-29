/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "istream.h"
#include "mail-html2text.h"
#include "message-parser.h"
#include "message-decoder.h"
#include "message-snippet.h"

enum snippet_state {
	/* beginning of the line */
	SNIPPET_STATE_NEWLINE = 0,
	/* within normal text */
	SNIPPET_STATE_NORMAL,
	/* within quoted text - skip until EOL */
	SNIPPET_STATE_QUOTED
};

struct snippet_data {
	string_t *snippet;
	unsigned int chars_left;
};

struct snippet_context {
	struct snippet_data snippet;
	enum snippet_state state;
	bool add_whitespace;
	struct mail_html2text *html2text;
	buffer_t *plain_output;
};

static bool snippet_generate(struct snippet_context *ctx,
			     const unsigned char *data, size_t size)
{
	size_t i, count;

	if (ctx->html2text != NULL) {
		buffer_set_used_size(ctx->plain_output, 0);
		mail_html2text_more(ctx->html2text, data, size,
				    ctx->plain_output);
		data = ctx->plain_output->data;
		size = ctx->plain_output->used;
	}

	/* message-decoder should feed us only valid and complete
	   UTF-8 input */

	for (i = 0; i < size; i += count) {
		count = 1;
		switch (ctx->state) {
		case SNIPPET_STATE_NEWLINE:
			if (data[i] == '>' && ctx->html2text == NULL) {
				ctx->state = SNIPPET_STATE_QUOTED;
				break;
			}
			ctx->state = SNIPPET_STATE_NORMAL;
			/* fallthrough */
		case SNIPPET_STATE_NORMAL:
			if (size-i >= 3 &&
			     ((data[i] == 0xEF && data[i+1] == 0xBB && data[i+2] == 0xBF) ||
			      (data[i] == 0xBF && data[i+1] == 0xBB && data[i+2] == 0xEF))) {
				count += 2; /* because we skip +1 next */
				break;
			}
			if (data[i] == '\0') {
				/* skip NULs without increasing snippet size */
				break;
			}
			if (data[i] == '\r' || data[i] == '\n' ||
			    data[i] == '\t' || data[i] == ' ') {
				/* skip any leading whitespace */
				if (str_len(ctx->snippet.snippet) > 1)
					ctx->add_whitespace = TRUE;
				if (data[i] == '\n')
					ctx->state = SNIPPET_STATE_NEWLINE;
				break;
			}
			if (ctx->add_whitespace) {
				str_append_c(ctx->snippet.snippet, ' ');
				ctx->add_whitespace = FALSE;
				if (ctx->snippet.chars_left-- == 0)
					return FALSE;
			}
			if (ctx->snippet.chars_left == 0)
				return FALSE;
			ctx->snippet.chars_left--;
			count = uni_utf8_char_bytes(data[i]);
			i_assert(i + count <= size);
			str_append_data(ctx->snippet.snippet, data + i, count);
			break;
		case SNIPPET_STATE_QUOTED:
			if (data[i] == '\n')
				ctx->state = SNIPPET_STATE_NEWLINE;
			break;
		}
	}
	return TRUE;
}

int message_snippet_generate(struct istream *input,
			     unsigned int max_snippet_chars,
			     string_t *snippet)
{
	struct message_parser_ctx *parser;
	struct message_part *parts;
	struct message_decoder_context *decoder;
	struct message_block raw_block, block;
	struct snippet_context ctx;
	pool_t pool;
	int ret;

	i_zero(&ctx);
	pool = pool_alloconly_create("message snippet", 1024);
	ctx.snippet.snippet = snippet;
	ctx.snippet.chars_left = max_snippet_chars;

	parser = message_parser_init(pool_datastack_create(), input, 0, 0);
	decoder = message_decoder_init(NULL, 0);
	while ((ret = message_parser_parse_next_block(parser, &raw_block)) > 0) {
		if (!message_decoder_decode_next_block(decoder, &raw_block, &block))
			continue;
		if (block.size == 0) {
			const char *ct;

			if (block.hdr != NULL)
				continue;

			/* end of headers - verify that we can use this
			   Content-Type. we get here only once, because we
			   always handle only one non-multipart MIME part. */
			ct = message_decoder_current_content_type(decoder);
			if (ct == NULL)
				/* text/plain */ ;
			else if (mail_html2text_content_type_match(ct)) {
				ctx.html2text = mail_html2text_init(MAIL_HTML2TEXT_FLAG_SKIP_QUOTED);
				ctx.plain_output = buffer_create_dynamic(pool, 1024);
			} else if (strncasecmp(ct, "text/", 5) != 0)
				break;
			continue;
		}
		if (!snippet_generate(&ctx, block.data, block.size))
			break;
	}
	i_assert(ret != 0);
	message_decoder_deinit(&decoder);
	message_parser_deinit(&parser, &parts);
	mail_html2text_deinit(&ctx.html2text);
	pool_unref(&pool);
	return input->stream_errno == 0 ? 0 : -1;
}
