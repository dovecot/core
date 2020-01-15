/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "str.h"
#include "istream.h"
#include "mail-html2text.h"
#include "message-parser.h"
#include "message-decoder.h"
#include "message-snippet.h"

#include <ctype.h>

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
	struct snippet_data quoted_snippet;
	enum snippet_state state;
	bool add_whitespace;
	struct mail_html2text *html2text;
	buffer_t *plain_output;
};

static void snippet_add_content(struct snippet_context *ctx,
				struct snippet_data *target,
				const unsigned char *data, size_t size,
				size_t *count_r)
{
	i_assert(target != NULL);
	if (size == 0)
		return;
	if (size >= 3 &&
	     ((data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF) ||
	      (data[0] == 0xBF && data[1] == 0xBB && data[2] == 0xEF))) {
		*count_r = 3;
		return;
	}
	if (data[0] == '\0') {
		/* skip NULs without increasing snippet size */
		return;
	}
	if (i_isspace(*data)) {
		/* skip any leading whitespace */
		if (str_len(target->snippet) > 1)
			ctx->add_whitespace = TRUE;
		if (data[0] == '\n')
			ctx->state = SNIPPET_STATE_NEWLINE;
		return;
	}
	if (ctx->add_whitespace) {
		str_append_c(target->snippet, ' ');
		ctx->add_whitespace = FALSE;
		if (target->chars_left-- == 0)
			return;
	}
	if (target->chars_left == 0)
		return;
	target->chars_left--;
	*count_r = uni_utf8_char_bytes(data[0]);
	i_assert(*count_r <= size);
	str_append_data(target->snippet, data, *count_r);
}

static bool snippet_generate(struct snippet_context *ctx,
			     const unsigned char *data, size_t size)
{
	size_t i, count;
	struct snippet_data *target = &ctx->snippet;

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
			if (data[i] == '>') {
				ctx->state = SNIPPET_STATE_QUOTED;
				i++;
				target = &ctx->quoted_snippet;
			} else {
				ctx->state = SNIPPET_STATE_NORMAL;
				target = &ctx->snippet;
			}
			/* fallthrough */
		case SNIPPET_STATE_NORMAL:
		case SNIPPET_STATE_QUOTED:
			snippet_add_content(ctx, target, CONST_PTR_OFFSET(data, i),
					    size-i, &count);
			/* break here if we have enough non-quoted data,
			   quoted data does not need to break here as it's
			   only used if the actual snippet is left empty. */
			if (ctx->snippet.chars_left == 0)
				return FALSE;
			break;
		}
	}
	return TRUE;
}

static void snippet_copy(const char *src, string_t *dst)
{
	while (*src != '\0' && i_isspace(*src)) src++;
	str_append(dst, src);
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
	pool = pool_alloconly_create("message snippet", 2048);
	ctx.snippet.snippet = str_new(pool, max_snippet_chars);
	ctx.snippet.chars_left = max_snippet_chars;
	ctx.quoted_snippet.snippet = str_new(pool, max_snippet_chars);
	ctx.quoted_snippet.chars_left = max_snippet_chars;
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
				ctx.html2text = mail_html2text_init(0);
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
	if (ctx.snippet.snippet->used != 0)
		snippet_copy(str_c(ctx.snippet.snippet), snippet);
	else if (ctx.quoted_snippet.snippet->used != 0) {
		str_append_c(snippet, '>');
		snippet_copy(str_c(ctx.quoted_snippet.snippet), snippet);
	}
	pool_unref(&pool);
	return input->stream_errno == 0 ? 0 : -1;
}
