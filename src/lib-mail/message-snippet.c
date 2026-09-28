/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
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
	/* NULL until the first character is added */
	string_t *snippet;
	unsigned int chars_left;
};

/* Snippet generated for a single MIME part */
struct snippet_part {
	const struct message_part *part;
	struct snippet_data snippet;
	struct snippet_data quoted_snippet;
};

struct snippet_context {
	pool_t pool;
	unsigned int max_snippet_chars;
	struct message_decoder_context *decoder;
	/* Snippets of the text parts, in the order they were seen */
	ARRAY(struct snippet_part *) parts;

	/* State of the MIME part that is currently being processed.
	   cur=NULL if the part is not a text part. */
	struct snippet_part *cur;
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
		if (target->snippet != NULL)
			ctx->add_whitespace = TRUE;
		if (data[0] == '\n')
			ctx->state = SNIPPET_STATE_NEWLINE;
		return;
	}
	if (target->chars_left == 0)
		return;
	target->chars_left--;
	if (target->snippet == NULL) {
		target->snippet =
			str_new(ctx->pool, ctx->max_snippet_chars);
	}
	if (ctx->add_whitespace) {
		if (target->chars_left == 0) {
			/* don't add a trailing whitespace */
			return;
		}
		str_append_c(target->snippet, ' ');
		ctx->add_whitespace = FALSE;
		target->chars_left--;
	}
	*count_r = uni_utf8_char_bytes(data[0]);
	i_assert(*count_r <= size);
	str_append_data(target->snippet, data, *count_r);
}

static bool snippet_generate(struct snippet_context *ctx,
			     const unsigned char *data, size_t size)
{
	struct snippet_part *cur = ctx->cur;
	size_t i, count;
	struct snippet_data *target;

	if (ctx->html2text != NULL) {
		buffer_set_used_size(ctx->plain_output, 0);
		mail_html2text_more(ctx->html2text, data, size,
				    ctx->plain_output);
		data = ctx->plain_output->data;
		size = ctx->plain_output->used;
	}

	if (ctx->state == SNIPPET_STATE_QUOTED)
		target = &cur->quoted_snippet;
	else
		target = &cur->snippet;

	/* message-decoder should feed us only valid and complete
	   UTF-8 input */

	for (i = 0; i < size; i += count) {
		count = 1;
		switch (ctx->state) {
		case SNIPPET_STATE_NEWLINE:
			if (data[i] == '>') {
				ctx->state = SNIPPET_STATE_QUOTED;
				i++;
				target = &cur->quoted_snippet;
			} else {
				ctx->state = SNIPPET_STATE_NORMAL;
				target = &cur->snippet;
			}
			/* fallthrough */
		case SNIPPET_STATE_NORMAL:
		case SNIPPET_STATE_QUOTED:
			snippet_add_content(ctx, target, CONST_PTR_OFFSET(data, i),
					    size-i, &count);
			/* break here if we have enough non-quoted data,
			   quoted data does not need to break here as it's
			   only used if the actual snippet is left empty. */
			if (cur->snippet.chars_left == 0)
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

static bool snippet_part_has_text(const struct snippet_part *spart)
{
	return spart->snippet.snippet != NULL ||
		spart->quoted_snippet.snippet != NULL;
}

static void
snippet_part_append(const struct snippet_part *spart, string_t *snippet)
{
	if (spart->snippet.snippet != NULL)
		snippet_copy(str_c(spart->snippet.snippet), snippet);
	else if (spart->quoted_snippet.snippet != NULL) {
		str_append_c(snippet, '>');
		snippet_copy(str_c(spart->quoted_snippet.snippet), snippet);
	}
}

static bool snippet_header_is_needed(const struct message_header_line *hdr)
{
	/* Only the headers used by message-decoder are needed */
	return (hdr->name_len == 12 &&
		strcasecmp(hdr->name, "Content-Type") == 0) ||
		(hdr->name_len == 25 &&
		 strcasecmp(hdr->name, "Content-Transfer-Encoding") == 0);
}

static void
snippet_part_start(struct snippet_context *ctx,
		   const struct message_part *part)
{
	struct snippet_part *spart;
	const char *ct;

	ctx->cur = NULL;
	mail_html2text_deinit(&ctx->html2text);

	if ((part->flags & (MESSAGE_PART_FLAG_MULTIPART |
			    MESSAGE_PART_FLAG_MESSAGE_RFC822)) != 0) {
		/* The body consists of child parts, which are handled
		   separately. */
		return;
	}

	/* verify that we can use this Content-Type */
	ct = message_decoder_current_content_type(ctx->decoder);
	if (ct == NULL)
		/* text/plain */ ;
	else if (mail_html2text_content_type_match(ct)) {
		ctx->html2text = mail_html2text_init(0);
		if (ctx->plain_output == NULL) {
			ctx->plain_output =
				buffer_create_dynamic(ctx->pool, 1024);
		}
	} else if (!str_begins_icase_with(ct, "text/"))
		return;

	spart = p_new(ctx->pool, struct snippet_part, 1);
	spart->part = part;
	spart->snippet.chars_left = ctx->max_snippet_chars;
	/* -1 for '>' */
	spart->quoted_snippet.chars_left = ctx->max_snippet_chars - 1;
	array_push_back(&ctx->parts, &spart);

	ctx->cur = spart;
	ctx->state = SNIPPET_STATE_NEWLINE;
	ctx->add_whitespace = FALSE;
}

static bool snippet_have_text(struct snippet_context *ctx)
{
	struct snippet_part *spart;

	array_foreach_elem(&ctx->parts, spart) {
		if (snippet_part_has_text(spart))
			return TRUE;
	}
	return FALSE;
}

int message_snippet_generate(struct istream *input,
			     unsigned int max_snippet_chars,
			     string_t *snippet)
{
	const struct message_parser_settings parser_set = { .flags = 0 };
	struct message_parser_ctx *parser;
	struct message_part *parts;
	struct message_block raw_block, block;
	struct snippet_context ctx;
	struct snippet_part *spart;
	pool_t pool;
	int ret;

	i_assert(max_snippet_chars > 0);

	i_zero(&ctx);
	pool = pool_alloconly_create("message snippet", 2048);
	ctx.pool = pool;
	ctx.max_snippet_chars = max_snippet_chars;
	ctx.decoder = message_decoder_init(NULL, 0);
	p_array_init(&ctx.parts, pool, 4);

	parser = message_parser_init(pool_datastack_create(), input, &parser_set);
	while ((ret = message_parser_parse_next_block(parser, &raw_block)) > 0) {
		if (raw_block.hdr != NULL) {
			if (snippet_header_is_needed(raw_block.hdr)) {
				(void)message_decoder_decode_next_block(
					ctx.decoder, &raw_block, &block);
			}
			continue;
		}
		if (raw_block.size == 0) {
			/* We already have a snippet, don't look for more in
			   subsequent parts. */
			if (snippet_have_text(&ctx))
				break;

			/* end of headers */
			(void)message_decoder_decode_next_block(
				ctx.decoder, &raw_block, &block);
			snippet_part_start(&ctx, raw_block.part);
			continue;
		}
		if (ctx.cur == NULL || ctx.cur->part != raw_block.part) {
			/* not a text part, or the part's end of headers was
			   never seen (e.g. truncated header) */
			continue;
		}
		if (!message_decoder_decode_next_block(ctx.decoder, &raw_block,
						       &block))
			continue;
		if (block.size > 0 &&
		    !snippet_generate(&ctx, block.data, block.size))
			break;
	}
	i_assert(ret != 0);
	message_decoder_deinit(&ctx.decoder);
	message_parser_deinit(&parser, &parts);
	mail_html2text_deinit(&ctx.html2text);

	/* use the first part that has a snippet */
	array_foreach_elem(&ctx.parts, spart) {
		if (snippet_part_has_text(spart)) {
			snippet_part_append(spart, snippet);
			break;
		}
	}
	pool_unref(&pool);
	return input->stream_errno == 0 ? 0 : -1;
}
