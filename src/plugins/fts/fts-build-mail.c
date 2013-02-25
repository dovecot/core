/* Copyright (c) 2006-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "buffer.h"
#include "str.h"
#include "rfc822-parser.h"
#include "message-address.h"
#include "message-parser.h"
#include "message-decoder.h"
#include "mail-storage.h"
#include "fts-parser.h"
#include "fts-api-private.h"
#include "fts-build-mail.h"

/* there are other characters as well, but this doesn't have to be exact */
#define IS_WORD_WHITESPACE(c) \
	((c) == ' ' || (c) == '\t' || (c) == '\n')
/* if we see a word larger than this, just go ahead and split it from
   wherever */
#define MAX_WORD_SIZE 1024

struct fts_mail_build_context {
	struct mail *mail;
	struct fts_backend_update_context *update_ctx;

	char *content_type, *content_disposition;
	struct fts_parser *body_parser;

	buffer_t *word_buf;
};

static void fts_build_parse_content_type(struct fts_mail_build_context *ctx,
					 const struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *content_type;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	rfc822_skip_lwsp(&parser);

	T_BEGIN {
		content_type = t_str_new(64);
		if (rfc822_parse_content_type(&parser, content_type) >= 0) {
			i_free(ctx->content_type);
			ctx->content_type =
				str_lcase(i_strdup(str_c(content_type)));
		}
	} T_END;
}

static void
fts_build_parse_content_disposition(struct fts_mail_build_context *ctx,
				    const struct message_header_line *hdr)
{
	/* just pass it as-is to backend. */
	i_free(ctx->content_disposition);
	ctx->content_disposition =
		i_strndup(hdr->full_value, hdr->full_value_len);
}

static void fts_parse_mail_header(struct fts_mail_build_context *ctx,
				  const struct message_block *raw_block)
{
	const struct message_header_line *hdr = raw_block->hdr;

	if (strcasecmp(hdr->name, "Content-Type") == 0)
		fts_build_parse_content_type(ctx, hdr);
	else if (strcasecmp(hdr->name, "Content-Disposition") == 0)
		fts_build_parse_content_disposition(ctx, hdr);
}

static void
fts_build_unstructured_header(struct fts_mail_build_context *ctx,
			      const struct message_header_line *hdr)
{
	const unsigned char *data = hdr->full_value;
	unsigned char *buf = NULL;
	unsigned int i;

	/* @UNSAFE: if there are any NULs, replace them with spaces */
	for (i = 0; i < hdr->full_value_len; i++) {
		if (data[i] == '\0') {
			if (buf == NULL) {
				buf = i_malloc(hdr->full_value_len);
				memcpy(buf, data, i);
				data = buf;
			}
			buf[i] = ' ';
		} else if (buf != NULL) {
			buf[i] = data[i];
		}
	}
	(void)fts_backend_update_build_more(ctx->update_ctx,
					    data, hdr->full_value_len);
	i_free(buf);
}

static void fts_build_mail_header(struct fts_mail_build_context *ctx,
				  const struct message_block *block)
{
	const struct message_header_line *hdr = block->hdr;
	struct fts_backend_build_key key;

	if (hdr->eoh)
		return;

	/* hdr->full_value is always set because we get the block from
	   message_decoder */
	memset(&key, 0, sizeof(key));
	key.uid = ctx->mail->uid;
	key.type = block->part->physical_pos == 0 ?
		FTS_BACKEND_BUILD_KEY_HDR : FTS_BACKEND_BUILD_KEY_MIME_HDR;
	key.hdr_name = hdr->name;

	if (!fts_backend_update_set_build_key(ctx->update_ctx, &key))
		return;

	if (!message_header_is_address(hdr->name)) {
		/* regular unstructured header */
		fts_build_unstructured_header(ctx, hdr);
	} else T_BEGIN {
		/* message address. normalize it to give better
		   search results. */
		struct message_address *addr;
		string_t *str;

		addr = message_address_parse(pool_datastack_create(),
					     hdr->full_value,
					     hdr->full_value_len,
					     UINT_MAX, TRUE);
		str = t_str_new(hdr->full_value_len);
		message_address_write(str, addr);

		(void)fts_backend_update_build_more(ctx->update_ctx,
						    str_data(str),
						    str_len(str));
	} T_END;
}

static bool
fts_build_body_begin(struct fts_mail_build_context *ctx, bool *binary_body_r)
{
	struct mail_storage *storage;
	const char *content_type;
	struct fts_backend_build_key key;

	i_assert(ctx->body_parser == NULL);

	*binary_body_r = FALSE;
	memset(&key, 0, sizeof(key));
	key.uid = ctx->mail->uid;

	content_type = ctx->content_type != NULL ?
		ctx->content_type : "text/plain";
	if (strncmp(content_type, "multipart/", 10) == 0) {
		/* multiparts are never indexed, only their contents */
		return FALSE;
	}

	
	storage = mailbox_get_storage(ctx->mail->box);
	if (fts_parser_init(mail_storage_get_user(storage),
			    content_type, ctx->content_disposition,
			    &ctx->body_parser)) {
		/* extract text using the the returned parser */
		*binary_body_r = TRUE;
		key.type = FTS_BACKEND_BUILD_KEY_BODY_PART;
	} else if (strncmp(content_type, "text/", 5) == 0 ||
		   strncmp(content_type, "message/", 8) == 0) {
		/* text body parts */
		key.type = FTS_BACKEND_BUILD_KEY_BODY_PART;
		ctx->body_parser = fts_parser_text_init();
	} else {
		/* possibly binary */
		if ((ctx->update_ctx->backend->flags &
		     FTS_BACKEND_FLAG_BINARY_MIME_PARTS) == 0)
			return FALSE;
		*binary_body_r = TRUE;
		key.type = FTS_BACKEND_BUILD_KEY_BODY_PART_BINARY;
	}
	key.body_content_type = content_type;
	key.body_content_disposition = ctx->content_disposition;
	return fts_backend_update_set_build_key(ctx->update_ctx, &key);
}

static int fts_build_body_block(struct fts_mail_build_context *ctx,
				struct message_block *block, bool last)
{
	unsigned int i;

	i_assert(block->hdr == NULL);

	if ((ctx->update_ctx->backend->flags &
	     FTS_BACKEND_FLAG_BUILD_FULL_WORDS) == 0) {
		return fts_backend_update_build_more(ctx->update_ctx,
						     block->data, block->size);
	}
	/* we'll need to send only full words to the backend */

	if (ctx->word_buf != NULL && ctx->word_buf->used > 0) {
		/* continuing previous word */
		for (i = 0; i < block->size; i++) {
			if (IS_WORD_WHITESPACE(block->data[i]))
				break;
		}
		buffer_append(ctx->word_buf, block->data, i);
		block->data += i;
		block->size -= i;
		if (block->size == 0 && ctx->word_buf->used < MAX_WORD_SIZE &&
		    !last) {
			/* word is still not finished */
			return 0;
		}
		/* we have a full word, index it */
		if (fts_backend_update_build_more(ctx->update_ctx,
						  ctx->word_buf->data,
						  ctx->word_buf->used) < 0)
			return -1;
		buffer_set_used_size(ctx->word_buf, 0);
	}

	/* find the boundary for last word */
	if (last)
		i = block->size;
	else {
		for (i = block->size; i > 0; i--) {
			if (IS_WORD_WHITESPACE(block->data[i-1]))
				break;
		}
	}

	if (fts_backend_update_build_more(ctx->update_ctx, block->data, i) < 0)
		return -1;

	if (i < block->size) {
		if (ctx->word_buf == NULL) {
			ctx->word_buf =
				buffer_create_dynamic(default_pool, 128);
		}
		buffer_append(ctx->word_buf, block->data + i, block->size - i);
	}
	return 0;
}

static int fts_body_parser_finish(struct fts_mail_build_context *ctx)
{
	struct message_block block;
	int ret = 0;

	do {
		memset(&block, 0, sizeof(block));
		fts_parser_more(ctx->body_parser, &block);
		if (fts_build_body_block(ctx, &block, FALSE) < 0) {
			ret = -1;
			break;
		}
	} while (block.size > 0);

	fts_parser_deinit(&ctx->body_parser);
	return ret;
}

static int
fts_build_mail_real(struct fts_backend_update_context *update_ctx,
		    struct mail *mail)
{
	struct fts_mail_build_context ctx;
	struct istream *input;
	struct message_parser_ctx *parser;
	struct message_decoder_context *decoder;
	struct message_block raw_block, block;
	struct message_part *prev_part, *parts;
	bool skip_body = FALSE, body_part = FALSE, body_added = FALSE;
	bool binary_body;
	int ret;

	if (mail_get_stream(mail, NULL, NULL, &input) < 0)
		return mail->expunged ? 0 : -1;

	memset(&ctx, 0, sizeof(ctx));
	ctx.update_ctx = update_ctx;
	ctx.mail = mail;

	prev_part = NULL;
	parser = message_parser_init(pool_datastack_create(), input,
				     MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE,
				     0);

	decoder = message_decoder_init(update_ctx->normalizer, 0);
	for (;;) {
		ret = message_parser_parse_next_block(parser, &raw_block);
		i_assert(ret != 0);
		if (ret < 0) {
			if (input->stream_errno == 0)
				ret = 0;
			break;
		}

		if (raw_block.part != prev_part) {
			/* body part changed. we're now parsing the end of
			   boundary, possibly followed by message epilogue */
			if (ctx.body_parser != NULL) {
				if (fts_body_parser_finish(&ctx) < 0) {
					ret = -1;
					break;
				}
			}
			message_decoder_set_return_binary(decoder, FALSE);
			fts_backend_update_unset_build_key(update_ctx);
			prev_part = raw_block.part;
			i_free_and_null(ctx.content_type);
			i_free_and_null(ctx.content_disposition);

			if (raw_block.size != 0) {
				/* multipart. skip until beginning of next
				   part's headers */
				skip_body = TRUE;
			}
		}

		if (raw_block.hdr != NULL) {
			/* always handle headers */
		} else if (raw_block.size == 0) {
			/* end of headers */
			skip_body = !fts_build_body_begin(&ctx, &binary_body);
			if (binary_body)
				message_decoder_set_return_binary(decoder, TRUE);
			body_part = TRUE;
		} else {
			if (skip_body)
				continue;
		}

		if (!message_decoder_decode_next_block(decoder, &raw_block,
						       &block))
			continue;

		if (block.hdr != NULL) {
			fts_parse_mail_header(&ctx, &raw_block);
			fts_build_mail_header(&ctx, &block);
		} else if (block.size == 0) {
			/* end of headers */
		} else {
			i_assert(body_part);
			if (ctx.body_parser != NULL)
				fts_parser_more(ctx.body_parser, &block);
			if (fts_build_body_block(&ctx, &block, FALSE) < 0) {
				ret = -1;
				break;
			}
			body_added = TRUE;
		}
	}
	if (ret == 0 && ctx.body_parser != NULL)
		ret = fts_body_parser_finish(&ctx);
	if (ret == 0 && body_part && !skip_body && !body_added) {
		/* make sure body is added even when it doesn't exist */
		block.data = NULL; block.size = 0;
		ret = fts_build_body_block(&ctx, &block, TRUE);
	}
	if (message_parser_deinit(&parser, &parts) < 0)
		mail_set_cache_corrupted(mail, MAIL_FETCH_MESSAGE_PARTS);
	message_decoder_deinit(&decoder);
	i_free(ctx.content_type);
	i_free(ctx.content_disposition);
	if (ctx.word_buf != NULL)
		buffer_free(&ctx.word_buf);
	return ret < 0 ? -1 : 1;
}

int fts_build_mail(struct fts_backend_update_context *update_ctx,
		   struct mail *mail)
{
	int ret;

	T_BEGIN {
		ret = fts_build_mail_real(update_ctx, mail);
	} T_END;
	return ret;
}
