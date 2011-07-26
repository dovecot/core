/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "str.h"
#include "time-util.h"
#include "rfc822-parser.h"
#include "message-address.h"
#include "message-parser.h"
#include "message-decoder.h"
#include "../virtual/virtual-storage.h"
#include "fts-api-private.h"
#include "fts-build-private.h"

#define FTS_BUILD_NOTIFY_INTERVAL_SECS 10

static void fts_build_parse_content_type(struct fts_storage_build_context *ctx,
					 const struct message_header_line *hdr)
{
	struct rfc822_parser_context parser;
	string_t *content_type;

	rfc822_parser_init(&parser, hdr->full_value, hdr->full_value_len, NULL);
	(void)rfc822_skip_lwsp(&parser);

	T_BEGIN {
		content_type = t_str_new(64);
		if (rfc822_parse_content_type(&parser, content_type) >= 0) {
			i_free(ctx->content_type);
			ctx->content_type = i_strdup(str_c(content_type));
		}
	} T_END;
}

static void
fts_build_parse_content_disposition(struct fts_storage_build_context *ctx,
				    const struct message_header_line *hdr)
{
	/* just pass it as-is to backend. */
	i_free(ctx->content_disposition);
	ctx->content_disposition =
		i_strndup(hdr->full_value, hdr->full_value_len);
}

static void fts_parse_mail_header(struct fts_storage_build_context *ctx,
				  const struct message_block *raw_block)
{
	const struct message_header_line *hdr = raw_block->hdr;

	if (strcasecmp(hdr->name, "Content-Type") == 0)
		fts_build_parse_content_type(ctx, hdr);
	else if (strcasecmp(hdr->name, "Content-Disposition") == 0)
		fts_build_parse_content_disposition(ctx, hdr);
}

static void fts_build_mail_header(struct fts_storage_build_context *ctx,
				  const struct message_block *block)
{
	const struct message_header_line *hdr = block->hdr;
	struct fts_backend_build_key key;

	if (hdr->eoh)
		return;

	/* hdr->full_value is always set because we get the block from
	   message_decoder */
	memset(&key, 0, sizeof(key));
	key.uid = ctx->uid;
	key.type = block->part->physical_pos == 0 ?
		FTS_BACKEND_BUILD_KEY_HDR : FTS_BACKEND_BUILD_KEY_MIME_HDR;
	key.hdr_name = hdr->name;

	if (!fts_backend_update_set_build_key(ctx->update_ctx, &key))
		return;

	if (!message_header_is_address(hdr->name)) {
		/* regular unstructured header */
		(void)fts_backend_update_build_more(ctx->update_ctx,
						    hdr->full_value,
						    hdr->full_value_len);
	} else T_BEGIN {
		/* message address. normalize it to give better
		   search results. */
		struct message_address *addr;
		string_t *str;

		addr = message_address_parse(pool_datastack_create(),
					     hdr->full_value,
					     hdr->full_value_len,
					     -1U, TRUE);
		str = t_str_new(hdr->full_value_len);
		message_address_write(str, addr);

		(void)fts_backend_update_build_more(ctx->update_ctx,
						    str_data(str),
						    str_len(str));
	} T_END;
}

static bool fts_build_body_begin(struct fts_storage_build_context *ctx)
{
	const char *content_type;
	struct fts_backend_build_key key;

	memset(&key, 0, sizeof(key));
	key.uid = ctx->uid;

	content_type = ctx->content_type != NULL ?
		ctx->content_type : "text/plain";
	if (strncmp(content_type, "text/", 5) == 0 ||
	    strncmp(content_type, "message/", 8) == 0) {
		/* text body parts */
		key.type = FTS_BACKEND_BUILD_KEY_BODY_PART;
	} else {
		/* possibly binary */
		if (!ctx->binary_mime_parts)
			return FALSE;
		key.type = FTS_BACKEND_BUILD_KEY_BODY_PART_BINARY;
	}
	key.body_content_type = content_type;
	key.body_content_disposition = ctx->content_disposition;
	return fts_backend_update_set_build_key(ctx->update_ctx, &key);
}

int fts_build_mail(struct fts_storage_build_context *ctx, struct mail *mail)
{
	enum message_decoder_flags decoder_flags = 0;
	struct istream *input;
	struct message_parser_ctx *parser;
	struct message_decoder_context *decoder;
	struct message_block raw_block, block;
	struct message_part *prev_part, *parts;
	bool skip_body = FALSE, body_part = FALSE, body_added = FALSE;
	int ret;

	ctx->uid = mail->uid;

	if (mail_get_stream(mail, NULL, NULL, &input) < 0)
		return -1;

	prev_part = NULL;
	parser = message_parser_init(pool_datastack_create(), input,
				     MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE,
				     0);

	if (ctx->dtcase)
		decoder_flags |= MESSAGE_DECODER_FLAG_DTCASE;
	if (ctx->binary_mime_parts)
		decoder_flags |= MESSAGE_DECODER_FLAG_RETURN_BINARY;
	decoder = message_decoder_init(decoder_flags);
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
			fts_backend_update_unset_build_key(ctx->update_ctx);
			prev_part = raw_block.part;
			i_free_and_null(ctx->content_type);
			i_free_and_null(ctx->content_disposition);

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
			skip_body = !fts_build_body_begin(ctx);
			body_part = TRUE;
		} else {
			if (skip_body)
				continue;
		}

		if (!message_decoder_decode_next_block(decoder, &raw_block,
						       &block))
			continue;

		if (block.hdr != NULL) {
			fts_parse_mail_header(ctx, &raw_block);
			fts_build_mail_header(ctx, &block);
		} else if (block.size == 0) {
			/* end of headers */
		} else {
			i_assert(body_part);
			if (fts_backend_update_build_more(ctx->update_ctx,
							  block.data,
							  block.size) < 0) {
				ret = -1;
				break;
			}
			body_added = TRUE;
		}
	}
	if (ret == 0 && body_part && !skip_body && !body_added) {
		/* make sure body is added even when it doesn't exist */
		ret = fts_backend_update_build_more(ctx->update_ctx, NULL, 0);
	}
	if (message_parser_deinit(&parser, &parts) < 0)
		mail_set_cache_corrupted(mail, MAIL_FETCH_MESSAGE_PARTS);
	message_decoder_deinit(&decoder);
	return ret;
}

static void fts_build_notify(struct fts_storage_build_context *ctx)
{
	double completed_frac;
	unsigned int eta_secs;

	if (ioloop_time - ctx->last_notify.tv_sec < FTS_BUILD_NOTIFY_INTERVAL_SECS)
		return;
	ctx->last_notify = ioloop_timeval;

	if (ctx->box->storage->callbacks.notify_ok == NULL ||
	    ctx->mail_idx == 0)
		return;

	/* mail_count is counted before indexing actually begins.
	   by the time the mailbox is actually indexed it may already
	   have more (or less) mails. so mail_idx can be higher than
	   mail_count. */
	completed_frac = ctx->mail_idx >= ctx->mail_count ? 1 :
		(double)ctx->mail_idx / ctx->mail_count;

	if (completed_frac >= 0.000001) {
		unsigned int elapsed_msecs, est_total_msecs;

		elapsed_msecs = timeval_diff_msecs(&ioloop_timeval,
						   &ctx->search_start_time);
		est_total_msecs = elapsed_msecs / completed_frac;
		eta_secs = (est_total_msecs - elapsed_msecs) / 1000;
	} else {
		eta_secs = 0;
	}

	T_BEGIN {
		const char *text;

		text = t_strdup_printf("Indexed %d%% of the mailbox, "
				       "ETA %d:%02d", (int)(completed_frac * 100.0),
				       eta_secs/60, eta_secs%60);
		ctx->box->storage->callbacks.
			notify_ok(ctx->box, text,
				  ctx->box->storage->callback_context);
		ctx->notified = TRUE;
	} T_END;
}

int fts_build_init(struct fts_backend *backend, struct mailbox *box,
		   bool precache,
		   struct fts_storage_build_context **build_ctx_r)
{
	const struct fts_storage_build_vfuncs *v;
	int ret;

	*build_ctx_r = NULL;

	/* unless we're precaching (i.e. indexer service, doveadm index)
	   use the indexer service */
	if (!precache)
		v = &fts_storage_build_indexer_vfuncs;
	else if (strcmp(box->storage->name, VIRTUAL_STORAGE_NAME) == 0)
		v = &fts_storage_build_virtual_vfuncs;
	else
		v = &fts_storage_build_mailbox_vfuncs;

	if ((ret = v->init(backend, box, build_ctx_r)) <= 0)
		return ret;

	(*build_ctx_r)->box = box;
	(*build_ctx_r)->v = *v;
	(*build_ctx_r)->dtcase =
		(backend->flags & FTS_BACKEND_FLAG_BUILD_DTCASE) != 0;
	(*build_ctx_r)->binary_mime_parts =
		(backend->flags & FTS_BACKEND_FLAG_BINARY_MIME_PARTS) != 0;
	return 1;
}

int fts_build_deinit(struct fts_storage_build_context **_ctx)
{
	struct fts_storage_build_context *ctx = *_ctx;
	int ret = ctx->failed ? -1 : 0;

	*_ctx = NULL;

	if (ctx->v.deinit(ctx) < 0)
		ret = -1;
	if (ctx->update_ctx != NULL) {
		if (fts_backend_update_deinit(&ctx->update_ctx) < 0)
			ret = -1;
	}
	if (ctx->notified) {
		/* we notified at least once */
		ctx->box->storage->callbacks.
			notify_ok(ctx->box, "Mailbox indexing finished",
				  ctx->box->storage->callback_context);
	}
	i_free(ctx->content_type);
	i_free(ctx->content_disposition);
	i_free(ctx);
	return ret;
}

int fts_build_more(struct fts_storage_build_context *ctx)
{
	int ret;

	if ((ret = ctx->v.more(ctx)) < 0) {
		ctx->failed = TRUE;
		return -1;
	}

	fts_build_notify(ctx);
	return ret;
}
