/* Copyright (c) 2006-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "message-parser.h"
#include "message-decoder.h"
#include "mail-search.h"
#include "mail-storage-private.h"
#include "fts-api-private.h"
#include "fts-storage.h"
#include "fts-plugin.h"

#include <stdlib.h>

#define FTS_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_storage_module)
#define FTS_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_mail_module)

#define FTS_SEARCH_NONBLOCK_COUNT 10
#define FTS_BUILD_NOTIFY_INTERVAL_SECS 10

struct fts_storage_build_context {
	struct mail_search_context *search_ctx;
	struct mail_search_seqset seqset;
	struct mail_search_arg search_arg;
	struct mail *mail;
	struct fts_backend_build_context *build;

	struct timeval search_start_time, last_notify;

	uint32_t uid;
	string_t *headers;

	unsigned int save_part:1;
};

struct fts_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct fts_storage_build_context *build_ctx;
	struct mail *mail;

	uint32_t last_uid;

	unsigned int free_mail:1;
	unsigned int expunges:1;
};

static MODULE_CONTEXT_DEFINE_INIT(fts_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(fts_mail_module, &mail_module_register);

static int fts_mailbox_close(struct mailbox *box)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(box);
	int ret;

	if (fbox->backend_substr != NULL)
		fts_backend_deinit(&fbox->backend_substr);
	if (fbox->backend_fast != NULL)
		fts_backend_deinit(&fbox->backend_fast);

	ret = fbox->module_ctx.super.close(box);
	i_free(fbox);
	return ret;
}

static int fts_build_mail_flush(struct fts_storage_build_context *ctx)
{
	if (str_len(ctx->headers) == 0)
		return 1;

	if (fts_backend_build_more(ctx->build, ctx->uid, str_data(ctx->headers),
				   str_len(ctx->headers), TRUE) < 0)
		return -1;

	str_truncate(ctx->headers, 0);
	return 1;
}

static bool fts_build_update_save_part(struct fts_storage_build_context *ctx,
				       const struct message_block *block)
{
	/* we'll index only text/xxx and message/rfc822 parts for now */
	if ((block->part->flags &
	     (MESSAGE_PART_FLAG_TEXT |
	      MESSAGE_PART_FLAG_MESSAGE_RFC822)) == 0)
		return FALSE;

	ctx->save_part = TRUE;
	return TRUE;
}

static int fts_build_mail_header(struct fts_storage_build_context *ctx,
				 const struct message_block *block)
{
	const struct message_header_line *hdr = block->hdr;

	/* hdr->full_value is always set because we get the block from
	   message_decoder */
	str_append(ctx->headers, hdr->name);
	str_append_n(ctx->headers, hdr->middle, hdr->middle_len);
	str_append_n(ctx->headers, hdr->full_value, hdr->full_value_len);
	if (!hdr->no_newline)
		str_append_c(ctx->headers, '\n');

	if (!ctx->save_part) {
		if (strcasecmp(hdr->name, "Content-Type") == 0) {
			if (!fts_build_update_save_part(ctx, block))
				return 0;
		}
		return 1;
	}

	return fts_build_mail_flush(ctx);
}

static int fts_build_mail(struct fts_storage_build_context *ctx, uint32_t uid)
{
	struct istream *input;
	struct message_parser_ctx *parser;
	struct message_decoder_context *decoder;
	struct message_block raw_block, block;
	struct message_part *prev_part, *skip_part;
	int ret;

	ctx->uid = uid;

	if (mail_get_stream(ctx->mail, NULL, NULL, &input) < 0)
		return -1;

	prev_part = skip_part = NULL;
	parser = message_parser_init(pool_datastack_create(), input,
				     MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE,
				     0);
	decoder = message_decoder_init(TRUE);
	for (;;) {
		ret = message_parser_parse_next_block(parser, &raw_block);
		i_assert(ret != 0);
		if (ret < 0) {
			if (input->stream_errno == 0)
				ret = 0;
			break;
		}
		if (raw_block.part == skip_part)
			continue;

		if (!message_decoder_decode_next_block(decoder, &raw_block,
						       &block))
			continue;

		if (block.part != prev_part &&
		    (block.hdr != NULL || block.size != 0)) {
			str_truncate(ctx->headers, 0);
			ctx->save_part = FALSE;
			prev_part = block.part;
			skip_part = NULL;
		}

		if (block.hdr != NULL) {
			ret = fts_build_mail_header(ctx, &block);
			if (ret < 0)
				break;
			if (ret == 0)
				skip_part = raw_block.part;
		} else if (block.size == 0) {
			/* end of headers */
			if (fts_build_update_save_part(ctx, &block)) {
				ret = fts_build_mail_flush(ctx);
				if (ret < 0)
					break;
			}
		} else {
			if (fts_backend_build_more(ctx->build, ctx->uid,
						   block.data, block.size,
						   FALSE) < 0) {
				ret = -1;
				break;
			}
		}
	}
	(void)message_parser_deinit(&parser);
	message_decoder_deinit(&decoder);
	return ret;
}

static int fts_build_init(struct fts_search_context *fctx)
{
	struct mailbox_transaction_context *t = fctx->t;
	struct fts_backend *backend = fctx->build_backend;
	struct fts_storage_build_context *ctx;
	struct fts_backend_build_context *build;
	struct mail_search_seqset seqset;
	uint32_t last_uid, last_uid_locked;

	if (fts_backend_get_last_uid(backend, &last_uid) < 0)
		return -1;

	memset(&seqset, 0, sizeof(seqset));
	mailbox_get_uids(t->box, last_uid+1, (uint32_t)-1,
			 &seqset.seq1, &seqset.seq2);
	if (seqset.seq1 == 0) {
		/* no new messages */
		return 0;
	}
	fctx->first_nonindexed_seq = seqset.seq1;

	if (fctx->best_arg->type == SEARCH_HEADER) {
		/* we're not updating the index just for header lookups */
		return 0;
	}

	if (fts_backend_build_init(backend, &last_uid_locked, &build) < 0)
		return -1;
	if (last_uid != last_uid_locked) {
		/* changed, need to get again the sequences */
		i_assert(last_uid < last_uid_locked);

		last_uid = last_uid_locked;
		mailbox_get_uids(t->box, last_uid+1, (uint32_t)-1,
				 &seqset.seq1, &seqset.seq2);
		if (seqset.seq1 == 0) {
			/* no new messages */
			(void)fts_backend_build_deinit(&build);
			return 0;
		}
	}

	ctx = i_new(struct fts_storage_build_context, 1);
	ctx->build = build;
	ctx->seqset = seqset;
	ctx->search_arg.type = SEARCH_SEQSET;
	ctx->search_arg.value.seqset = &ctx->seqset;

	ctx->headers = str_new(default_pool, 512);
	ctx->mail = mail_alloc(t, 0, NULL);
	ctx->search_ctx = mailbox_search_init(t, NULL, &ctx->search_arg, NULL);

	fctx->build_ctx = ctx;
	return 0;
}

static int fts_build_deinit(struct fts_storage_build_context **_ctx)
{
	struct fts_storage_build_context *ctx = *_ctx;
	struct mailbox *box = ctx->mail->transaction->box;
	int ret = 0;

	*_ctx = NULL;

	if (mailbox_search_deinit(&ctx->search_ctx) < 0)
		ret = -1;
	mail_free(&ctx->mail);

	if (fts_backend_build_deinit(&ctx->build) < 0)
		ret = -1;

	if (ioloop_time - ctx->search_start_time.tv_sec >=
	    FTS_BUILD_NOTIFY_INTERVAL_SECS) {
		/* we notified at least once */
		box->storage->callbacks->
			notify_ok(box, "Mailbox indexing finished",
				  box->storage->callback_context);
	}

	str_free(&ctx->headers);
	i_free(ctx);
	return ret;
}

static void fts_build_notify(struct fts_storage_build_context *ctx)
{
	struct mailbox *box = ctx->mail->transaction->box;
	const char *text;
	float percentage;
	unsigned int msecs, secs;

	if (ctx->last_notify.tv_sec == 0) {
		/* set the search time in here, in case a plugin
		   already spent some time indexing the mailbox */
		ctx->search_start_time = ioloop_timeval;
	} else if (box->storage->callbacks->notify_ok != NULL) {
		percentage = (ctx->mail->seq - ctx->seqset.seq1) * 100.0 /
			(ctx->seqset.seq2 - ctx->seqset.seq1);
		msecs = (ioloop_timeval.tv_sec -
			 ctx->search_start_time.tv_sec) * 1000 +
			(ioloop_timeval.tv_usec -
			 ctx->search_start_time.tv_usec) / 1000;
		secs = (msecs / (percentage / 100.0) - msecs) / 1000;

		t_push();
		text = t_strdup_printf("Indexed %d%% of the mailbox, "
				       "ETA %d:%02d", (int)percentage,
				       secs/60, secs%60);
		box->storage->callbacks->
			notify_ok(box, text, box->storage->callback_context);
		t_pop();
	}
	ctx->last_notify = ioloop_timeval;
}

static int fts_build_more(struct fts_storage_build_context *ctx)
{
	unsigned int count = 0;
	int ret;

	if (ioloop_time - ctx->last_notify.tv_sec >=
	    FTS_BUILD_NOTIFY_INTERVAL_SECS)
		fts_build_notify(ctx);

	while (mailbox_search_next(ctx->search_ctx, ctx->mail) > 0) {
		t_push();
		ret = fts_build_mail(ctx, ctx->mail->uid);
		t_pop();

		if (ret < 0)
			return -1;

		if (++count == FTS_SEARCH_NONBLOCK_COUNT)
			return 0;
	}

	return 1;
}

static bool fts_try_build_init(struct fts_search_context *fctx)
{
	if (fctx->build_backend == NULL) {
		fctx->build_initialized = TRUE;
		return TRUE;
	}

	if (fts_backend_is_building(fctx->build_backend)) {
		/* this process is already building the indexes */
		return FALSE;
	}
	fctx->build_initialized = TRUE;

	if (fts_build_init(fctx) < 0) {
		fctx->build_backend = NULL;
		return TRUE;
	}

	if (fctx->build_ctx == NULL) {
		/* the index was up to date */
		fts_search_lookup(fctx);
	}
	return TRUE;
}

static struct mail_search_context *
fts_mailbox_search_init(struct mailbox_transaction_context *t,
			const char *charset, struct mail_search_arg *args,
			const enum mail_sort_type *sort_program)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(t->box);
	struct mail_search_context *ctx;
	struct fts_search_context *fctx;

	ctx = fbox->module_ctx.super.
		search_init(t, charset, args, sort_program);

	fctx = i_new(struct fts_search_context, 1);
	fctx->fbox = fbox;
	fctx->t = t;
	fctx->args = args;
	MODULE_CONTEXT_SET(ctx, fts_storage_module, fctx);

	if (fbox->backend_substr == NULL && fbox->backend_fast == NULL)
		return ctx;

	fts_search_analyze(fctx);
	(void)fts_try_build_init(fctx);
	return ctx;
}

static int fts_mailbox_search_next_nonblock(struct mail_search_context *ctx,
					    struct mail *mail, bool *tryagain_r)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	int ret;

	if (!fctx->build_initialized) {
		/* we're still waiting for this process (but another command)
		   to finish building the indexes */
		if (!fts_try_build_init(fctx)) {
			*tryagain_r = TRUE;
			return 0;
		}
	}

	if (fctx->build_ctx != NULL) {
		/* this command is still building the indexes */
		ret = fts_build_more(fctx->build_ctx);
		if (ret == 0) {
			*tryagain_r = TRUE;
			return 0;
		}

		/* finished / error */
		fts_build_deinit(&fctx->build_ctx);
		if (ret > 0)
			fts_search_lookup(fctx);
	}

	/* if we're here, the indexes are either built or they're not used */
	return fbox->module_ctx.super.
		search_next_nonblock(ctx, mail, tryagain_r);
}

static void
fts_mailbox_search_args_definite_set(struct fts_search_context *fctx)
{
	struct mail_search_arg *arg;

	for (arg = fctx->args; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_TEXT:
		case SEARCH_BODY:
		case SEARCH_BODY_FAST:
		case SEARCH_TEXT_FAST:
			arg->result = 1;
			break;
		default:
			break;
		}
	}
}

static int
search_next_update_seq_finish(struct mail_search_context *ctx,
			      struct fts_search_context *fctx)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);

	if (fctx->first_nonindexed_seq == 0) {
		/* everything was indexed. we're done */
		return 0;
	}
	if (ctx->seq < fctx->first_nonindexed_seq) {
		/* scan the non-indexed messages */
		fctx->seqs_set = FALSE;
		ctx->seq = fctx->first_nonindexed_seq - 1;
	}
	return fbox->module_ctx.super.search_next_update_seq(ctx);
}

static int fts_mailbox_search_next_update_seq(struct mail_search_context *ctx)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	struct seq_range *def_range, *maybe_range, *range;
	unsigned int def_count, maybe_count;
	uint32_t wanted_seq;
	bool use_maybe;
	int ret;

	if (!fctx->seqs_set)
		return fbox->module_ctx.super.search_next_update_seq(ctx);

	/* fts_search_lookup() was called successfully */
	do {
		def_range = array_get_modifiable(&fctx->definite_seqs,
						 &def_count);
		maybe_range = array_get_modifiable(&fctx->maybe_seqs,
						   &maybe_count);
		/* if we're ahead of current positions, skip them */
		while (fctx->definite_idx < def_count &&
		       ctx->seq > def_range[fctx->definite_idx].seq2)
			fctx->definite_idx++;
		while (fctx->maybe_idx < maybe_count &&
		       ctx->seq > maybe_range[fctx->maybe_idx].seq2)
			fctx->maybe_idx++;

		/* use whichever is lower of definite/maybe */
		if (fctx->definite_idx == def_count) {
			if (fctx->maybe_idx == maybe_count)
				return search_next_update_seq_finish(ctx, fctx);
			use_maybe = TRUE;
		} else if (fctx->maybe_idx == maybe_count) {
			use_maybe = FALSE;
		} else {
			use_maybe = maybe_range[fctx->maybe_idx].seq1 <
				def_range[fctx->definite_idx].seq2;
		}

		if (use_maybe)
			range = maybe_range + fctx->maybe_idx;
		else
			range = def_range + fctx->definite_idx;

		i_assert(range->seq1 <= range->seq2);
		if (ctx->seq > range->seq1) {
			/* current sequence is already larger than where
			   range begins, so use the current sequence. */
			range->seq1 = ctx->seq+1;
		} else {
			ctx->seq = range->seq1 - 1;
			if (++range->seq1 > range->seq2)
				range->seq2 = 0;
		}

		/* ctx->seq points to previous sequence we want */
		wanted_seq = ctx->seq + 1;
		ret = fbox->module_ctx.super.search_next_update_seq(ctx);
	} while (ret > 0 && wanted_seq != ctx->seq);

	if (!use_maybe) {
		/* we have definite results, update args */
		fts_mailbox_search_args_definite_set(fctx);
	}

	return ret;
}

static int fts_mailbox_search_deinit(struct mail_search_context *ctx)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);

	if (fctx->build_ctx != NULL) {
		/* the search was cancelled */
		fts_build_deinit(&fctx->build_ctx);
	}

	if (array_is_created(&fctx->definite_seqs))
		array_free(&fctx->definite_seqs);
	if (array_is_created(&fctx->maybe_seqs))
		array_free(&fctx->maybe_seqs);
	i_free(fctx);
	return fbox->module_ctx.super.search_deinit(ctx);
}

static void fts_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *fmail = FTS_MAIL_CONTEXT(mail);
	struct fts_mailbox *fbox = FTS_CONTEXT(_mail->box);
	struct fts_transaction_context *ft = FTS_CONTEXT(_mail->transaction);

	ft->expunges = TRUE;
	if (fbox->backend_substr != NULL)
		fts_backend_expunge(fbox->backend_substr, _mail);
	if (fbox->backend_fast != NULL)
		fts_backend_expunge(fbox->backend_fast, _mail);

	fmail->super.expunge(_mail);
}

static struct mail *
fts_mail_alloc(struct mailbox_transaction_context *t,
	       enum mail_fetch_field wanted_fields,
	       struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(t->box);
	union mail_module_context *fmail;
	struct mail *_mail;
	struct mail_private *mail;

	_mail = fbox->module_ctx.super.
		mail_alloc(t, wanted_fields, wanted_headers);
	if (fbox->backend_substr != NULL || fbox->backend_fast != NULL) {
		mail = (struct mail_private *)_mail;

		fmail = p_new(mail->pool, union mail_module_context, 1);
		fmail->super = mail->v;

		mail->v.expunge = fts_mail_expunge;
		MODULE_CONTEXT_SET_SELF(mail, fts_mail_module, fmail);
	}
	return _mail;
}

static void fts_box_backends_init(struct mailbox *box)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(box);
	struct fts_backend *backend;
	const char *const *tmp;

	for (tmp = t_strsplit(fbox->env, ", "); *tmp != NULL; tmp++) {
		backend = fts_backend_init(*tmp, box);
		if (backend == NULL)
			continue;

		if ((backend->flags &
		     FTS_BACKEND_FLAG_SUBSTRING_LOOKUPS) != 0) {
			if (fbox->backend_substr != NULL) {
				i_fatal("fts: duplicate substring backend: %s",
					*tmp);
			}
			fbox->backend_substr = backend;
		} else {
			if (fbox->backend_fast != NULL) {
				i_fatal("fts: duplicate fast backend: %s",
					*tmp);
			}
			fbox->backend_fast = backend;
		}
	}
}

static struct mailbox_transaction_context *
fts_transaction_begin(struct mailbox *box,
		      enum mailbox_transaction_flags flags)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct fts_transaction_context *ft;

	ft = i_new(struct fts_transaction_context, 1);

	/* the backend creation is delayed until the first transaction is
	   started. at that point the mailbox has been synced at least once. */
	if (!fbox->backend_set) {
		fts_box_backends_init(box);
		fbox->backend_set = TRUE;
	}

	t = fbox->module_ctx.super.transaction_begin(box, flags);
	MODULE_CONTEXT_SET(t, fts_storage_module, ft);
	return t;
}

static void
fts_storage_build_context_deinit(struct fts_storage_build_context *build_ctx)
{
	(void)fts_backend_build_deinit(&build_ctx->build);
	str_free(&build_ctx->headers);
	i_free(build_ctx);
}

static void
fts_transaction_finish(struct mailbox *box, struct fts_transaction_context *ft,
		       bool committed)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(box);

	if (ft->expunges) {
		if (fbox->backend_fast != NULL) {
			fts_backend_expunge_finish(fbox->backend_fast,
						   box, committed);
		}
	}
	i_free(ft);
}

static void fts_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct mailbox *box = t->box;
	struct fts_mailbox *fbox = FTS_CONTEXT(box);
	struct fts_transaction_context *ft = FTS_CONTEXT(t);

	if (ft->build_ctx != NULL) {
		fts_storage_build_context_deinit(ft->build_ctx);
		ft->build_ctx = NULL;
	}
	if (ft->free_mail)
		mail_free(&ft->mail);

	fbox->module_ctx.super.transaction_rollback(t);
	fts_transaction_finish(box, ft, FALSE);
}

static int fts_transaction_commit(struct mailbox_transaction_context *t,
				  uint32_t *uid_validity_r,
				  uint32_t *first_saved_uid_r,
				  uint32_t *last_saved_uid_r)
{
	struct mailbox *box = t->box;
	struct fts_mailbox *fbox = FTS_CONTEXT(box);
	struct fts_transaction_context *ft = FTS_CONTEXT(t);
	int ret;

	if (ft->build_ctx != NULL) {
		fts_storage_build_context_deinit(ft->build_ctx);
		ft->build_ctx = NULL;
	}
	if (ft->free_mail)
		mail_free(&ft->mail);

	ret = fbox->module_ctx.super.transaction_commit(t,
							uid_validity_r,
							first_saved_uid_r,
							last_saved_uid_r);
	fts_transaction_finish(box, ft, ret == 0);
	return ret;
}

void fts_mailbox_opened(struct mailbox *box)
{
	struct fts_mailbox *fbox;
	const char *env;

	if (fts_next_hook_mailbox_opened != NULL)
		fts_next_hook_mailbox_opened(box);

	env = getenv("FTS");
	if (env == NULL)
		return;

	fbox = i_new(struct fts_mailbox, 1);
	fbox->env = env;
	fbox->module_ctx.super = box->v;
	box->v.close = fts_mailbox_close;
	box->v.search_init = fts_mailbox_search_init;
	box->v.search_next_nonblock = fts_mailbox_search_next_nonblock;
	box->v.search_next_update_seq = fts_mailbox_search_next_update_seq;
	box->v.search_deinit = fts_mailbox_search_deinit;
	box->v.mail_alloc = fts_mail_alloc;
	box->v.transaction_begin = fts_transaction_begin;
	box->v.transaction_rollback = fts_transaction_rollback;
	box->v.transaction_commit = fts_transaction_commit;

	MODULE_CONTEXT_SET(box, fts_storage_module, fbox);
}
