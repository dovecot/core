/* Copyright (C) 2006 Timo Sirainen */

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
#include "fts-plugin.h"

#include <stdlib.h>

#define FTS_CONTEXT(obj) \
	*((void **)array_idx_modifiable(&(obj)->module_contexts, \
					fts_storage_module_id))

#define FTS_SEARCH_NONBLOCK_COUNT 10
#define FTS_BUILD_NOTIFY_INTERVAL_SECS 10

struct fts_mailbox {
	struct mailbox_vfuncs super;
	struct fts_backend *backend_exact;
	struct fts_backend *backend_fast;

	const char *env;
	unsigned int backend_set:1;
};

struct fts_search_context {
	ARRAY_TYPE(seq_range) result;
	unsigned int result_pos;

	struct mail_search_arg *args, *best_arg;
	struct fts_backend *backend;
	struct fts_storage_build_context *build_ctx;
	struct mailbox_transaction_context *t;

	unsigned int build_initialized:1;
	unsigned int locked:1;
};

struct fts_storage_build_context {
	struct mail_search_context *search_ctx;
	struct mail_search_seqset seqset;
	struct mail_search_arg search_arg;
	struct mail *mail;
	struct fts_backend_build_context *build;

	struct timeval search_start_time, last_notify;

	uint32_t uid;
	string_t *headers;
	bool save_part;
};

struct fts_transaction_context {
	bool expunges;
};

struct fts_mail {
	struct mail_vfuncs super;
};

static unsigned int fts_storage_module_id = 0;
static bool fts_storage_module_id_set = FALSE;

static int fts_mailbox_close(struct mailbox *box)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(box);
	int ret;

	if (fbox->backend_exact != NULL)
		fts_backend_deinit(fbox->backend_exact);
	if (fbox->backend_fast != NULL)
		fts_backend_deinit(fbox->backend_fast);

	ret = fbox->super.close(box);
	i_free(fbox);
	return ret;
}

static int uid_range_to_seq(struct mailbox *box,
			    ARRAY_TYPE(seq_range) *uid_range,
			    ARRAY_TYPE(seq_range) *seq_range)
{
	const struct seq_range *range;
	struct seq_range new_range;
	unsigned int i, count;

	range = array_get(uid_range, &count);
	i_array_init(seq_range, count);
	for (i = 0; i < count; i++) {
		if (mailbox_get_uids(box, range[i].seq1, range[i].seq2,
				     &new_range.seq1, &new_range.seq2) < 0) {
			array_free(seq_range);
			return -1;
		}

		if (new_range.seq1 != 0)
			array_append(seq_range, &new_range, 1);
	}
	return 0;
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

static int fts_build_mail(struct fts_storage_build_context *ctx)
{
	struct istream *input;
	struct message_parser_ctx *parser;
	struct message_decoder_context *decoder;
	struct message_block raw_block, block;
	struct message_part *prev_part, *skip_part;
	int ret;

	ctx->uid = ctx->mail->uid;

	input = mail_get_stream(ctx->mail, NULL, NULL);
	if (input == NULL)
		return -1;

	prev_part = skip_part = NULL;
	parser = message_parser_init(pool_datastack_create(), input);
	decoder = message_decoder_init();
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
			if (fts_backend_build_more(ctx->build, ctx->mail->uid,
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
	struct fts_backend *backend = fctx->backend;
	struct fts_storage_build_context *ctx;
	struct fts_backend_build_context *build;
	struct mail_search_seqset seqset;
	uint32_t last_uid, last_uid_locked;

	if (fts_backend_get_last_uid(backend, &last_uid) < 0)
		return -1;

	if (last_uid == 0 && fctx->best_arg->type == SEARCH_HEADER) {
		/* index doesn't exist. we're not creating it just for
		   header lookups. */
		return -1;
	}

	memset(&seqset, 0, sizeof(seqset));
	if (mailbox_get_uids(t->box, last_uid+1, (uint32_t)-1,
			     &seqset.seq1, &seqset.seq2) < 0)
		return -1;
	if (seqset.seq1 == 0) {
		/* no new messages */
		return 0;
	}

	build = fts_backend_build_init(backend, &last_uid_locked);
	if (last_uid != last_uid_locked) {
		/* changed, need to get again the sequences */
		i_assert(last_uid < last_uid_locked);

		last_uid = last_uid_locked;
		if (mailbox_get_uids(t->box, last_uid+1, (uint32_t)-1,
				     &seqset.seq1, &seqset.seq2) < 0) {
			(void)fts_backend_build_deinit(build);
			return -1;
		}
		if (seqset.seq1 == 0) {
			/* no new messages */
			(void)fts_backend_build_deinit(build);
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

static int fts_build_deinit(struct fts_storage_build_context *ctx)
{
	struct mailbox *box = ctx->mail->transaction->box;
	int ret = 0;

	if (mailbox_search_deinit(&ctx->search_ctx) < 0)
		ret = -1;
	mail_free(&ctx->mail);

	if (fts_backend_build_deinit(ctx->build) < 0)
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
		ret = fts_build_mail(ctx);
		t_pop();

		if (ret < 0)
			return -1;

		if (++count == FTS_SEARCH_NONBLOCK_COUNT)
			return 0;
	}

	return 1;
}

static void fts_search_filter_args(struct fts_search_context *fctx,
				   struct mail_search_arg *args,
				   ARRAY_TYPE(seq_range) *uid_result)
{
	const char *key;
	enum fts_lookup_flags flags;

	for (; args != NULL; args = args->next) {
		switch (args->type) {
		case SEARCH_BODY_FAST:
		case SEARCH_TEXT_FAST:
			if ((fctx->backend->flags &
			     FTS_BACKEND_FLAG_EXACT_LOOKUPS) == 0)
				break;
			/* fall through */
		case SEARCH_BODY:
		case SEARCH_TEXT:
		case SEARCH_HEADER:
			if (args == fctx->best_arg) {
				/* already handled this one */
				break;
			}

			key = args->value.str;
			if (*key == '\0') {
				i_assert(args->type == SEARCH_HEADER);

				/* we're only checking the existence
				   of the header. */
				key = args->hdr_field_name;
			}

			flags = FTS_LOOKUP_FLAG_BODY;
			if (args->type == SEARCH_TEXT_FAST ||
			    args->type == SEARCH_TEXT)
				flags |= FTS_LOOKUP_FLAG_HEADERS;
			if (fts_backend_filter(fctx->backend, flags, key,
					       uid_result) < 0) {
				/* failed, but we already have limited
				   the search, so just ignore this */
				break;
			}
			if (args->type != SEARCH_HEADER &&
			    (fctx->backend->flags &
			     FTS_BACKEND_FLAG_DEFINITE_LOOKUPS) != 0) {
				args->match_always = TRUE;
				args->result = 1;
			}
			break;
		case SEARCH_OR:
		case SEARCH_SUB:
			fts_search_filter_args(fctx, args->value.subargs,
					       uid_result);
			break;
		default:
			break;
		}
	}
}

static void fts_search_init(struct mailbox *box,
			    struct fts_search_context *fctx)
{
	struct fts_backend *backend = fctx->backend;
	enum fts_lookup_flags flags;
	const char *key;
	ARRAY_TYPE(seq_range) uid_result;

	if (fts_backend_lock(backend) <= 0)
		return;
	fctx->locked = TRUE;

	key = fctx->best_arg->value.str;
	if (*key == '\0') {
		i_assert(fctx->best_arg->type == SEARCH_HEADER);

		/* we're only checking the existence
		   of the header. */
		flags = FTS_LOOKUP_FLAG_HEADERS;
		key = fctx->best_arg->hdr_field_name;
	} else {
		flags = FTS_LOOKUP_FLAG_BODY;
		if (fctx->best_arg->type == SEARCH_TEXT_FAST ||
		    fctx->best_arg->type == SEARCH_TEXT)
			flags |= FTS_LOOKUP_FLAG_HEADERS;
	}

	i_array_init(&uid_result, 64);
	if (fts_backend_lookup(backend, flags, key, &uid_result) < 0) {
		/* failed, fallback to reading everything */
		array_free(&uid_result);
		return;
	}

	if ((backend->flags & FTS_BACKEND_FLAG_DEFINITE_LOOKUPS) != 0) {
		fctx->best_arg->match_always = TRUE;
		fctx->best_arg->result = 1;
	}

	fts_search_filter_args(fctx, fctx->args, &uid_result);

	(void)uid_range_to_seq(box, &uid_result, &fctx->result);
	array_free(&uid_result);
}

static bool arg_is_better(const struct mail_search_arg *new_arg,
			  const struct mail_search_arg *old_arg)
{
	if (old_arg == NULL)
		return TRUE;
	if (new_arg == NULL)
		return FALSE;

	/* prefer not to use headers. they have a larger possibility of
	   having lots of identical strings */
	if (old_arg->type == SEARCH_HEADER)
		return TRUE;
	else if (new_arg->type == SEARCH_HEADER)
		return FALSE;

	return strlen(new_arg->value.str) > strlen(old_arg->value.str);
}

static void fts_search_args_check(struct mail_search_arg *args,
				  bool *have_fast_r, bool *have_exact_r,
				  struct mail_search_arg **best_fast_arg,
				  struct mail_search_arg **best_exact_arg)
{
	for (; args != NULL; args = args->next) {
		switch (args->type) {
		case SEARCH_BODY_FAST:
		case SEARCH_TEXT_FAST:
			if (*args->value.str == '\0') {
				/* this matches everything */
				args->match_always = TRUE;
				args->result = 1;
				break;
			}
			if (arg_is_better(args, *best_fast_arg)) {
				*best_fast_arg = args;
				*have_fast_r = TRUE;
			}
			break;
		case SEARCH_BODY:
		case SEARCH_TEXT:
			if (*args->value.str == '\0') {
				/* this matches everything */
				args->match_always = TRUE;
				args->result = 1;
				break;
			}
		case SEARCH_HEADER:
			if (arg_is_better(args, *best_exact_arg)) {
				*best_exact_arg = args;
				*have_exact_r = TRUE;
			}
			break;
		case SEARCH_OR:
		case SEARCH_SUB:
			fts_search_args_check(args->value.subargs,
					      have_fast_r, have_exact_r,
					      best_fast_arg, best_exact_arg);
			break;
		default:
			break;
		}
	}
}

static bool fts_try_build_init(struct fts_search_context *fctx)
{
	if (fctx->backend == NULL) {
		fctx->build_initialized = TRUE;
		return TRUE;
	}

	if (fts_backend_is_building(fctx->backend))
		return FALSE;
	fctx->build_initialized = TRUE;

	if (fts_build_init(fctx) < 0)
		fctx->backend = NULL;
	else if (fctx->build_ctx == NULL) {
		/* the index was up to date */
		fts_search_init(fctx->t->box, fctx);
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
	struct mail_search_arg *best_fast_arg, *best_exact_arg;
	bool have_fast, have_exact;

	ctx = fbox->super.search_init(t, charset, args, sort_program);

	fctx = i_new(struct fts_search_context, 1);
	fctx->t = t;
	fctx->args = args;
	array_idx_set(&ctx->module_contexts, fts_storage_module_id, &fctx);

	if (fbox->backend_exact == NULL && fbox->backend_fast == NULL)
		return ctx;

	have_fast = have_exact = FALSE;
	best_fast_arg = best_exact_arg = NULL;
	fts_search_args_check(args, &have_fast, &have_exact,
			      &best_fast_arg, &best_exact_arg);
	if (have_fast && fbox->backend_fast != NULL) {
		/* use fast backend whenever possible */
		fctx->backend = fbox->backend_fast;
		fctx->best_arg = best_fast_arg;
	} else if (have_exact || have_fast) {
		fctx->backend = fbox->backend_exact;
		fctx->best_arg = arg_is_better(best_exact_arg, best_fast_arg) ?
			best_exact_arg : best_fast_arg;
	}

	fts_try_build_init(fctx);
	return ctx;
}

static int fts_mailbox_search_next_nonblock(struct mail_search_context *ctx,
					    struct mail *mail, bool *tryagain_r)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	int ret;

	if (!fctx->build_initialized) {
		if (!fts_try_build_init(fctx)) {
			*tryagain_r = TRUE;
			return 0;
		}
	}

	if (fctx->build_ctx != NULL) {
		/* still building the index */
		ret = fts_build_more(fctx->build_ctx);
		if (ret == 0) {
			*tryagain_r = TRUE;
			return 0;
		}

		/* finished / error */
		fts_build_deinit(fctx->build_ctx);
		fctx->build_ctx = NULL;

		if (ret > 0)
			fts_search_init(ctx->transaction->box, fctx);
	}
	return fbox->super.search_next_nonblock(ctx, mail, tryagain_r);

}

static int fts_mailbox_search_next_update_seq(struct mail_search_context *ctx)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	struct seq_range *range;
	unsigned int count;
	uint32_t wanted_seq;
	int ret;

	if (!array_is_created(&fctx->result))
		return fbox->super.search_next_update_seq(ctx);

	do {
		range = array_get_modifiable(&fctx->result, &count);
		while (fctx->result_pos < count &&
		       ctx->seq > range[fctx->result_pos].seq2)
			fctx->result_pos++;

		if (fctx->result_pos == count)
			return 0;

		if (ctx->seq > range[fctx->result_pos].seq1)
			range[fctx->result_pos].seq1 = ctx->seq+1;
		else {
			ctx->seq = range[fctx->result_pos].seq1 - 1;

			if (fctx->result_pos < count &&
			    ctx->seq + 1 == range[fctx->result_pos].seq2)
				fctx->result_pos++;
			else
				range[fctx->result_pos].seq1++;
		}

		wanted_seq = ctx->seq + 1;
		ret = fbox->super.search_next_update_seq(ctx);
	} while (ret > 0 && wanted_seq != ctx->seq);

	return ret;
}

static int fts_mailbox_search_deinit(struct mail_search_context *ctx)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);

	if (fctx->build_ctx != NULL) {
		/* the search was cancelled */
		fts_build_deinit(fctx->build_ctx);
	}

	if (fctx->locked)
		fts_backend_unlock(fctx->backend);

	if (array_is_created(&fctx->result))
		array_free(&fctx->result);
	i_free(fctx);
	return fbox->super.search_deinit(ctx);
}

static int fts_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct fts_mail *fmail = FTS_CONTEXT(mail);
	struct fts_mailbox *fbox = FTS_CONTEXT(_mail->box);
	struct fts_transaction_context *ft = FTS_CONTEXT(_mail->transaction);

	if (fmail->super.expunge(_mail) < 0)
		return -1;

	ft->expunges = TRUE;
	if (fbox->backend_exact != NULL)
		fts_backend_expunge(fbox->backend_exact, _mail);
	if (fbox->backend_fast != NULL)
		fts_backend_expunge(fbox->backend_fast, _mail);
	return 0;
}

static struct mail *
fts_mail_alloc(struct mailbox_transaction_context *t,
	       enum mail_fetch_field wanted_fields,
	       struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(t->box);
	struct fts_mail *fmail;
	struct mail *_mail;
	struct mail_private *mail;

	_mail = fbox->super.mail_alloc(t, wanted_fields, wanted_headers);
	if (fbox->backend_exact != NULL || fbox->backend_fast != NULL) {
		mail = (struct mail_private *)_mail;

		fmail = p_new(mail->pool, struct fts_mail, 1);
		fmail->super = mail->v;

		mail->v.expunge = fts_mail_expunge;
		array_idx_set(&mail->module_contexts,
			      fts_storage_module_id, &fmail);
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
		     FTS_BACKEND_FLAG_EXACT_LOOKUPS) != 0) {
			if (fbox->backend_exact != NULL) {
				i_fatal("fts: duplicate exact backend: %s",
					*tmp);
			}
			fbox->backend_exact = backend;
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

	t = fbox->super.transaction_begin(box, flags);
	array_idx_set(&t->module_contexts, fts_storage_module_id, &ft);
	return t;
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

	fbox->super.transaction_rollback(t);
	fts_transaction_finish(box, ft, FALSE);
}

static int fts_transaction_commit(struct mailbox_transaction_context *t,
				  enum mailbox_sync_flags flags)
{
	struct mailbox *box = t->box;
	struct fts_mailbox *fbox = FTS_CONTEXT(box);
	struct fts_transaction_context *ft = FTS_CONTEXT(t);
	int ret;

	ret = fbox->super.transaction_commit(t, flags);
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
	fbox->super = box->v;
	box->v.close = fts_mailbox_close;
	box->v.search_init = fts_mailbox_search_init;
	box->v.search_next_nonblock = fts_mailbox_search_next_nonblock;
	box->v.search_next_update_seq = fts_mailbox_search_next_update_seq;
	box->v.search_deinit = fts_mailbox_search_deinit;
	box->v.mail_alloc = fts_mail_alloc;
	box->v.transaction_begin = fts_transaction_begin;
	box->v.transaction_rollback = fts_transaction_rollback;
	box->v.transaction_commit = fts_transaction_commit;

	if (!fts_storage_module_id_set) {
		fts_storage_module_id = mail_storage_module_id++;
		fts_storage_module_id_set = TRUE;
	}

	array_idx_set(&box->module_contexts, fts_storage_module_id, &fbox);
}
