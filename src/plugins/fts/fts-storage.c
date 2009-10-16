/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "time-util.h"
#include "message-parser.h"
#include "message-decoder.h"
#include "mail-namespace.h"
#include "mail-search-build.h"
#include "mail-storage-private.h"
#include "fts-api-private.h"
#include "fts-storage.h"
#include "fts-plugin.h"

#include <stdlib.h>

#define FTS_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_storage_module)
#define FTS_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, fts_mail_module)

#define FTS_SEARCH_NONBLOCK_COUNT 50
#define FTS_BUILD_NOTIFY_INTERVAL_SECS 10

struct fts_mail {
	union mail_module_context module_ctx;
	char score[30];
};

struct fts_storage_build_context {
	struct mail_search_context *search_ctx;
	struct mail_search_args *search_args;
	struct mail *mail;
	struct fts_backend_build_context *build;

	struct timeval search_start_time, last_notify;

	uint32_t uid;
	string_t *headers;
};

struct fts_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct fts_storage_build_context *build_ctx;
	ARRAY_TYPE(fts_score_map) *score_map;
	struct mail *mail;

	uint32_t last_uid;

	unsigned int free_mail:1;
	unsigned int expunges:1;
};

static MODULE_CONTEXT_DEFINE_INIT(fts_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(fts_mail_module, &mail_module_register);

static void fts_mailbox_close(struct mailbox *box)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(box);

	if (fbox->backend_substr != NULL)
		fts_backend_deinit(&fbox->backend_substr);
	if (fbox->backend_fast != NULL)
		fts_backend_deinit(&fbox->backend_fast);

	fbox->module_ctx.super.close(box);
	i_free(fbox);
}

static int fts_build_mail_flush_headers(struct fts_storage_build_context *ctx)
{
	if (str_len(ctx->headers) == 0)
		return 0;

	if (fts_backend_build_more(ctx->build, ctx->uid, str_data(ctx->headers),
				   str_len(ctx->headers), TRUE) < 0)
		return -1;

	str_truncate(ctx->headers, 0);
	return 0;
}

static bool fts_build_want_index_part(const struct message_block *block)
{
	/* we'll index only text/xxx and message/rfc822 parts for now */
	return (block->part->flags &
		(MESSAGE_PART_FLAG_TEXT |
		 MESSAGE_PART_FLAG_MESSAGE_RFC822)) != 0;
}

static void fts_build_mail_header(struct fts_storage_build_context *ctx,
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
}

static int fts_build_mail(struct fts_storage_build_context *ctx, uint32_t uid)
{
	struct istream *input;
	struct message_parser_ctx *parser;
	struct message_decoder_context *decoder;
	struct message_block raw_block, block;
	struct message_part *prev_part, *parts;
	int ret;

	ctx->uid = uid;

	if (mail_get_stream(ctx->mail, NULL, NULL, &input) < 0)
		return -1;

	prev_part = NULL;
	parser = message_parser_init(pool_datastack_create(), input,
				     MESSAGE_HEADER_PARSER_FLAG_CLEAN_ONELINE,
				     0);
	decoder = message_decoder_init(MESSAGE_DECODER_FLAG_DTCASE);
	for (;;) {
		ret = message_parser_parse_next_block(parser, &raw_block);
		i_assert(ret != 0);
		if (ret < 0) {
			if (input->stream_errno == 0)
				ret = 0;
			break;
		}
		if (raw_block.hdr == NULL && raw_block.size != 0 &&
		    !fts_build_want_index_part(&raw_block)) {
			/* skipping this body */
			continue;
		}

		if (!message_decoder_decode_next_block(decoder, &raw_block,
						       &block))
			continue;

		if (block.hdr != NULL)
			fts_build_mail_header(ctx, &block);
		else if (block.size == 0) {
			/* end of headers */
			str_append_c(ctx->headers, '\n');
		} else {
			if (fts_backend_build_more(ctx->build, ctx->uid,
						   block.data, block.size,
						   FALSE) < 0) {
				ret = -1;
				break;
			}
		}
	}
	if (message_parser_deinit(&parser, &parts) < 0)
		mail_set_cache_corrupted(ctx->mail, MAIL_FETCH_MESSAGE_PARTS);
	message_decoder_deinit(&decoder);

	if (ret == 0) {
		/* Index all headers at the end. This is required for Squat,
		   because it can handle only incremental UIDs. */
		ret = fts_build_mail_flush_headers(ctx);
	}
	return ret;
}

static int fts_build_init_seq(struct fts_search_context *fctx,
			      struct fts_backend *backend,
			      struct mailbox_transaction_context *t,
			      uint32_t seq1, uint32_t seq2, uint32_t last_uid)
{
	struct mail_search_args *search_args;
	struct fts_storage_build_context *ctx;
	struct fts_backend_build_context *build;
	uint32_t last_uid_locked;

	if (fctx->best_arg->type == SEARCH_HEADER ||
	    fctx->best_arg->type == SEARCH_HEADER_COMPRESS_LWSP) {
		/* we're not updating the index just for header lookups */
		if (seq1 < fctx->first_nonindexed_seq)
			fctx->first_nonindexed_seq = seq1;
		return 0;
	}

	if (fts_backend_build_init(backend, &last_uid_locked, &build) < 0)
		return -1;
	if (last_uid != last_uid_locked && last_uid_locked != (uint32_t)-1) {
		/* changed, need to get again the sequences */
		last_uid = last_uid_locked;
		mailbox_get_seq_range(t->box, last_uid+1, (uint32_t)-1,
				      &seq1, &seq2);
		if (seq1 == 0) {
			/* no new messages */
			(void)fts_backend_build_deinit(&build);
			return 0;
		}
	}

	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, seq1, seq2);

	ctx = i_new(struct fts_storage_build_context, 1);
	ctx->build = build;
	ctx->headers = str_new(default_pool, 512);
	ctx->mail = mail_alloc(t, 0, NULL);
	ctx->search_ctx = mailbox_search_init(t, search_args, NULL);
	ctx->search_ctx->progress_hidden = TRUE;
	ctx->search_args = search_args;

	fctx->build_ctx = ctx;
	return 1;
}

static struct fts_backend *
fts_mailbox_get_backend(struct fts_search_context *fctx,
			struct mailbox *box)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(box);

	if (fctx->build_backend == fctx->fbox->backend_fast)
		return fbox->backend_fast;
	else {
		i_assert(fctx->build_backend == fctx->fbox->backend_substr);
		return fbox->backend_substr;
	}
}

static int fts_build_init_trans(struct fts_search_context *fctx,
				struct mailbox_transaction_context *t)
{
	struct fts_backend *backend;
	uint32_t last_uid, seq1, seq2;
	int ret;

	backend = fts_mailbox_get_backend(fctx, t->box);
	if (fts_backend_get_last_uid(backend, &last_uid) < 0)
		return -1;

	mailbox_get_seq_range(t->box, last_uid+1, (uint32_t)-1, &seq1, &seq2);
	if (seq1 == 0) {
		/* no new messages */
		return 0;
	}

	ret = fts_build_init_seq(fctx, backend, t, seq1, seq2, last_uid);
	return ret < 0 ? -1 : 0;
}

static int
fts_build_init_box(struct fts_search_context *fctx, struct mailbox *box,
		   uint32_t last_uid)
{
	struct fts_backend *backend;
	uint32_t seq1, seq2;

	mailbox_get_seq_range(box, last_uid + 1, (uint32_t)-1, &seq1, &seq2);
	if (seq1 == 0)
		return 0;

	backend = fts_mailbox_get_backend(fctx, box);
	fctx->virtual_ctx.trans = mailbox_transaction_begin(box, 0);
	return fts_build_init_seq(fctx, backend, fctx->virtual_ctx.trans,
				  seq1, seq2, last_uid);
}

static int mailbox_name_cmp(const struct fts_orig_mailboxes *box1,
			    const struct fts_orig_mailboxes *box2)
{
	int ret;

	T_BEGIN {
		string_t *tmp1, *tmp2;
		const char *vname1, *vname2;

		tmp1 = t_str_new(128);
		tmp2 = t_str_new(128);
		vname1 = mail_namespace_get_vname(box1->ns, tmp1, box1->name);
		vname2 = mail_namespace_get_vname(box2->ns, tmp2, box2->name);
		ret = strcmp(vname1, vname2);
	} T_END;
	return ret;
}

static int
fts_backend_uid_map_mailbox_cmp(const struct fts_backend_uid_map *map1,
				const struct fts_backend_uid_map *map2)
{
	return strcmp(map1->mailbox, map2->mailbox);
}

static int fts_build_init_virtual_next(struct fts_search_context *fctx)
{
	struct fts_search_virtual_context *vctx = &fctx->virtual_ctx;
	struct mailbox_status status;
	const struct fts_orig_mailboxes *boxes;
	const struct fts_backend_uid_map *last_uids;
	unsigned int boxi, uidi, box_count, last_uid_count;
	const char *vname;
	string_t *tmp;
	int ret, vret = 0;

	if (vctx->pool == NULL)
		return 0;

	if (fctx->virtual_ctx.trans != NULL)
		(void)mailbox_transaction_commit(&fctx->virtual_ctx.trans);

	boxes = array_get(&vctx->orig_mailboxes, &box_count);
	last_uids = array_get(&vctx->last_uids, &last_uid_count);

	tmp = t_str_new(256);
	boxi = vctx->boxi;
	uidi = vctx->uidi;
	while (vret == 0 && boxi < box_count && uidi < last_uid_count) {
		vname = mail_namespace_get_vname(boxes[boxi].ns, tmp,
						 boxes[boxi].name);
		ret = strcmp(vname, last_uids[uidi].mailbox);
		if (ret == 0) {
			/* match. check also that uidvalidity matches. */
			mailbox_get_status(boxes[boxi].box, STATUS_UIDVALIDITY,
					   &status);
			if (status.uidvalidity != last_uids[uidi].uidvalidity) {
				uidi++;
				continue;
			}
			vret = fts_build_init_box(fctx, boxes[boxi].box,
						  last_uids[uidi].uid);
			boxi++;
			uidi++;
		} else if (ret > 0) {
			/* not part of this virtual mailbox */
			uidi++;
		} else {
			/* no messages indexed in the mailbox */
			vret = fts_build_init_box(fctx, boxes[boxi].box, 0);
			boxi++;
		}
	}
	while (vret == 0 && boxi < box_count) {
		vret = fts_build_init_box(fctx, boxes[boxi].box, 0);
		boxi++;
	}
	vctx->boxi = boxi;
	vctx->uidi = uidi;
	return vret;
}

static const char *
fts_box_get_root(struct mailbox *box, struct mail_namespace **ns_r)
{
	struct mail_namespace *ns = mailbox_get_namespace(box);
	const char *name = box->name;

	while (ns->alias_for != NULL)
		ns = ns->alias_for;
	*ns_r = ns;

	if (*name == '\0' && ns != mailbox_get_namespace(box) &&
	    (ns->flags & NAMESPACE_FLAG_INBOX) != 0) {
		/* ugly workaround to allow selecting INBOX from a Maildir/
		   when it's not in the inbox=yes namespace. */
		return "INBOX";
	}
	return name;
}

static int fts_build_init_virtual(struct fts_search_context *fctx)
{
	struct fts_search_virtual_context *vctx = &fctx->virtual_ctx;
	ARRAY_TYPE(mailboxes) mailboxes;
	struct mailbox *const *boxes;
	const struct fts_orig_mailboxes *orig_boxes;
	struct fts_orig_mailboxes orig_box;
	unsigned int i, box_count;
	int ret;

	t_array_init(&mailboxes, 64);
	mailbox_get_virtual_backend_boxes(fctx->t->box, &mailboxes, TRUE);
	boxes = array_get_modifiable(&mailboxes, &box_count);

	vctx->pool = pool_alloconly_create("fts virtual build", 1024);
	p_array_init(&vctx->orig_mailboxes, vctx->pool, box_count);
	memset(&orig_box, 0, sizeof(orig_box));
	for (i = 0; i < box_count; i++) {
		orig_box.box = boxes[i];
		orig_box.name = fts_box_get_root(boxes[i], &orig_box.ns);
		array_append(&vctx->orig_mailboxes, &orig_box, 1);
	}

	orig_boxes = array_get(&vctx->orig_mailboxes, &box_count);
	if (box_count <= 0) {
		if (box_count == 0) {
			/* empty virtual mailbox */
			return 0;
		}
		/* virtual mailbox is built from only a single mailbox
		   (currently). check that directly. */
		fctx->virtual_ctx.trans =
			mailbox_transaction_begin(orig_boxes[0].box, 0);
		ret = fts_build_init_trans(fctx, fctx->virtual_ctx.trans);
		return ret;
	}

	/* virtual mailbox is built from multiple mailboxes. figure out which
	   ones need updating. */
	p_array_init(&vctx->last_uids, vctx->pool, 64);
	if (fts_backend_get_all_last_uids(fctx->build_backend, vctx->pool,
					  &vctx->last_uids) < 0) {
		pool_unref(&vctx->pool);
		return -1;
	}

	array_sort(&vctx->orig_mailboxes, mailbox_name_cmp);
	array_sort(&vctx->last_uids, fts_backend_uid_map_mailbox_cmp);

	ret = fts_build_init_virtual_next(fctx);
	return ret < 0 ? -1 : 0;
}

static int fts_build_init(struct fts_search_context *fctx)
{
	struct mailbox_status status;
	int ret;

	mailbox_get_status(fctx->t->box, STATUS_MESSAGES | STATUS_UIDNEXT,
			   &status);
	if (status.messages == fctx->fbox->last_messages_count &&
	    status.uidnext == fctx->fbox->last_uidnext) {
		/* no new messages since last check */
		return 0;
	}

	if (fctx->fbox->virtual &&
	    (fctx->build_backend->flags & FTS_BACKEND_FLAG_VIRTUAL_LOOKUPS) != 0)
		ret = fts_build_init_virtual(fctx);
	else
		ret = fts_build_init_trans(fctx, fctx->t);
	if (ret == 0 && fctx->build_ctx == NULL) {
		/* index was up-to-date */
		fctx->fbox->last_messages_count = status.messages;
		fctx->fbox->last_uidnext = status.uidnext;
	}
	return ret;
}

static int fts_build_deinit(struct fts_storage_build_context **_ctx)
{
	struct fts_storage_build_context *ctx = *_ctx;
	struct mailbox *box = ctx->mail->transaction->box;
	struct fts_mailbox *fbox = FTS_CONTEXT(box);
	struct mailbox_status status;
	int ret = 0;

	*_ctx = NULL;

	if (mailbox_search_deinit(&ctx->search_ctx) < 0)
		ret = -1;
	mail_free(&ctx->mail);

	if (fts_backend_build_deinit(&ctx->build) < 0)
		ret = -1;

	if (ret == 0) {
		mailbox_get_status(box, STATUS_MESSAGES | STATUS_UIDNEXT,
				   &status);
		fbox->last_messages_count = status.messages;
		fbox->last_uidnext = status.uidnext;
	}

	if (ioloop_time - ctx->search_start_time.tv_sec >=
	    FTS_BUILD_NOTIFY_INTERVAL_SECS) {
		/* we notified at least once */
		box->storage->callbacks.
			notify_ok(box, "Mailbox indexing finished",
				  box->storage->callback_context);
	}

	str_free(&ctx->headers);
	mail_search_args_unref(&ctx->search_args);
	i_free(ctx);
	return ret;
}

static void fts_build_notify(struct fts_storage_build_context *ctx)
{
	struct mailbox *box = ctx->mail->transaction->box;
	const struct seq_range *range;
	float percentage;
	unsigned int msecs, secs;

	if (ctx->last_notify.tv_sec == 0) {
		/* set the search time in here, in case a plugin
		   already spent some time indexing the mailbox */
		ctx->search_start_time = ioloop_timeval;
	} else if (box->storage->callbacks.notify_ok != NULL) {
		range = array_idx(&ctx->search_args->args->value.seqset, 0);
		percentage = (ctx->mail->seq - range->seq1) * 100.0 /
			(range->seq2 - range->seq1);
		msecs = timeval_diff_msecs(&ioloop_timeval,
					   &ctx->search_start_time);
		secs = (msecs / (percentage / 100.0) - msecs) / 1000;

		T_BEGIN {
			const char *text;

			text = t_strdup_printf("Indexed %d%% of the mailbox, "
					       "ETA %d:%02d", (int)percentage,
					       secs/60, secs%60);
			box->storage->callbacks.
				notify_ok(box, text,
				box->storage->callback_context);
		} T_END;
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
		T_BEGIN {
			ret = fts_build_mail(ctx, ctx->mail->uid);
		} T_END;

		if (ret < 0)
			return -1;

		if (++count == FTS_SEARCH_NONBLOCK_COUNT)
			return 0;
	}

	return 1;
}

static void fts_search_init_lookup(struct mail_search_context *ctx,
				   struct fts_search_context *fctx)
{
	fts_search_lookup(fctx);

	if (fctx->seqs_set &&
	    strcmp(ctx->transaction->box->storage->name, "virtual") != 0) {
		ctx->progress_max = array_count(&fctx->definite_seqs) +
			array_count(&fctx->maybe_seqs);
	}
	ctx->progress_cur = 0;
}

static bool fts_try_build_init(struct mail_search_context *ctx,
			       struct fts_search_context *fctx)
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
		fts_search_init_lookup(ctx, fctx);
	} else {
		/* hide "searching" notifications */
		ctx->progress_hidden = TRUE;
	}
	return TRUE;
}

static struct mail_search_context *
fts_mailbox_search_init(struct mailbox_transaction_context *t,
			struct mail_search_args *args,
			const enum mail_sort_type *sort_program)
{
	struct fts_transaction_context *ft = FTS_CONTEXT(t);
	struct fts_mailbox *fbox = FTS_CONTEXT(t->box);
	struct mail_search_context *ctx;
	struct fts_search_context *fctx;

	ctx = fbox->module_ctx.super.search_init(t, args, sort_program);

	fctx = i_new(struct fts_search_context, 1);
	fctx->fbox = fbox;
	fctx->t = t;
	fctx->args = args;
	fctx->first_nonindexed_seq = (uint32_t)-1;
	MODULE_CONTEXT_SET(ctx, fts_storage_module, fctx);

	if (fbox->backend_substr == NULL && fbox->backend_fast == NULL)
		return ctx;

	ft->score_map = &fctx->score_map;

	fts_search_analyze(fctx);
	(void)fts_try_build_init(ctx, fctx);
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
		if (!fts_try_build_init(ctx, fctx)) {
			*tryagain_r = TRUE;
			return 0;
		}
	}

	while (fctx->build_ctx != NULL) {
		/* this command is still building the indexes */
		ret = fts_build_more(fctx->build_ctx);
		if (ret == 0) {
			*tryagain_r = TRUE;
			return 0;
		}

		/* finished / error */
		ctx->progress_hidden = FALSE;
		if (fts_build_deinit(&fctx->build_ctx) < 0)
			ret = -1;
		if (ret > 0) {
			if (fts_build_init_virtual_next(fctx) == 0) {
				/* all finished */
				fts_search_init_lookup(ctx, fctx);
			}
		}
	}

	/* if we're here, the indexes are either built or they're not used */
	return fbox->module_ctx.super.
		search_next_nonblock(ctx, mail, tryagain_r);
}

static void
fts_mailbox_search_args_definite_set(struct fts_search_context *fctx)
{
	struct mail_search_arg *arg;

	for (arg = fctx->args->args; arg != NULL; arg = arg->next) {
		switch (arg->type) {
		case SEARCH_TEXT:
		case SEARCH_BODY:
			if (fctx->fbox->backend_substr == NULL) {
				/* we're marking only fast args */
				break;
			}
		case SEARCH_BODY_FAST:
		case SEARCH_TEXT_FAST:
			arg->result = 1;
			break;
		default:
			break;
		}
	}
}

static bool search_nonindexed(struct mail_search_context *ctx)
{
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);
	struct mailbox_status status;

	mailbox_get_status(ctx->transaction->box, STATUS_MESSAGES, &status);

	fctx->seqs_set = FALSE;
	ctx->seq = fctx->first_nonindexed_seq - 1;
	ctx->progress_cur = ctx->seq;
	ctx->progress_max = status.messages;
	return fbox->module_ctx.super.search_next_update_seq(ctx);
}

static bool fts_mailbox_search_next_update_seq(struct mail_search_context *ctx)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);
	struct seq_range *def_range, *maybe_range, *range;
	unsigned int def_count, maybe_count;
	uint32_t wanted_seq;
	bool use_maybe, ret;

	if (!fctx->seqs_set)
		return fbox->module_ctx.super.search_next_update_seq(ctx);

	wanted_seq = ctx->seq + 1;
	/* fts_search_lookup() was called successfully */
	for (;;) {
		def_range = array_get_modifiable(&fctx->definite_seqs,
						 &def_count);
		maybe_range = array_get_modifiable(&fctx->maybe_seqs,
						   &maybe_count);
		/* if we're ahead of current positions, skip them */
		while (fctx->definite_idx < def_count &&
		       wanted_seq > def_range[fctx->definite_idx].seq2)
			fctx->definite_idx++;
		while (fctx->maybe_idx < maybe_count &&
		       wanted_seq > maybe_range[fctx->maybe_idx].seq2)
			fctx->maybe_idx++;

		/* use whichever is lower of definite/maybe */
		if (fctx->definite_idx == def_count) {
			if (fctx->maybe_idx == maybe_count) {
				/* look for the non-indexed mails */
				if (fctx->first_nonindexed_seq == (uint32_t)-1)
					return FALSE;
				return search_nonindexed(ctx);
			}
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
		if (wanted_seq > range->seq1) {
			/* current sequence is already larger than where
			   range begins, so use the current sequence. */
			range->seq1 = wanted_seq+1;
		} else {
			wanted_seq = range->seq1;
			range->seq1++;
		}
		if (range->seq1 > range->seq2)
			range->seq2 = 0;

		/* ctx->seq points to previous sequence we want */
		ctx->seq = wanted_seq - 1;
		ret = fbox->module_ctx.super.search_next_update_seq(ctx);
		if (!ret || wanted_seq == ctx->seq)
			break;
		wanted_seq = ctx->seq;
		mail_search_args_reset(ctx->args->args, FALSE);
	}

	if (!use_maybe) {
		/* we have definite results, update args */
		fts_mailbox_search_args_definite_set(fctx);
	}

	if (ctx->seq + 1 >= fctx->first_nonindexed_seq) {
		/* this is a virtual mailbox and we're searching headers.
		   some mailboxes had more messages indexed than others.
		   to avoid duplicates or jumping around, ignore the rest of
		   the search results and just go through the messages in
		   order. */
		return search_nonindexed(ctx);
	}

	ctx->progress_cur = fctx->definite_idx + fctx->maybe_idx;
	return ret;
}

static bool
fts_mailbox_search_next_update_seq_virtual(struct mail_search_context *ctx)
{
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);

	while (fbox->module_ctx.super.search_next_update_seq(ctx)) {
		if (!fctx->seqs_set)
			return TRUE;

		/* virtual mailbox searches don't return sequences sorted.
		   just check if the suggested sequence exists. */
		if (seq_range_exists(&fctx->definite_seqs, ctx->seq)) {
			fts_mailbox_search_args_definite_set(fctx);
			return TRUE;
		}
		if (seq_range_exists(&fctx->maybe_seqs, ctx->seq))
			return TRUE;
		mail_search_args_reset(ctx->args->args, FALSE);
	}
	return FALSE;
}

static int fts_mailbox_search_deinit(struct mail_search_context *ctx)
{
	struct fts_transaction_context *ft = FTS_CONTEXT(ctx->transaction);
	struct fts_mailbox *fbox = FTS_CONTEXT(ctx->transaction->box);
	struct fts_search_context *fctx = FTS_CONTEXT(ctx);

	if (ft->score_map == &fctx->score_map)
		ft->score_map = NULL;

	if (fctx->build_ctx != NULL) {
		/* the search was cancelled */
		(void)fts_build_deinit(&fctx->build_ctx);
	}

	if (array_is_created(&fctx->definite_seqs))
		array_free(&fctx->definite_seqs);
	if (array_is_created(&fctx->maybe_seqs))
		array_free(&fctx->maybe_seqs);
	if (array_is_created(&fctx->score_map))
		array_free(&fctx->score_map);
	if (fctx->virtual_ctx.trans != NULL)
		(void)mailbox_transaction_commit(&fctx->virtual_ctx.trans);
	if (fctx->virtual_ctx.pool != NULL)
		pool_unref(&fctx->virtual_ctx.pool);
	i_free(fctx);
	return fbox->module_ctx.super.search_deinit(ctx);
}

static void fts_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct fts_mail *fmail = FTS_MAIL_CONTEXT(mail);
	struct fts_mailbox *fbox = FTS_CONTEXT(_mail->box);
	struct fts_transaction_context *ft = FTS_CONTEXT(_mail->transaction);

	ft->expunges = TRUE;
	if (fbox->backend_substr != NULL)
		fts_backend_expunge(fbox->backend_substr, _mail);
	if (fbox->backend_fast != NULL)
		fts_backend_expunge(fbox->backend_fast, _mail);

	fmail->module_ctx.super.expunge(_mail);
}

static int fts_score_cmp(const uint32_t *uid, const struct fts_score_map *score)
{
	return *uid < score->uid ? -1 :
		(*uid > score->uid ? 1 : 0);
}

static int fts_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
				const char **value_r)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct fts_mail *fmail = FTS_MAIL_CONTEXT(mail);
	struct fts_transaction_context *ft = FTS_CONTEXT(_mail->transaction);
	const struct fts_score_map *scores;

	if (field != MAIL_FETCH_SEARCH_SCORE || ft->score_map == NULL ||
	    !array_is_created(ft->score_map))
		scores = NULL;
	else {
		scores = array_bsearch(ft->score_map, &_mail->uid,
				       fts_score_cmp);
	}
	if (scores != NULL) {
		i_assert(scores->uid == _mail->uid);
		i_snprintf(fmail->score, sizeof(fmail->score),
			   "%f", scores->score);
		*value_r = fmail->score;
		return 0;
	}

	return fmail->module_ctx.super.get_special(_mail, field, value_r);
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

	_mail = fbox->module_ctx.super.
		mail_alloc(t, wanted_fields, wanted_headers);
	if (fbox->backend_substr != NULL || fbox->backend_fast != NULL) {
		mail = (struct mail_private *)_mail;

		fmail = p_new(mail->pool, struct fts_mail, 1);
		fmail->module_ctx.super = mail->v;

		mail->v.expunge = fts_mail_expunge;
		mail->v.get_special = fts_mail_get_special;
		MODULE_CONTEXT_SET(mail, fts_mail_module, fmail);
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
	if (box->storage->set->mail_debug &&
	    fbox->backend_substr == NULL && fbox->backend_fast == NULL)
		i_debug("fts: No backends enabled by the fts setting");
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

static int
fts_transaction_commit(struct mailbox_transaction_context *t,
		       struct mail_transaction_commit_changes *changes_r)
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

	ret = fbox->module_ctx.super.transaction_commit(t, changes_r);
	fts_transaction_finish(box, ft, ret == 0);
	return ret;
}

static void fts_mailbox_init(struct mailbox *box, const char *env)
{
	struct fts_mailbox *fbox;

	fbox = i_new(struct fts_mailbox, 1);
	fbox->virtual = strcmp(box->storage->name, "virtual") == 0;
	fbox->env = env;
	fbox->module_ctx.super = box->v;
	box->v.close = fts_mailbox_close;
	box->v.search_init = fts_mailbox_search_init;
	box->v.search_next_nonblock = fts_mailbox_search_next_nonblock;
	box->v.search_next_update_seq = fbox->virtual ?
		fts_mailbox_search_next_update_seq_virtual :
		fts_mailbox_search_next_update_seq;
	box->v.search_deinit = fts_mailbox_search_deinit;
	box->v.mail_alloc = fts_mail_alloc;
	box->v.transaction_begin = fts_transaction_begin;
	box->v.transaction_rollback = fts_transaction_rollback;
	box->v.transaction_commit = fts_transaction_commit;

	MODULE_CONTEXT_SET(box, fts_storage_module, fbox);
}

void fts_mailbox_allocated(struct mailbox *box)
{
	const char *env;

	env = mail_user_plugin_getenv(box->storage->user, "fts");
	if (env != NULL)
		fts_mailbox_init(box, env);

	if (fts_next_hook_mailbox_allocated != NULL)
		fts_next_hook_mailbox_allocated(box);
}
