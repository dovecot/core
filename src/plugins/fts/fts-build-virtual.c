/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mail-storage-private.h"
#include "mail-search-build.h"
#include "../virtual/virtual-storage.h"
#include "fts-api-private.h"
#include "fts-storage.h"
#include "fts-build-private.h"

#define FTS_SEARCH_NONBLOCK_COUNT 50

struct virtual_fts_storage_build_context {
	struct fts_storage_build_context ctx;

	struct fts_backend *update_backend;
	uint32_t virtual_last_uid;

	ARRAY_TYPE(mailboxes) mailboxes;
	unsigned int mailbox_idx;
};

static int
fts_mailbox_get_seqs(struct mailbox *box, uint32_t *seq1_r, uint32_t *seq2_r)
{
	struct mailbox_status status;
	uint32_t last_uid;

	if (fts_backend_get_last_uid(fts_mailbox_backend(box),
				     box, &last_uid) < 0)
		return -1;

	mailbox_get_open_status(box, STATUS_UIDNEXT, &status);
	if (status.uidnext <= last_uid+1)
		*seq1_r = *seq2_r = 0;
	else {
		mailbox_get_seq_range(box, last_uid+1, (uint32_t)-1,
				      seq1_r, seq2_r);
	}
	return 0;
}

static int
fts_build_virtual_mailboxes_get(struct virtual_fts_storage_build_context *ctx)
{
	struct virtual_mailbox *vbox =
		(struct virtual_mailbox *)ctx->ctx.box;
	struct mailbox *const *boxp;
	ARRAY_TYPE(mailboxes) all_mailboxes;
	uint32_t seq1, seq2;

	t_array_init(&all_mailboxes, 64);
	i_array_init(&ctx->mailboxes, 64);
	vbox->vfuncs.get_virtual_backend_boxes(ctx->ctx.box,
					       &all_mailboxes, TRUE);

	array_foreach(&all_mailboxes, boxp) {
		if (fts_mailbox_get_seqs(*boxp, &seq1, &seq2) < 0) {
			array_free(&ctx->mailboxes);
			return -1;
		}
		if (seq1 != 0) {
			ctx->ctx.mail_count += seq2 - seq1 + 1;
			array_append(&ctx->mailboxes, boxp, 1);
		}
	}
	return 0;
}

static void
fts_build_virtual_mailbox_close(struct virtual_fts_storage_build_context *ctx)
{
	if (mailbox_search_deinit(&ctx->ctx.search_ctx) < 0)
		ctx->ctx.failed = TRUE;
	(void)mailbox_transaction_commit(&ctx->ctx.trans);
}

static bool
fts_build_virtual_mailbox_next(struct virtual_fts_storage_build_context *ctx)
{
	struct mail_search_args *search_args;
	struct mailbox *const *boxes, *box;
	struct fts_backend *backend;
	unsigned int count;
	uint32_t seq1, seq2;

	boxes = array_get(&ctx->mailboxes, &count);
	if (ctx->mailbox_idx == count)
		return FALSE;
	box = boxes[ctx->mailbox_idx++];

	if (ctx->ctx.trans != NULL)
		fts_build_virtual_mailbox_close(ctx);

	if (fts_mailbox_get_seqs(box, &seq1, &seq2) < 0) {
		ctx->ctx.failed = TRUE;
		return fts_build_virtual_mailbox_next(ctx);
	}

	backend = fts_mailbox_backend(box);
	if (ctx->update_backend != backend) {
		if (ctx->ctx.update_ctx != NULL) {
			if (fts_backend_update_deinit(&ctx->ctx.update_ctx) < 0)
				ctx->ctx.failed = TRUE;
		}
		ctx->update_backend = backend;
		ctx->ctx.update_ctx = fts_backend_update_init(backend);
	}


	fts_backend_update_set_mailbox(ctx->ctx.update_ctx, box);
	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, seq1, seq2);

	ctx->ctx.trans = mailbox_transaction_begin(box, 0);
	ctx->ctx.search_ctx = mailbox_search_init(ctx->ctx.trans, search_args,
						  NULL, 0, NULL);
	ctx->ctx.search_ctx->progress_hidden = TRUE;
	mail_search_args_unref(&search_args);
	return TRUE;
}

static int
fts_build_virtual_init(struct fts_backend *backend, struct mailbox *box,
		       struct fts_storage_build_context **build_ctx_r)
{
	struct virtual_fts_storage_build_context *ctx;
	struct mailbox_status status;
	uint32_t last_uid;

	/* first do a quick check: is the virtual mailbox's last indexed
	   UID up to date? */
	if (fts_backend_get_last_uid(backend, box, &last_uid) < 0)
		return -1;

	mailbox_get_open_status(box, STATUS_UIDNEXT, &status);
	if (status.uidnext == last_uid+1)
		return 0;

	/* nope. we'll need to go through its mailboxes and check their
	   indexes. FIXME: we could optimize by going through only those
	   mailboxes that exist in >last_uid mails */
	ctx = i_new(struct virtual_fts_storage_build_context, 1);
	ctx->ctx.box = box;
	ctx->virtual_last_uid = status.uidnext - 1;

	if (fts_build_virtual_mailboxes_get(ctx) < 0) {
		i_free(ctx);
		return -1;
	}
	fts_build_virtual_mailbox_next(ctx);

	*build_ctx_r = &ctx->ctx;
	return 1;
}

static int fts_build_virtual_deinit(struct fts_storage_build_context *_ctx)
{
	struct virtual_fts_storage_build_context *ctx =
		(struct virtual_fts_storage_build_context *)_ctx;

	if (!_ctx->failed) {
		(void)fts_index_set_last_uid(ctx->ctx.box,
					     ctx->virtual_last_uid);
	}

	fts_build_virtual_mailbox_close(ctx);
	array_free(&ctx->mailboxes);
	return 0;
}

static int fts_build_virtual_more(struct fts_storage_build_context *_ctx)
{
	struct virtual_fts_storage_build_context *ctx =
		(struct virtual_fts_storage_build_context *)_ctx;
	struct mail *mail;
	unsigned int count = 0;
	int ret;

	while (mailbox_search_next(_ctx->search_ctx, &mail)) {
		T_BEGIN {
			ret = fts_build_mail(_ctx, mail);
		} T_END;

		if (ret < 0)
			return -1;

		_ctx->mail_idx++;
		if (++count == FTS_SEARCH_NONBLOCK_COUNT)
			return 0;
	}

	if (fts_build_virtual_mailbox_next(ctx))
		return fts_build_virtual_more(_ctx);
	return 1;
}

const struct fts_storage_build_vfuncs fts_storage_build_virtual_vfuncs = {
	fts_build_virtual_init,
	fts_build_virtual_deinit,
	fts_build_virtual_more
};
