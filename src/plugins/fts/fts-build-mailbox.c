/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mail-storage-private.h"
#include "mail-search-build.h"
#include "fts-api-private.h"
#include "fts-build-private.h"

#define FTS_SEARCH_NONBLOCK_COUNT 50

static int
fts_build_mailbox_init(struct fts_backend *backend, struct mailbox *box,
		       struct fts_storage_build_context **build_ctx_r)
{
	struct fts_storage_build_context *ctx;
	struct mail_search_args *search_args;
	struct fts_backend_update_context *update_ctx;
	struct mailbox_status status;
	uint32_t last_uid, seq1, seq2;

	if (fts_backend_get_last_uid(backend, box, &last_uid) < 0)
		return -1;

	mailbox_get_open_status(box, STATUS_UIDNEXT, &status);
	if (status.uidnext == last_uid+1) {
		/* everything is already indexed */
		return 0;
	}

	mailbox_get_seq_range(box, last_uid+1, (uint32_t)-1, &seq1, &seq2);
	if (seq1 == 0) {
		/* no new messages (last messages in mailbox were expunged) */
		return 0;
	}

	update_ctx = fts_backend_update_init(backend);
	fts_backend_update_set_mailbox(update_ctx, box);

	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, seq1, seq2);

	ctx = i_new(struct fts_storage_build_context, 1);
	ctx->update_ctx = update_ctx;
	ctx->mail_count = seq2 - seq1 + 1;

	ctx->trans = mailbox_transaction_begin(box, 0);
	ctx->search_ctx = mailbox_search_init(ctx->trans, search_args,
					      NULL, 0, NULL);
	ctx->search_ctx->progress_hidden = TRUE;
	mail_search_args_unref(&search_args);

	*build_ctx_r = ctx;
	return 1;
}

static int fts_build_mailbox_deinit(struct fts_storage_build_context *ctx)
{
	int ret;

	ret = mailbox_search_deinit(&ctx->search_ctx);
	(void)mailbox_transaction_commit(&ctx->trans);
	return ret;
}

static int fts_build_mailbox_more(struct fts_storage_build_context *ctx)
{
	struct mail *mail = NULL;
	unsigned int count = 0;
	int ret;

	while (mailbox_search_next(ctx->search_ctx, &mail)) {
		T_BEGIN {
			ret = fts_build_mail(ctx, mail);
		} T_END;

		if (ret < 0)
			return -1;

		ctx->mail_idx++;
		if (++count == FTS_SEARCH_NONBLOCK_COUNT)
			return 0;
	}
	return 1;
}

const struct fts_storage_build_vfuncs fts_storage_build_mailbox_vfuncs = {
	fts_build_mailbox_init,
	fts_build_mailbox_deinit,
	fts_build_mailbox_more
};
