/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "index-mail.h"
#include "imapc-storage.h"
#include "imapc-sync.h"

struct imapc_save_context {
	struct mail_save_context ctx;

	struct imapc_mailbox *mbox;
	struct mail_index_transaction *trans;

	unsigned int failed:1;
};

struct mail_save_context *
imapc_save_alloc(struct mailbox_transaction_context *t)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)t->box;
	struct imapc_save_context *ctx;

	i_assert((t->flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (t->save_ctx == NULL) {
		ctx = i_new(struct imapc_save_context, 1);
		ctx->ctx.transaction = t;
		ctx->mbox = mbox;
		ctx->trans = t->itrans;
		t->save_ctx = &ctx->ctx;
	}
	return t->save_ctx;
}

int imapc_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	return -1;
}

int imapc_save_continue(struct mail_save_context *_ctx)
{
	return -1;
}

int imapc_save_finish(struct mail_save_context *_ctx)
{
	struct imapc_save_context *ctx = (struct imapc_save_context *)_ctx;

	ctx->failed = TRUE;

	index_save_context_free(_ctx);
	return ctx->failed ? -1 : 0;
}

void imapc_save_cancel(struct mail_save_context *_ctx)
{
	struct imapc_save_context *ctx = (struct imapc_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)imapc_save_finish(_ctx);
}

int imapc_transaction_save_commit_pre(struct mail_save_context *_ctx)
{
	return -1;
}

void imapc_transaction_save_commit_post(struct mail_save_context *_ctx,
					struct mail_index_transaction_commit_result *result)
{
}

void imapc_transaction_save_rollback(struct mail_save_context *_ctx)
{
}
