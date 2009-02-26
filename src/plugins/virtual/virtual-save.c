/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "virtual-transaction.h"
#include "virtual-storage.h"

struct virtual_save_context {
	struct mail_save_context ctx;
	struct mail_save_context *backend_save_ctx;
};

struct mail_save_context *
virtual_save_alloc(struct mailbox_transaction_context *_t)
{
	struct virtual_transaction_context *t =
		(struct virtual_transaction_context *)_t;
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)_t->box;
	struct mailbox_transaction_context *backend_trans;
	struct virtual_save_context *ctx;

	if (t->save_ctx != NULL)
		return &t->save_ctx->ctx;

	ctx = t->save_ctx = i_new(struct virtual_save_context, 1);
	ctx->ctx.transaction = &t->ictx.mailbox_ctx;

	if (mbox->save_bbox != NULL) {
		backend_trans =
			virtual_transaction_get(_t, mbox->save_bbox->box);
		ctx->backend_save_ctx = mailbox_save_alloc(backend_trans);
	}
	return &ctx->ctx;
}

int virtual_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	struct virtual_save_context *ctx = (struct virtual_save_context *)_ctx;
	struct virtual_mailbox *mbox =
		(struct virtual_mailbox *)_ctx->transaction->box;
	struct mail *mail;

	if (ctx->backend_save_ctx == NULL) {
		mail_storage_set_error(_ctx->transaction->box->storage,
			MAIL_ERROR_NOTPOSSIBLE,
			"Can't save messages to this virtual mailbox");
		return -1;
	}

	mailbox_save_set_flags(ctx->backend_save_ctx, _ctx->flags,
			       _ctx->keywords);
	mailbox_save_set_received_date(ctx->backend_save_ctx,
				       _ctx->received_date,
				       _ctx->received_tz_offset);
	mailbox_save_set_from_envelope(ctx->backend_save_ctx,
				       _ctx->from_envelope);
	mailbox_save_set_guid(ctx->backend_save_ctx, _ctx->guid);

	if (_ctx->dest_mail != NULL) {
		mail = virtual_mail_set_backend_mail(_ctx->dest_mail,
						     mbox->save_bbox);
		mailbox_save_set_dest_mail(ctx->backend_save_ctx, mail);
	}
	return mailbox_save_begin(&ctx->backend_save_ctx, input);
}

int virtual_save_continue(struct mail_save_context *_ctx)
{
	struct virtual_save_context *ctx = (struct virtual_save_context *)_ctx;

	return mailbox_save_continue(ctx->backend_save_ctx);
}

int virtual_save_finish(struct mail_save_context *_ctx)
{
	struct virtual_save_context *ctx = (struct virtual_save_context *)_ctx;

	return mailbox_save_finish(&ctx->backend_save_ctx);
}

void virtual_save_cancel(struct mail_save_context *_ctx)
{
	struct virtual_save_context *ctx = (struct virtual_save_context *)_ctx;

	if (ctx->backend_save_ctx != NULL)
		mailbox_save_cancel(&ctx->backend_save_ctx);
}

void virtual_save_free(struct virtual_save_context *ctx)
{
	if (ctx->backend_save_ctx != NULL)
		mailbox_save_cancel(&ctx->backend_save_ctx);
	i_free(ctx);
}
