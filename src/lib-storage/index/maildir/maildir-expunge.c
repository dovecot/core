/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "index-expunge.h"
#include "maildir-index.h"
#include "maildir-storage.h"

struct maildir_expunge_context {
	struct mail_expunge_context *ctx;
	int sent_access_warning;
};

struct mail_expunge_context *
maildir_storage_expunge_init(struct mailbox *box,
			     enum mail_fetch_field wanted_fields,
			     int expunge_all)
{
	struct maildir_expunge_context *ctx;
        struct mail_expunge_context *mctx;

	mctx = index_storage_expunge_init(box, wanted_fields, expunge_all);
	if (mctx == NULL)
		return NULL;

	ctx = i_new(struct maildir_expunge_context, 1);
	ctx->ctx = mctx;
	return (struct mail_expunge_context *) ctx;
}

int maildir_storage_expunge_deinit(struct mail_expunge_context *_ctx)
{
	struct maildir_expunge_context *ctx =
		(struct maildir_expunge_context *) _ctx;
	struct mail_expunge_context *mctx;

	mctx = ctx->ctx;
	i_free(ctx);
	return index_storage_expunge_deinit(mctx);
}

struct mail *
maildir_storage_expunge_fetch_next(struct mail_expunge_context *_ctx)
{
	struct maildir_expunge_context *ctx =
		(struct maildir_expunge_context *) _ctx;

	return index_storage_expunge_fetch_next(ctx->ctx);
}

int maildir_storage_expunge(struct mail *mail,
			    struct mail_expunge_context *_ctx,
			    unsigned int *seq_r, int notify)
{
	struct maildir_expunge_context *ctx =
		(struct maildir_expunge_context *) _ctx;
	struct index_mail *imail = (struct index_mail *) mail;
	int ret;

	if (mail->box->readonly) {
		/* send warning */
		return index_storage_expunge(mail, ctx->ctx, seq_r, notify);
	}

	t_push();
	ret = maildir_expunge_mail(imail->ibox->index, imail->data.rec);
	t_pop();

	if (!ret) {
		if (errno != EACCES)
			return FALSE;

		if (ctx->sent_access_warning)
			return TRUE;
                ctx->sent_access_warning = TRUE;

		mail->box->storage->callbacks->notify_no(mail->box,
			"We didn't have permission to expunge all the mails",
			mail->box->storage->callback_context);
		return TRUE;
	}

	return index_storage_expunge(mail, ctx->ctx, seq_r, notify);
}
