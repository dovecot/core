/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "mail-custom-flags.h"
#include "index-storage.h"
#include "index-messageset.h"

#include <unistd.h>

struct mail_copy_context {
	struct mailbox *box;
	struct mail_save_context *save_ctx;
};

struct mail_copy_context *index_storage_copy_init(struct mailbox *box)
{
	struct mail_copy_context *ctx;
	struct mail_save_context *save_ctx;

	save_ctx = box->save_init(box, TRUE);
	if (save_ctx == NULL)
		return NULL;

	ctx = i_new(struct mail_copy_context, 1);
	ctx->box = box;
	ctx->save_ctx = save_ctx;

	return ctx;
}

int index_storage_copy_deinit(struct mail_copy_context *ctx, int rollback)
{
	int ret;

	ret = ctx->box->save_deinit(ctx->save_ctx, rollback);
	i_free(ctx);
	return ret;
}

int index_storage_copy(struct mail *mail, struct mail_copy_context *ctx)
{
	struct index_mail *imail = (struct index_mail *) mail;
	struct istream *input;
	time_t received_date;
	int ret, deleted;

	input = imail->ibox->index->open_mail(imail->ibox->index,
					      imail->data.rec,
					      &received_date, &deleted);
	if (input == NULL)
		return FALSE;

	ret = ctx->box->save_next(ctx->save_ctx, mail->get_flags(mail),
				  received_date, 0, input);
	i_stream_unref(input);

	return ret;
}
