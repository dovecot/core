/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "virtual-transaction.h"
#include "virtual-storage.h"

struct virtual_save_context {
	struct mail_save_context ctx;
	struct mail_save_context *backend_save_ctx;
	struct mailbox *backend_box;
	struct mail_keywords *backend_keywords;
};

struct mail_save_context *
virtual_save_alloc(struct mailbox_transaction_context *_t)
{
	struct virtual_transaction_context *t =
		(struct virtual_transaction_context *)_t;
	struct virtual_mailbox *mbox = (struct virtual_mailbox *)_t->box;
	struct mailbox_transaction_context *backend_trans;
	struct virtual_save_context *ctx;

	if (_t->save_ctx == NULL) {
		ctx = i_new(struct virtual_save_context, 1);
		ctx->ctx.transaction = &t->ictx.mailbox_ctx;
		_t->save_ctx = &ctx->ctx;
	} else {
		ctx = (struct virtual_save_context *)_t->save_ctx;
	}

	if (mbox->save_bbox != NULL) {
		i_assert(ctx->backend_save_ctx == NULL);
		backend_trans =
			virtual_transaction_get(_t, mbox->save_bbox->box);
		ctx->backend_save_ctx = mailbox_save_alloc(backend_trans);
	}
	return _t->save_ctx;
}

static struct mail_keywords *
virtual_copy_keywords(struct mailbox *src_box,
		      const struct mail_keywords *src_keywords,
		      struct mailbox *dest_box)
{
	struct mailbox_status status;
	ARRAY_TYPE(keywords) kw_strings;
	const char *const *kwp;
	unsigned int i;

	if (src_keywords == NULL || src_keywords->count == 0)
		return NULL;

	t_array_init(&kw_strings, src_keywords->count + 1);
	mailbox_get_status(src_box, STATUS_KEYWORDS, &status);

	for (i = 0; i < src_keywords->count; i++) {
		kwp = array_idx(status.keywords, src_keywords->idx[i]);
		array_append(&kw_strings, kwp, 1);
	}
	(void)array_append_space(&kw_strings);
	return mailbox_keywords_create_valid(dest_box,
					     array_idx(&kw_strings, 0));
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

	ctx->backend_box = ctx->backend_save_ctx->transaction->box;
	ctx->backend_keywords =
		virtual_copy_keywords(_ctx->transaction->box, _ctx->keywords,
				      ctx->backend_box);

	mailbox_save_set_flags(ctx->backend_save_ctx, _ctx->flags,
			       ctx->backend_keywords);
	mailbox_save_set_received_date(ctx->backend_save_ctx,
				       _ctx->received_date,
				       _ctx->received_tz_offset);
	mailbox_save_set_from_envelope(ctx->backend_save_ctx,
				       _ctx->from_envelope);
	mailbox_save_set_guid(ctx->backend_save_ctx, _ctx->guid);
	mailbox_save_set_min_modseq(ctx->backend_save_ctx, _ctx->min_modseq);

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

void virtual_save_free(struct mail_save_context *_ctx)
{
	struct virtual_save_context *ctx = (struct virtual_save_context *)_ctx;

	if (ctx->backend_keywords != NULL)
		mailbox_keywords_unref(ctx->backend_box, &ctx->backend_keywords);
	if (ctx->backend_save_ctx != NULL)
		mailbox_save_cancel(&ctx->backend_save_ctx);
	i_free(ctx);
}
