/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "index-storage.h"
#include "index-mail.h"

void index_transaction_init(struct index_transaction_context *t,
			    struct index_mailbox *ibox,
			    enum mailbox_transaction_flags flags)
{
	t->mailbox_ctx.box = &ibox->box;
	t->ibox = ibox;
	t->flags = flags;

	array_create(&t->mailbox_ctx.module_contexts, default_pool,
		     sizeof(void *), 5);

	t->trans = mail_index_transaction_begin(ibox->view,
		(flags & MAILBOX_TRANSACTION_FLAG_HIDE) != 0,
		(flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);
	t->trans_view = mail_index_transaction_open_updated_view(t->trans);
	t->cache_view = mail_cache_view_open(ibox->cache, t->trans_view);
	t->cache_trans = mail_cache_get_transaction(t->cache_view, t->trans);
}

static void index_transaction_free(struct index_transaction_context *t)
{
	mail_cache_view_close(t->cache_view);
	mail_index_view_close(&t->trans_view);
	mail_index_view_unlock(t->ibox->view);
	array_free(&t->mailbox_ctx.module_contexts);
	i_free(t);
}

int index_transaction_commit(struct mailbox_transaction_context *_t)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	uint32_t seq;
	uoff_t offset;
	int ret;

	ret = mail_index_transaction_commit(&t->trans, &seq, &offset);
	if (ret < 0)
		mail_storage_set_index_error(t->ibox);
	else {
		if (seq != 0) {
			t->ibox->commit_log_file_seq = seq;
			t->ibox->commit_log_file_offset = offset;
		}
	}

	index_transaction_free(t);
	return ret;
}

void index_transaction_rollback(struct mailbox_transaction_context *_t)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;

	mail_index_transaction_rollback(&t->trans);
	index_transaction_free(t);
}
