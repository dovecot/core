/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"

void index_transaction_init(struct index_transaction_context *t,
			    struct index_mailbox *ibox, int hide)
{
	t->mailbox_ctx.box = &ibox->box;
	t->ibox = ibox;
	t->trans = mail_index_transaction_begin(ibox->view, hide);
	t->trans_view = mail_index_transaction_open_updated_view(t->trans);
	t->cache_view = mail_cache_view_open(ibox->cache, t->trans_view);
	t->cache_trans = mail_cache_get_transaction(t->cache_view, t->trans);
}

static void index_transaction_free(struct index_transaction_context *t)
{
	mail_cache_view_close(t->cache_view);
	mail_index_view_close(t->trans_view);
	mail_index_view_unlock(t->ibox->view);

	if (t->fetch_mail.pool != NULL)
		index_mail_deinit(&t->fetch_mail);
	i_free(t);
}

int index_transaction_commit(struct mailbox_transaction_context *_t)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	uint32_t seq;
	uoff_t offset;
	int ret;

	ret = mail_index_transaction_commit(t->trans, &seq, &offset);
	if (ret < 0)
		mail_storage_set_index_error(t->ibox);

	if (seq != 0) {
		t->ibox->commit_log_file_seq = seq;
		t->ibox->commit_log_file_offset = offset;
	}

	index_transaction_free(t);
	return ret;
}

void index_transaction_rollback(struct mailbox_transaction_context *_t)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;

	mail_index_transaction_rollback(t->trans);
	index_transaction_free(t);
}
