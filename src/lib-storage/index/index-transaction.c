/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"

static void index_transaction_free(struct index_transaction_context *t)
{
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

	if (t->cache_trans != NULL) 
		(void)mail_cache_transaction_commit(t->cache_trans);

	ret = mail_index_transaction_commit(t->trans, &seq, &offset);
	if (ret < 0)
		mail_storage_set_index_error(t->ibox);

	t->ibox->commit_log_file_seq = seq;
	t->ibox->commit_log_file_offset = offset;

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
