/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "index-storage.h"
#include "index-mail.h"

void index_transaction_init(struct index_transaction_context *t,
			    struct index_mailbox *ibox)
{
	t->mailbox_ctx.box = &ibox->box;
	t->ibox = ibox;

	array_create(&t->mailbox_ctx.module_contexts, default_pool,
		     sizeof(void *), 5);

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

int index_transaction_finish_commit(struct index_transaction_context *t,
				    uint32_t *log_file_seq_r,
				    uoff_t *log_file_offset_r)
{
	int ret;

	ret = t->super.commit(t->trans, log_file_seq_r, log_file_offset_r);
	if (ret < 0)
		mail_storage_set_index_error(t->ibox);
	else {
		if (*log_file_seq_r != 0) {
			t->ibox->commit_log_file_seq = *log_file_seq_r;
			t->ibox->commit_log_file_offset = *log_file_offset_r;
		}
	}

	index_transaction_free(t);
	return ret;
}

void index_transaction_finish_rollback(struct index_transaction_context *t)
{
	t->super.rollback(t->trans);
	index_transaction_free(t);
}

struct mailbox_transaction_context *
index_transaction_begin(struct mailbox *box,
			enum mailbox_transaction_flags flags)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	struct mail_index_transaction *t;
	struct index_transaction_context *it;

	if (!box->opened)
		index_storage_mailbox_open(ibox);

	t = mail_index_transaction_begin(ibox->view,
		(flags & MAILBOX_TRANSACTION_FLAG_HIDE) != 0,
		(flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	it = MAIL_STORAGE_CONTEXT(t);
	if (it == NULL) {
		i_panic("mail storage transaction context mising for type %s",
			box->storage->name);
	}
	it->flags = flags;
	return &it->mailbox_ctx;
}

int index_transaction_commit(struct mailbox_transaction_context *_t,
			     enum mailbox_sync_flags flags,
			     uint32_t *first_saved_uid_r,
			     uint32_t *last_saved_uid_r)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	struct mail_index_transaction *itrans = t->trans;
	uint32_t seq;
	uoff_t offset;

	t->commit_flags = flags;
	if (mail_index_transaction_commit(&itrans, &seq, &offset) < 0)
		return -1;

	if (t->first_saved_uid <= t->last_saved_uid) {
		*first_saved_uid_r = t->first_saved_uid;
		*last_saved_uid_r = t->last_saved_uid;
	}
	return 0;
}

void index_transaction_rollback(struct mailbox_transaction_context *_t)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	struct mail_index_transaction *itrans = t->trans;

	mail_index_transaction_rollback(&itrans);
}
