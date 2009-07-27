/* Copyright (c) 2003-2009 Dovecot authors, see the included COPYING file */

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

	/* mail_cache_get_transaction() changes trans->v */
	t->super = t->trans->v;
}

static void index_transaction_free(struct index_transaction_context *t)
{
	mail_cache_view_close(t->cache_view);
	mail_index_view_close(&t->trans_view);
	array_free(&t->mailbox_ctx.module_contexts);
	i_free(t);
}

int index_transaction_finish_commit(struct index_transaction_context *t,
				    uint32_t *log_file_seq_r,
				    uoff_t *log_file_offset_r)
{
	int ret;

	i_assert(t->mail_ref_count == 0);

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
	i_assert(t->mail_ref_count == 0);

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
	enum mail_index_transaction_flags trans_flags;

	i_assert(box->opened);

	trans_flags = MAIL_INDEX_TRANSACTION_FLAG_AVOID_FLAG_UPDATES;
	if ((flags & MAILBOX_TRANSACTION_FLAG_HIDE) != 0)
		trans_flags |= MAIL_INDEX_TRANSACTION_FLAG_HIDE;
	if ((flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0)
		trans_flags |= MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL;
	if ((flags & MAILBOX_TRANSACTION_FLAG_REFRESH) != 0)
		(void)mail_index_refresh(ibox->index);
	t = mail_index_transaction_begin(ibox->view, trans_flags);

	it = MAIL_STORAGE_CONTEXT(t);
	if (it == NULL) {
		i_panic("mail storage transaction context mising for type %s",
			box->storage->name);
	}
	it->flags = flags;
	return &it->mailbox_ctx;
}

int index_transaction_commit(struct mailbox_transaction_context *_t,
			     struct mail_transaction_commit_changes *changes_r)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	struct mail_index_transaction *itrans = t->trans;

	memset(changes_r, 0, sizeof(*changes_r));
	changes_r->pool = pool_alloconly_create("transaction changes", 1024);
	p_array_init(&changes_r->saved_uids, changes_r->pool, 32);
	p_array_init(&changes_r->updated_uids, changes_r->pool, 32);
	_t->changes = changes_r;

	return mail_index_transaction_commit(&itrans);
}

void index_transaction_rollback(struct mailbox_transaction_context *_t)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	struct mail_index_transaction *itrans = t->trans;

	mail_index_transaction_rollback(&itrans);
}

void index_transaction_set_max_modseq(struct mailbox_transaction_context *_t,
				      uint64_t max_modseq,
				      ARRAY_TYPE(seq_range) *seqs)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;

	mail_index_transaction_set_max_modseq(t->trans, max_modseq, seqs);
}
