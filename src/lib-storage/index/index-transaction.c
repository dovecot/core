/* Copyright (c) 2003-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "index-storage.h"
#include "index-mail.h"

static void index_transaction_free(struct index_transaction_context *t)
{
	mail_cache_view_close(t->cache_view);
	mail_index_view_close(&t->trans_view);
	array_free(&t->mailbox_ctx.module_contexts);
	i_free(t);
}

static int
index_transaction_index_commit(struct mail_index_transaction *index_trans,
			       struct mail_index_transaction_commit_result *result_r)
{
	struct index_transaction_context *it =
		MAIL_STORAGE_CONTEXT(index_trans);
	struct mailbox_transaction_context *t = &it->mailbox_ctx;
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(t->box);
	int ret = 0;

	if (t->save_ctx != NULL) {
		if (ibox->save_commit_pre(t->save_ctx) < 0) {
			t->save_ctx = NULL;
			ret = -1;
		}
	}

	i_assert(it->mail_ref_count == 0);
	if (ret < 0)
		it->super.rollback(it->trans);
	else {
		if (it->super.commit(it->trans, result_r) < 0) {
			mail_storage_set_index_error(t->box);
			ret = -1;
		}
	}

	if (t->save_ctx != NULL)
		ibox->save_commit_post(t->save_ctx, result_r);

	index_transaction_free(it);
	return ret;
}

static void index_transaction_index_rollback(struct mail_index_transaction *t)
{
	struct index_transaction_context *it = MAIL_STORAGE_CONTEXT(t);
	struct index_mailbox_context *ibox =
		INDEX_STORAGE_CONTEXT(it->mailbox_ctx.box);

	if (it->mailbox_ctx.save_ctx != NULL)
		ibox->save_rollback(it->mailbox_ctx.save_ctx);

	it->super.rollback(it->trans);
	index_transaction_free(it);
}

void index_transaction_init(struct index_transaction_context *it,
			    struct mailbox *box,
			    enum mailbox_transaction_flags flags)
{
	enum mail_index_transaction_flags trans_flags;

	i_assert(box->opened);

	trans_flags = MAIL_INDEX_TRANSACTION_FLAG_AVOID_FLAG_UPDATES;
	if ((flags & MAILBOX_TRANSACTION_FLAG_HIDE) != 0)
		trans_flags |= MAIL_INDEX_TRANSACTION_FLAG_HIDE;
	if ((flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0)
		trans_flags |= MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL;
	if ((flags & MAILBOX_TRANSACTION_FLAG_REFRESH) != 0)
		(void)mail_index_refresh(box->index);

	it->trans = mail_index_transaction_begin(box->view, trans_flags);
	it->mailbox_ctx.box = box;

	array_create(&it->mailbox_ctx.module_contexts, default_pool,
		     sizeof(void *), 5);

	it->trans_view = mail_index_transaction_open_updated_view(it->trans);
	it->cache_view = mail_cache_view_open(box->cache, it->trans_view);
	it->cache_trans = mail_cache_get_transaction(it->cache_view, it->trans);

	/* set up after mail_cache_get_transaction(), so that we'll still
	   have the cache_trans available in _index_commit() */
	it->super = it->trans->v;
	it->trans->v.commit = index_transaction_index_commit;
	it->trans->v.rollback = index_transaction_index_rollback;
	MODULE_CONTEXT_SET(it->trans, mail_storage_mail_index_module, it);
}

struct mailbox_transaction_context *
index_transaction_begin(struct mailbox *box,
			enum mailbox_transaction_flags flags)
{
	struct index_transaction_context *it;

	it = i_new(struct index_transaction_context, 1);
	index_transaction_init(it, box, flags);
	return &it->mailbox_ctx;
}

int index_transaction_commit(struct mailbox_transaction_context *_t,
			     struct mail_transaction_commit_changes *changes_r)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	struct mailbox *box = _t->box;
	struct mail_index_transaction *itrans = t->trans;
	struct mail_index_transaction_commit_result result;
	int ret;

	memset(changes_r, 0, sizeof(*changes_r));
	changes_r->pool = pool_alloconly_create(MEMPOOL_GROWING
						"transaction changes", 512);
	p_array_init(&changes_r->saved_uids, changes_r->pool, 32);
	_t->changes = changes_r;

	ret = mail_index_transaction_commit_full(&itrans, &result);
	_t = NULL;

	if (ret < 0 && mail_index_is_deleted(box->index))
		mailbox_set_deleted(box);

	changes_r->ignored_uid_changes = result.ignored_uid_changes;
	changes_r->ignored_modseq_changes = result.ignored_modseq_changes;

	i_assert(box->transaction_count > 0 ||
		 box->view->transactions == 0);
	return ret;
}

void index_transaction_rollback(struct mailbox_transaction_context *_t)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	struct mailbox *box = _t->box;
	struct mail_index_transaction *itrans = t->trans;

	mail_index_transaction_rollback(&itrans);

	i_assert(box->transaction_count > 0 ||
		 box->view->transactions == 0);
}

void index_transaction_set_max_modseq(struct mailbox_transaction_context *_t,
				      uint64_t max_modseq,
				      ARRAY_TYPE(seq_range) *seqs)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;

	mail_index_transaction_set_max_modseq(t->trans, max_modseq, seqs);
}
