/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "index-storage.h"
#include "index-mail.h"

static void index_transaction_free(struct index_transaction_context *t)
{
	mail_cache_view_close(t->cache_view);
	mail_index_view_close(&t->mailbox_ctx.view);
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
		it->super.rollback(index_trans);
	else {
		if (it->super.commit(index_trans, result_r) < 0) {
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

	i_assert(it->mail_ref_count == 0);
	it->super.rollback(t);
	index_transaction_free(it);
}

void index_transaction_init(struct index_transaction_context *it,
			    struct mailbox *box,
			    enum mailbox_transaction_flags flags)
{
	struct mailbox_transaction_context *t = &it->mailbox_ctx;
	enum mail_index_transaction_flags trans_flags;

	i_assert(box->opened);

	trans_flags = MAIL_INDEX_TRANSACTION_FLAG_AVOID_FLAG_UPDATES;
	if ((flags & MAILBOX_TRANSACTION_FLAG_HIDE) != 0)
		trans_flags |= MAIL_INDEX_TRANSACTION_FLAG_HIDE;
	if ((flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0)
		trans_flags |= MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL;
	if ((flags & MAILBOX_TRANSACTION_FLAG_REFRESH) != 0)
		(void)mail_index_refresh(box->index);

	t->box = box;
	t->itrans = mail_index_transaction_begin(box->view, trans_flags);
	t->view = mail_index_transaction_open_updated_view(t->itrans);

	array_create(&t->module_contexts, default_pool,
		     sizeof(void *), 5);

	it->cache_view = mail_cache_view_open(box->cache, t->view);
	it->cache_trans = mail_cache_get_transaction(it->cache_view, t->itrans);

	t->cache_view = it->cache_view;
	t->cache_trans = it->cache_trans;

	/* set up after mail_cache_get_transaction(), so that we'll still
	   have the cache_trans available in _index_commit() */
	it->super = t->itrans->v;
	t->itrans->v.commit = index_transaction_index_commit;
	t->itrans->v.rollback = index_transaction_index_rollback;
	MODULE_CONTEXT_SET(t->itrans, mail_storage_mail_index_module, it);
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

int index_transaction_commit(struct mailbox_transaction_context *t,
			     struct mail_transaction_commit_changes *changes_r)
{
	struct mailbox *box = t->box;
	struct mail_index_transaction *itrans = t->itrans;
	struct mail_index_transaction_commit_result result;
	int ret;

	memset(changes_r, 0, sizeof(*changes_r));
	changes_r->pool = pool_alloconly_create(MEMPOOL_GROWING
						"transaction changes", 512);
	p_array_init(&changes_r->saved_uids, changes_r->pool, 32);
	t->changes = changes_r;

	ret = mail_index_transaction_commit_full(&itrans, &result);
	t = NULL;

	if (ret < 0 && mail_index_is_deleted(box->index))
		mailbox_set_deleted(box);

	changes_r->ignored_modseq_changes = result.ignored_modseq_changes;
	return ret;
}

void index_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct mail_index_transaction *itrans = t->itrans;

	mail_index_transaction_rollback(&itrans);
}

void index_transaction_set_max_modseq(struct mailbox_transaction_context *t,
				      uint64_t max_modseq,
				      ARRAY_TYPE(seq_range) *seqs)
{
	mail_index_transaction_set_max_modseq(t->itrans, max_modseq, seqs);
}
