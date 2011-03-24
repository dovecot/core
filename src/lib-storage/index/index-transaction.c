/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "index-storage.h"
#include "index-mail.h"

static void index_transaction_free(struct mailbox_transaction_context *t)
{
	mail_cache_view_close(t->cache_view);
	mail_index_view_close(&t->view);
	array_free(&t->module_contexts);
	i_free(t);
}

static int
index_transaction_index_commit(struct mail_index_transaction *index_trans,
			       struct mail_index_transaction_commit_result *result_r)
{
	struct mailbox_transaction_context *t =
		MAIL_STORAGE_CONTEXT(index_trans);
	int ret = 0;

	if (t->save_ctx != NULL) {
		if (t->box->v.transaction_save_commit_pre(t->save_ctx) < 0) {
			t->save_ctx = NULL;
			ret = -1;
		}
	}

	i_assert(t->mail_ref_count == 0);
	if (ret < 0)
		t->super.rollback(index_trans);
	else {
		if (t->super.commit(index_trans, result_r) < 0) {
			mail_storage_set_index_error(t->box);
			ret = -1;
		}
	}

	if (t->save_ctx != NULL)
		t->box->v.transaction_save_commit_post(t->save_ctx, result_r);

	index_transaction_free(t);
	return ret;
}

static void
index_transaction_index_rollback(struct mail_index_transaction *index_trans)
{
	struct mailbox_transaction_context *t =
		MAIL_STORAGE_CONTEXT(index_trans);

	if (t->save_ctx != NULL)
		t->box->v.transaction_save_rollback(t->save_ctx);

	i_assert(t->mail_ref_count == 0);
	t->super.rollback(index_trans);
	index_transaction_free(t);
}

void index_transaction_init(struct mailbox_transaction_context *t,
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

	t->box = box;
	t->itrans = mail_index_transaction_begin(box->view, trans_flags);
	t->view = mail_index_transaction_open_updated_view(t->itrans);

	array_create(&t->module_contexts, default_pool,
		     sizeof(void *), 5);

	t->cache_view = mail_cache_view_open(box->cache, t->view);
	t->cache_trans = mail_cache_get_transaction(t->cache_view, t->itrans);

	/* set up after mail_cache_get_transaction(), so that we'll still
	   have the cache_trans available in _index_commit() */
	t->super = t->itrans->v;
	t->itrans->v.commit = index_transaction_index_commit;
	t->itrans->v.rollback = index_transaction_index_rollback;
	MODULE_CONTEXT_SET(t->itrans, mail_storage_mail_index_module, t);
}

struct mailbox_transaction_context *
index_transaction_begin(struct mailbox *box,
			enum mailbox_transaction_flags flags)
{
	struct mailbox_transaction_context *t;

	t = i_new(struct mailbox_transaction_context, 1);
	index_transaction_init(t, box, flags);
	return t;
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
