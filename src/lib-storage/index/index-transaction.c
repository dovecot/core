/* Copyright (c) 2003-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "dict.h"
#include "index-storage.h"
#include "index-sync-private.h"
#include "index-mail.h"

static void index_transaction_free(struct mailbox_transaction_context *t)
{
	if (t->view_pvt != NULL)
		mail_index_view_close(&t->view_pvt);
	mail_cache_view_close(&t->cache_view);
	mail_index_view_close(&t->view);
	if (array_is_created(&t->pvt_saves))
		array_free(&t->pvt_saves);
	array_free(&t->module_contexts);
	i_free(t);
}

static int
index_transaction_index_commit(struct mail_index_transaction *index_trans,
			       struct mail_index_transaction_commit_result *result_r)
{
	struct mailbox_transaction_context *t =
		MAIL_STORAGE_CONTEXT(index_trans);
	struct index_mailbox_sync_pvt_context *pvt_sync_ctx = NULL;
	int ret = 0;

	if (t->nontransactional_changes)
		t->changes->changed = TRUE;

	if (t->attr_pvt_trans != NULL) {
		if (dict_transaction_commit(&t->attr_pvt_trans) < 0) {
			mail_storage_set_internal_error(t->box->storage);
			ret = -1;
		}
	}
	if (t->attr_shared_trans != NULL) {
		if (dict_transaction_commit(&t->attr_shared_trans) < 0) {
			mail_storage_set_internal_error(t->box->storage);
			ret = -1;
		}
	}

	if (t->save_ctx != NULL) {
		if (ret < 0) {
			t->box->v.transaction_save_rollback(t->save_ctx);
			t->save_ctx = NULL;
		} else if (t->box->v.transaction_save_commit_pre(t->save_ctx) < 0) {
			t->save_ctx = NULL;
			ret = -1;
		} else {
			t->changes->changed = TRUE;
		}
	}

	if (array_is_created(&t->pvt_saves)) {
		if (index_mailbox_sync_pvt_init(t->box, TRUE, &pvt_sync_ctx) < 0)
			ret = -1;
	}

	i_assert(t->mail_ref_count == 0);
	if (ret < 0)
		t->super.rollback(index_trans);
	else {
		if (t->super.commit(index_trans, result_r) < 0) {
			mailbox_set_index_error(t->box);
			ret = -1;
		} else if (result_r->commit_size > 0) {
			/* something was written to the transaction log */
			t->changes->changed = TRUE;
		}
	}

	if (t->save_ctx != NULL)
		t->box->v.transaction_save_commit_post(t->save_ctx, result_r);

	if (pvt_sync_ctx != NULL) {
		if (index_mailbox_sync_pvt_newmails(pvt_sync_ctx, t) < 0) {
			/* failed to add private flags. a bit too late to
			   return failure though, so just ignore silently */
		}
		index_mailbox_sync_pvt_deinit(&pvt_sync_ctx);
	}

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

static enum mail_index_transaction_flags
index_transaction_flags_get(enum mailbox_transaction_flags flags)
{
	enum mail_index_transaction_flags itrans_flags;

	itrans_flags = MAIL_INDEX_TRANSACTION_FLAG_AVOID_FLAG_UPDATES;
	if ((flags & MAILBOX_TRANSACTION_FLAG_HIDE) != 0)
		itrans_flags |= MAIL_INDEX_TRANSACTION_FLAG_HIDE;
	if ((flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0)
		itrans_flags |= MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL;
	if ((flags & MAILBOX_TRANSACTION_FLAG_SYNC) != 0)
		itrans_flags |= MAIL_INDEX_TRANSACTION_FLAG_SYNC;
	return itrans_flags;
}

void index_transaction_init_pvt(struct mailbox_transaction_context *t)
{
	enum mail_index_transaction_flags itrans_flags;

	if (t->box->view_pvt == NULL || t->itrans_pvt != NULL)
		return;

	itrans_flags = index_transaction_flags_get(t->flags);
	t->itrans_pvt = mail_index_transaction_begin(t->box->view_pvt,
						     itrans_flags);
	t->view_pvt = mail_index_transaction_open_updated_view(t->itrans_pvt);
}

void index_transaction_init(struct mailbox_transaction_context *t,
			    struct mailbox *box,
			    enum mailbox_transaction_flags flags)
{
	enum mail_index_transaction_flags itrans_flags;

	i_assert(box->opened);

	itrans_flags = index_transaction_flags_get(flags);
	if ((flags & MAILBOX_TRANSACTION_FLAG_REFRESH) != 0)
		mail_index_refresh(box->index);

	t->box = box;
	t->itrans = mail_index_transaction_begin(box->view, itrans_flags);
	t->view = mail_index_transaction_open_updated_view(t->itrans);

	array_create(&t->module_contexts, default_pool,
		     sizeof(void *), 5);

	t->cache_view = mail_cache_view_open(box->cache, t->view);
	t->cache_trans = mail_cache_get_transaction(t->cache_view, t->itrans);

	if ((flags & MAILBOX_TRANSACTION_FLAG_NO_CACHE_DEC) != 0)
		mail_cache_view_update_cache_decisions(t->cache_view, FALSE);

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
	int ret = 0;

	memset(changes_r, 0, sizeof(*changes_r));
	changes_r->pool = pool_alloconly_create(MEMPOOL_GROWING
						"transaction changes", 512);
	p_array_init(&changes_r->saved_uids, changes_r->pool, 32);
	t->changes = changes_r;

	if (t->itrans_pvt != NULL)
		ret = mail_index_transaction_commit(&t->itrans_pvt);
	if (mail_index_transaction_commit_full(&itrans, &result) < 0)
		ret = -1;
	t = NULL;

	if (ret < 0 && mail_index_is_deleted(box->index))
		mailbox_set_deleted(box);

	changes_r->ignored_modseq_changes = result.ignored_modseq_changes;
	return ret;
}

void index_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct mail_index_transaction *itrans = t->itrans;

	if (t->itrans_pvt != NULL)
		mail_index_transaction_rollback(&t->itrans_pvt);
	mail_index_transaction_rollback(&itrans);
}
