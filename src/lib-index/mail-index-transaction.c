/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "hook-build.h"
#include "bsearch-insert-pos.h"
#include "llist.h"
#include "mail-index-private.h"
#include "mail-transaction-log-private.h"
#include "mail-index-transaction-private.h"

static ARRAY(hook_mail_index_transaction_created_t *)
	hook_mail_index_transaction_created;

void mail_index_transaction_hook_register(hook_mail_index_transaction_created_t *hook)
{
	if (!array_is_created(&hook_mail_index_transaction_created))
		i_array_init(&hook_mail_index_transaction_created, 8);
	array_push_back(&hook_mail_index_transaction_created, &hook);
}

void mail_index_transaction_hook_unregister(hook_mail_index_transaction_created_t *hook)
{
	unsigned int idx;
	bool found = FALSE;

	i_assert(array_is_created(&hook_mail_index_transaction_created));
	for(idx = 0; idx < array_count(&hook_mail_index_transaction_created); idx++) {
		hook_mail_index_transaction_created_t *const *hook_ptr =
			array_idx(&hook_mail_index_transaction_created, idx);
		if (*hook_ptr == hook) {
			array_delete(&hook_mail_index_transaction_created, idx, 1);
			found = TRUE;
			break;
		}
	}
	i_assert(found == TRUE);
	if (array_count(&hook_mail_index_transaction_created) == 0)
		array_free(&hook_mail_index_transaction_created);
}


struct mail_index_view *
mail_index_transaction_get_view(struct mail_index_transaction *t)
{
	return t->view;
}

bool mail_index_transaction_is_expunged(struct mail_index_transaction *t,
					uint32_t seq)
{
	struct mail_transaction_expunge_guid key;

	if (!array_is_created(&t->expunges))
		return FALSE;

	if (t->expunges_nonsorted)
		mail_index_transaction_sort_expunges(t);

	key.uid = seq;
	return array_bsearch(&t->expunges, &key,
			     mail_transaction_expunge_guid_cmp) != NULL;
}

void mail_index_transaction_ref(struct mail_index_transaction *t)
{
	t->refcount++;
}

void mail_index_transaction_unref(struct mail_index_transaction **_t)
{
	struct mail_index_transaction *t = *_t;

	*_t = NULL;
	if (--t->refcount > 0)
		return;

	mail_index_transaction_reset_v(t);

	DLLIST_REMOVE(&t->view->transactions_list, t);
	array_free(&t->module_contexts);
	mail_index_view_transaction_unref(t->view);
	if (t->latest_view != NULL)
		mail_index_view_close(&t->latest_view);
	mail_index_view_close(&t->view);
	i_free(t);
}

uint32_t mail_index_transaction_get_next_uid(struct mail_index_transaction *t)
{
	const struct mail_index_header *head_hdr, *hdr;
	unsigned int offset;
	uint32_t next_uid;

	head_hdr = &t->view->index->map->hdr;
	hdr = &t->view->map->hdr;
	next_uid = t->reset || head_hdr->uid_validity != hdr->uid_validity ?
		1 : hdr->next_uid;
	if (array_is_created(&t->appends) && t->highest_append_uid != 0) {
		/* get next_uid from appends if they have UIDs. it's possible
		   that some appends have too low UIDs, they'll be caught
		   later. */
		if (next_uid <= t->highest_append_uid)
			next_uid = t->highest_append_uid + 1;
	}

	/* see if it's been updated in pre/post header changes */
	offset = offsetof(struct mail_index_header, next_uid);
	if (t->post_hdr_mask[offset] != 0) {
		hdr = (const void *)t->post_hdr_change;
		if (hdr->next_uid > next_uid)
			next_uid = hdr->next_uid;
	}
	if (t->pre_hdr_mask[offset] != 0) {
		hdr = (const void *)t->pre_hdr_change;
		if (hdr->next_uid > next_uid)
			next_uid = hdr->next_uid;
	}
	return next_uid;
}

void mail_index_transaction_lookup_latest_keywords(struct mail_index_transaction *t,
						   uint32_t seq,
						   ARRAY_TYPE(keyword_indexes) *keywords)
{
	uint32_t uid, latest_seq;

	/* seq points to the transaction's primary view */
	mail_index_lookup_uid(t->view, seq, &uid);

	/* get the latest keywords from the updated index, or fallback to the
	   primary view if the message is already expunged */
	if (t->latest_view == NULL) {
		mail_index_refresh(t->view->index);
		t->latest_view = mail_index_view_open(t->view->index);
	}
	if (mail_index_lookup_seq(t->latest_view, uid, &latest_seq))
		mail_index_lookup_keywords(t->latest_view, latest_seq, keywords);
	else
		mail_index_lookup_keywords(t->view, seq, keywords);
}

static int
mail_transaction_log_file_refresh(struct mail_index_transaction *t,
				  struct mail_transaction_log_append_ctx *ctx)
{
	struct mail_transaction_log_file *file;

	if (t->reset) {
		/* Reset the whole index, preserving only indexid. Begin by
		   rotating the log. We don't care if we skip some non-synced
		   transactions. */
		if (mail_transaction_log_rotate(t->view->index->log, TRUE) < 0)
			return -1;

		if (!MAIL_INDEX_TRANSACTION_HAS_CHANGES(t)) {
			/* we only wanted to reset */
			return 0;
		}
	}
	file = t->view->index->log->head;

	/* make sure we have everything mapped */
	if (mail_index_map(t->view->index, MAIL_INDEX_SYNC_HANDLER_HEAD) <= 0)
		return -1;

	i_assert(file->sync_offset >= file->buffer_offset);
	ctx->new_highest_modseq = file->sync_highest_modseq;
	return 1;
}

static int
mail_index_transaction_commit_real(struct mail_index_transaction *t,
				   uoff_t *commit_size_r,
				   enum mail_index_transaction_change *changes_r)
{
	struct mail_transaction_log *log = t->view->index->log;
	struct mail_transaction_log_append_ctx *ctx;
	enum mail_transaction_type trans_flags = 0;
	uint32_t log_seq1, log_seq2;
	uoff_t log_offset1, log_offset2;
	int ret;

	*changes_r = 0;

	if ((t->flags & MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL) != 0)
		trans_flags |= MAIL_TRANSACTION_EXTERNAL;
	if ((t->flags & MAIL_INDEX_TRANSACTION_FLAG_SYNC) != 0)
		trans_flags |= MAIL_TRANSACTION_SYNC;

	if (mail_transaction_log_append_begin(log->index, trans_flags, &ctx) < 0)
		return -1;
	ret = mail_transaction_log_file_refresh(t, ctx);
#ifdef DEBUG
	uint64_t expected_highest_modseq =
		mail_index_transaction_get_highest_modseq(t);
#endif
	if (ret > 0) T_BEGIN {
		mail_index_transaction_finish(t);
		mail_index_transaction_export(t, ctx, changes_r);
	} T_END;

	mail_transaction_log_get_head(log, &log_seq1, &log_offset1);
	if (mail_transaction_log_append_commit(&ctx) < 0 || ret < 0)
		return -1;
	mail_transaction_log_get_head(log, &log_seq2, &log_offset2);
	i_assert(log_seq1 == log_seq2);

#ifdef DEBUG
	i_assert(expected_highest_modseq == log->head->sync_highest_modseq);
#endif

	if (t->reset) {
		/* get rid of the old index. it might just confuse readers,
		   especially if it's broken. */
		i_unlink_if_exists(log->index->filepath);
	}

	*commit_size_r = log_offset2 - log_offset1;

	if ((t->flags & MAIL_INDEX_TRANSACTION_FLAG_HIDE) != 0 &&
	    log_offset1 != log_offset2) {
		/* mark the area covered by this transaction hidden */
		mail_index_view_add_hidden_transaction(t->view, log_seq1,
			log_offset1, log_offset2 - log_offset1);
	}
	return 0;
}

static int mail_index_transaction_commit_v(struct mail_index_transaction *t,
					   struct mail_index_transaction_commit_result *result_r)
{
	struct mail_index *index = t->view->index;
	bool changed;
	int ret;

	i_assert(t->first_new_seq >
		 mail_index_view_get_messages_count(t->view));

	changed = MAIL_INDEX_TRANSACTION_HAS_CHANGES(t) || t->reset;
	ret = !changed ? 0 :
		mail_index_transaction_commit_real(t, &result_r->commit_size,
						   &result_r->changes_mask);
	mail_transaction_log_get_head(index->log, &result_r->log_file_seq,
				      &result_r->log_file_offset);

	if (ret == 0 && !index->syncing && changed) {
		/* if we're committing a normal transaction, we want to
		   have those changes in the index mapping immediately. this
		   is especially important when committing cache offset
		   updates.

		   however if we're syncing the index now, the mapping must
		   be done later as MAIL_INDEX_SYNC_HANDLER_FILE so that
		   expunge handlers get run for the newly expunged messages
		   (and sync handlers that require HANDLER_FILE as well). */
		index->sync_commit_result = result_r;
		mail_index_refresh(index);
		index->sync_commit_result = NULL;
	}

	mail_index_transaction_unref(&t);
	return ret;
}

static void mail_index_transaction_rollback_v(struct mail_index_transaction *t)
{
        mail_index_transaction_unref(&t);
}

int mail_index_transaction_commit(struct mail_index_transaction **t)
{
	struct mail_index_transaction_commit_result result;

	return mail_index_transaction_commit_full(t, &result);
}

int mail_index_transaction_commit_full(struct mail_index_transaction **_t,
				       struct mail_index_transaction_commit_result *result_r)
{
	struct mail_index_transaction *t = *_t;
	struct mail_index *index = t->view->index;
	bool index_undeleted = t->index_undeleted;

	if (mail_index_view_is_inconsistent(t->view)) {
		mail_index_set_error_nolog(index, "View is inconsistent");
		mail_index_transaction_rollback(_t);
		return -1;
	}
	if (!index_undeleted && !t->commit_deleted_index) {
		if (t->view->index->index_deleted ||
		    (t->view->index->index_delete_requested &&
		     !t->view->index->syncing)) {
			/* no further changes allowed */
			mail_index_set_error_nolog(index, "Index is marked deleted");
			mail_index_transaction_rollback(_t);
			return -1;
		}
	}

	*_t = NULL;
	i_zero(result_r);
	if (t->v.commit(t, result_r) < 0)
		return -1;

	if (index_undeleted) {
		index->index_deleted = FALSE;
		index->index_delete_requested = FALSE;
	}
	return 0;
}

void mail_index_transaction_rollback(struct mail_index_transaction **_t)
{
	struct mail_index_transaction *t = *_t;

	*_t = NULL;
	t->v.rollback(t);
}

static struct mail_index_transaction_vfuncs trans_vfuncs = {
	mail_index_transaction_reset_v,
	mail_index_transaction_commit_v,
	mail_index_transaction_rollback_v
};

struct mail_index_transaction *
mail_index_transaction_begin(struct mail_index_view *view,
			     enum mail_index_transaction_flags flags)
{
	struct mail_index_transaction *t;

	/* don't allow syncing view while there's ongoing transactions */
	mail_index_view_transaction_ref(view);
 	mail_index_view_ref(view);

	t = i_new(struct mail_index_transaction, 1);
	t->refcount = 1;
	t->v = trans_vfuncs;
	t->view = view;
	t->flags = flags;

	if (view->syncing) {
		/* transaction view cannot work if new records are being added
		   in two places. make sure it doesn't happen. */
		t->no_appends = TRUE;
		t->first_new_seq = (uint32_t)-1;
	} else {
		t->first_new_seq =
			mail_index_view_get_messages_count(t->view) + 1;
	}

	i_array_init(&t->module_contexts,
		     I_MIN(5, mail_index_module_register.id));
	DLLIST_PREPEND(&view->transactions_list, t);

	if (array_is_created(&hook_mail_index_transaction_created)) {
	        struct hook_build_context *ctx =
			hook_build_init((void *)&t->v, sizeof(t->v));
		hook_mail_index_transaction_created_t *const *ptr;
		array_foreach(&hook_mail_index_transaction_created, ptr) {
			(*ptr)(t);
			hook_build_update(ctx, t->vlast);
		}
		t->vlast = NULL;
		hook_build_deinit(&ctx);
	}
	return t;
}
