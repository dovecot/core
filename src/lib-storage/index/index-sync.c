/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "seq-range-array.h"
#include "ioloop.h"
#include "array.h"
#include "index-mailbox-size.h"
#include "index-sync-private.h"
#include "mailbox-recent-flags.h"

struct index_storage_list_index_record {
	uint32_t size;
	uint32_t mtime;
};

enum mail_index_sync_flags index_storage_get_sync_flags(struct mailbox *box)
{
	enum mail_index_sync_flags sync_flags = 0;

	if ((box->flags & MAILBOX_FLAG_DROP_RECENT) != 0)
		sync_flags |= MAIL_INDEX_SYNC_FLAG_DROP_RECENT;
	if (box->deleting) {
		sync_flags |= box->delete_sync_check ?
			MAIL_INDEX_SYNC_FLAG_TRY_DELETING_INDEX :
			MAIL_INDEX_SYNC_FLAG_DELETING_INDEX;
	}
	return sync_flags;
}

bool index_mailbox_want_full_sync(struct mailbox *box,
				  enum mailbox_sync_flags flags)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);

	if ((flags & MAILBOX_SYNC_FLAG_FAST) != 0 &&
	    ioloop_time < ibox->sync_last_check + MAILBOX_FULL_SYNC_INTERVAL)
		return FALSE;

	if ((flags & MAILBOX_SYNC_FLAG_FAST) != 0 &&
	    (box->flags & MAILBOX_FLAG_SAVEONLY) != 0) {
		/* lib-lda is syncing the mailbox after saving a mail.
		   it only wants to find the new mail for potentially copying
		   to other mailboxes. that's mainly an optimization, and since
		   the mail was most likely already added to index we don't
		   need to do a full sync to find it. the main benefit here is
		   to avoid a very costly sync with a large Maildir/new/ */
		return FALSE;
	}

	if (box->to_notify != NULL)
		timeout_reset(box->to_notify);
	ibox->sync_last_check = ioloop_time;
	return TRUE;
}

static void index_view_sync_recs_get(struct index_mailbox_sync_context *ctx)
{
	struct mail_index_view_sync_rec sync_rec;
	uint32_t seq1, seq2;

	i_array_init(&ctx->flag_updates, 128);
	i_array_init(&ctx->hidden_updates, 32);
	while (mail_index_view_sync_next(ctx->sync_ctx, &sync_rec)) {
		switch (sync_rec.type) {
		case MAIL_INDEX_VIEW_SYNC_TYPE_MODSEQ:
		case MAIL_INDEX_VIEW_SYNC_TYPE_FLAGS:
			if (!mail_index_lookup_seq_range(ctx->ctx.box->view,
							 sync_rec.uid1,
							 sync_rec.uid2,
							 &seq1, &seq2))
				break;

			if (!sync_rec.hidden &&
			    sync_rec.type == MAIL_INDEX_VIEW_SYNC_TYPE_FLAGS) {
				seq_range_array_add_range(&ctx->flag_updates,
							  seq1, seq2);
			} else {
				seq_range_array_add_range(&ctx->hidden_updates,
							  seq1, seq2);
			}
			break;
		}
	}
}

static void
index_view_sync_cleanup_updates(struct index_mailbox_sync_context *ctx)
{
	/* remove expunged messages from flag updates */
	if (ctx->expunges != NULL) {
		seq_range_array_remove_seq_range(&ctx->flag_updates,
						 ctx->expunges);
		seq_range_array_remove_seq_range(&ctx->hidden_updates,
						 ctx->expunges);
	}
	/* remove flag updates from hidden updates */
	seq_range_array_remove_seq_range(&ctx->hidden_updates,
					 &ctx->flag_updates);
}

struct mailbox_sync_context *
index_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags,
			bool failed)
{
        struct index_mailbox_sync_context *ctx;
	struct index_mailbox_sync_pvt_context *pvt_ctx;
	enum mail_index_view_sync_flags sync_flags = 0;

	ctx = i_new(struct index_mailbox_sync_context, 1);
	ctx->ctx.box = box;
	ctx->ctx.flags = flags;

	if (failed) {
		ctx->failed = TRUE;
		return &ctx->ctx;
	}

	if ((flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) != 0)
		sync_flags |= MAIL_INDEX_VIEW_SYNC_FLAG_NOEXPUNGES;

	if ((flags & MAILBOX_SYNC_FLAG_FIX_INCONSISTENT) != 0) {
		sync_flags |= MAIL_INDEX_VIEW_SYNC_FLAG_FIX_INCONSISTENT;
		ctx->messages_count = 0;
	} else {
		ctx->messages_count =
			mail_index_view_get_messages_count(box->view);
	}

	if ((flags & MAILBOX_SYNC_FLAG_FAST) != 0) {
		/* we most likely did a fast sync. refresh the index anyway in
		   case there were some new changes. */
		(void)mail_index_refresh(box->index);
	}
	ctx->sync_ctx = mail_index_view_sync_begin(box->view, sync_flags);
	if ((flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) == 0) {
		mail_index_view_sync_get_expunges(ctx->sync_ctx,
						  &ctx->expunges);
		ctx->expunge_pos = array_count(ctx->expunges);
	}
	index_view_sync_recs_get(ctx);
	index_sync_search_results_expunge(ctx);

	/* sync private index if needed. it doesn't use box->view, so it
	   doesn't matter if it's called at _sync_init() or _sync_deinit().
	   however we also need to know if any private flags have changed
	   since last sync, so we need to call it before _sync_next() calls. */
	if (index_mailbox_sync_pvt_init(box, FALSE, &pvt_ctx) > 0) {
		(void)index_mailbox_sync_pvt_view(pvt_ctx, &ctx->flag_updates,
						  &ctx->hidden_updates);
		index_mailbox_sync_pvt_deinit(&pvt_ctx);

	}
	index_view_sync_cleanup_updates(ctx);
	return &ctx->ctx;
}

static bool
index_mailbox_sync_next_expunge(struct index_mailbox_sync_context *ctx,
				struct mailbox_sync_rec *sync_rec_r)
{
	const struct seq_range *range;

	if (ctx->expunge_pos == 0)
		return FALSE;

	/* expunges is a sorted array of sequences. it's easiest for
	   us to print them from end to beginning. */
	ctx->expunge_pos--;
	range = array_idx(ctx->expunges, ctx->expunge_pos);
	i_assert(range->seq2 <= ctx->messages_count);

	mailbox_recent_flags_expunge_seqs(ctx->ctx.box, range->seq1, range->seq2);
	ctx->messages_count -= range->seq2 - range->seq1 + 1;

	sync_rec_r->seq1 = range->seq1;
	sync_rec_r->seq2 = range->seq2;
	sync_rec_r->type = MAILBOX_SYNC_TYPE_EXPUNGE;
	return TRUE;
}

bool index_mailbox_sync_next(struct mailbox_sync_context *_ctx,
			     struct mailbox_sync_rec *sync_rec_r)
{
	struct index_mailbox_sync_context *ctx =
		(struct index_mailbox_sync_context *)_ctx;
	const struct seq_range *range;
	unsigned int count;

	if (ctx->failed)
		return FALSE;

	range = array_get(&ctx->flag_updates, &count);
	if (ctx->flag_update_idx < count) {
		sync_rec_r->type = MAILBOX_SYNC_TYPE_FLAGS;
		sync_rec_r->seq1 = range[ctx->flag_update_idx].seq1;
		sync_rec_r->seq2 = range[ctx->flag_update_idx].seq2;
		ctx->flag_update_idx++;
		return TRUE;
	}
	if ((_ctx->box->enabled_features & MAILBOX_FEATURE_CONDSTORE) != 0) {
		/* hidden flag changes' MODSEQs still need to be returned */
		range = array_get(&ctx->hidden_updates, &count);
		if (ctx->hidden_update_idx < count) {
			sync_rec_r->type = MAILBOX_SYNC_TYPE_MODSEQ;
			sync_rec_r->seq1 = range[ctx->hidden_update_idx].seq1;
			sync_rec_r->seq2 = range[ctx->hidden_update_idx].seq2;
			ctx->hidden_update_idx++;
			return TRUE;
		}
	}

	return index_mailbox_sync_next_expunge(ctx, sync_rec_r);
}

static void
index_mailbox_expunge_unseen_recent(struct index_mailbox_sync_context *ctx)
{
	struct mailbox *box = ctx->ctx.box;
	struct mail_index_view *view = ctx->ctx.box->view;
	const struct mail_index_header *hdr;
	uint32_t seq, start_uid, uid;

	if (!array_is_created(&box->recent_flags))
		return;

	/* expunges array contained expunges for the messages that were already
	   visible in this view, but append+expunge would be invisible.
	   recent_flags may however contain the append UID, so we'll have to
	   remove it separately */
	hdr = mail_index_get_header(view);
	if (ctx->messages_count == 0)
		uid = 0;
	else if (ctx->messages_count <= hdr->messages_count)
		mail_index_lookup_uid(view, ctx->messages_count, &uid);
	else {
		i_assert(mail_index_view_is_inconsistent(view));
		return;
	}

	for (seq = ctx->messages_count + 1; seq <= hdr->messages_count; seq++) {
		start_uid = uid;
		mail_index_lookup_uid(view, seq, &uid);
		if (start_uid + 1 > uid - 1)
			continue;

		box->recent_flags_count -=
			seq_range_array_remove_range(&box->recent_flags,
						     start_uid + 1, uid - 1);
	}

	if (uid + 1 < hdr->next_uid) {
		box->recent_flags_count -=
			seq_range_array_remove_range(&box->recent_flags,
						     uid + 1,
						     hdr->next_uid - 1);
	}
#ifdef DEBUG
	if (!mail_index_view_is_inconsistent(view)) {
		const struct seq_range *range;
		unsigned int i, count;

		range = array_get(&box->recent_flags, &count);
		for (i = 0; i < count; i++) {
			for (uid = range[i].seq1; uid <= range[i].seq2; uid++) {
				if (uid >= hdr->next_uid)
					break;
				(void)mail_index_lookup_seq(view, uid, &seq);
				i_assert(seq != 0);
			}
		}
	}
#endif
}

void index_sync_update_recent_count(struct mailbox *box)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);
	const struct mail_index_header *hdr;
	uint32_t seq1, seq2;

	hdr = mail_index_get_header(box->view);
	if (hdr->first_recent_uid < ibox->recent_flags_prev_first_recent_uid) {
		mailbox_set_critical(box,
			"first_recent_uid unexpectedly shrank: %u -> %u",
			ibox->recent_flags_prev_first_recent_uid,
			hdr->first_recent_uid);
		mailbox_recent_flags_reset(box);
	}

	if (hdr->first_recent_uid > box->recent_flags_prev_uid ||
	    hdr->next_uid > ibox->recent_flags_last_check_nextuid) {
		ibox->recent_flags_prev_first_recent_uid = hdr->first_recent_uid;
		ibox->recent_flags_last_check_nextuid = hdr->next_uid;
		if (mail_index_lookup_seq_range(box->view,
						hdr->first_recent_uid,
						hdr->next_uid,
						&seq1, &seq2)) {
			mailbox_recent_flags_set_seqs(box, box->view,
						      seq1, seq2);
		}
	}
}

static void index_mailbox_sync_free(struct index_mailbox_sync_context *ctx)
{
	if (array_is_created(&ctx->flag_updates))
		array_free(&ctx->flag_updates);
	if (array_is_created(&ctx->hidden_updates))
		array_free(&ctx->hidden_updates);
	if (array_is_created(&ctx->all_flag_update_uids))
		array_free(&ctx->all_flag_update_uids);
	i_free(ctx);
}

int index_mailbox_sync_deinit(struct mailbox_sync_context *_ctx,
			      struct mailbox_sync_status *status_r)
{
	struct index_mailbox_sync_context *ctx =
		(struct index_mailbox_sync_context *)_ctx;
	struct mailbox_sync_rec sync_rec;
	bool delayed_expunges = FALSE;
	int ret = ctx->failed ? -1 : 0;

	/* finish handling expunges, so we don't break when updating
	   recent flags */
	while (index_mailbox_sync_next_expunge(ctx, &sync_rec)) ;

	/* convert sequences to uids before syncing view */
	index_sync_search_results_uidify(ctx);

	if (ctx->sync_ctx != NULL) {
		if (mail_index_view_sync_commit(&ctx->sync_ctx,
						&delayed_expunges) < 0) {
			mailbox_set_index_error(_ctx->box);
			ret = -1;
		}
	}
	if (ret < 0) {
		index_mailbox_sync_free(ctx);
		return -1;
	}
	index_mailbox_expunge_unseen_recent(ctx);

	if ((_ctx->box->flags & MAILBOX_FLAG_DROP_RECENT) == 0 &&
	    _ctx->box->opened) {
		/* mailbox syncing didn't necessarily update our recent state */
		index_sync_update_recent_count(_ctx->box);
	}

	if (status_r != NULL)
		status_r->sync_delayed_expunges = delayed_expunges;

	/* update search results after private index is updated */
	index_sync_search_results_update(ctx);
	/* update vsize header if wanted */
	index_mailbox_vsize_update_appends(_ctx->box);

	if (ret == 0 && mail_index_view_is_inconsistent(_ctx->box->view)) {
		/* we probably had MAILBOX_SYNC_FLAG_FIX_INCONSISTENT set,
		   but the view got broken in the middle. FIXME: We could
		   attempt to fix it automatically. In any case now the view
		   isn't usable and we can't return success. */
		mailbox_set_index_error(_ctx->box);
		ret = -1;
	}

	index_mailbox_sync_free(ctx);
	return ret;
}

bool index_keyword_array_cmp(const ARRAY_TYPE(keyword_indexes) *k1,
			     const ARRAY_TYPE(keyword_indexes) *k2)
{
	const unsigned int *idx1, *idx2;
	unsigned int i, j, count1, count2;

	if (!array_is_created(k1))
		return !array_is_created(k2) || array_count(k2) == 0;
	if (!array_is_created(k2))
		return array_count(k1) == 0;

	/* The arrays may not be sorted, but they usually are. Optimize for
	   the assumption that they are */
	idx1 = array_get(k1, &count1);
	idx2 = array_get(k2, &count2);

	if (count1 != count2)
		return FALSE;

	for (i = 0; i < count1; i++) {
		if (idx1[i] != idx2[i]) {
			/* not found / unsorted array. check. */
			for (j = 0; j < count1; j++) {
				if (idx1[i] == idx2[j])
					break;
			}
			if (j == count1)
				return FALSE;
		}
	}
	return TRUE;
}

enum mailbox_sync_type index_sync_type_convert(enum mail_index_sync_type type)
{
	enum mailbox_sync_type ret = 0;

	if ((type & MAIL_INDEX_SYNC_TYPE_EXPUNGE) != 0)
		ret |= MAILBOX_SYNC_TYPE_EXPUNGE;
	if ((type & (MAIL_INDEX_SYNC_TYPE_FLAGS |
		     MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD |
		     MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE)) != 0)
		ret |= MAILBOX_SYNC_TYPE_FLAGS;
	return ret;
}

static uint32_t
index_list_get_ext_id(struct mailbox *box, struct mail_index_view *view)
{
	struct index_mailbox_context *ibox = INDEX_STORAGE_CONTEXT(box);

	if (ibox->list_index_sync_ext_id == (uint32_t)-1) {
		ibox->list_index_sync_ext_id =
			mail_index_ext_register(mail_index_view_get_index(view),
				"index sync", 0,
				sizeof(struct index_storage_list_index_record),
				sizeof(uint32_t));
	}
	return ibox->list_index_sync_ext_id;
}

enum index_storage_list_change
index_storage_list_index_has_changed_full(struct mailbox *box,
					  struct mail_index_view *list_view,
					  uint32_t seq)
{
	const struct index_storage_list_index_record *rec;
	const void *data;
	const char *dir, *path;
	struct stat st;
	uint32_t ext_id;
	bool expunged;
	int ret;

	if (mail_index_is_in_memory(mail_index_view_get_index(list_view)))
		return INDEX_STORAGE_LIST_CHANGE_INMEMORY;

	ext_id = index_list_get_ext_id(box, list_view);
	mail_index_lookup_ext(list_view, seq, ext_id, &data, &expunged);
	rec = data;

	if (rec == NULL || expunged || rec->size == 0 || rec->mtime == 0) {
		/* doesn't exist / not synced */
		return INDEX_STORAGE_LIST_CHANGE_NORECORD;
	}
	if (box->storage->set->mailbox_list_index_very_dirty_syncs)
		return INDEX_STORAGE_LIST_CHANGE_NONE;

	ret = mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX, &dir);
	if (ret < 0)
		return INDEX_STORAGE_LIST_CHANGE_ERROR;
	i_assert(ret > 0);

	path = t_strconcat(dir, "/", box->index_prefix, ".log", NULL);
	if (stat(path, &st) < 0) {
		if (errno == ENOENT)
			return INDEX_STORAGE_LIST_CHANGE_NOT_IN_FS;
		mailbox_set_critical(box, "stat(%s) failed: %m", path);
		return INDEX_STORAGE_LIST_CHANGE_ERROR;
	}
	if (rec->size != (st.st_size & 0xffffffffU))
		return INDEX_STORAGE_LIST_CHANGE_SIZE_CHANGED;
	if (rec->mtime != (st.st_mtime & 0xffffffffU))
		return INDEX_STORAGE_LIST_CHANGE_MTIME_CHANGED;
	return INDEX_STORAGE_LIST_CHANGE_NONE;
}

int index_storage_list_index_has_changed(struct mailbox *box,
					 struct mail_index_view *list_view,
					 uint32_t seq, bool quick ATTR_UNUSED)
{
	switch (index_storage_list_index_has_changed_full(box, list_view, seq)) {
	case INDEX_STORAGE_LIST_CHANGE_ERROR:
		return -1;
	case INDEX_STORAGE_LIST_CHANGE_NONE:
		return 0;
	default:
		return 1;
	}
}

void index_storage_list_index_update_sync(struct mailbox *box,
					  struct mail_index_transaction *trans,
					  uint32_t seq)
{
	struct mail_index_view *list_view;
	const struct index_storage_list_index_record *old_rec;
	struct index_storage_list_index_record new_rec;
	const void *data;
	const char *dir, *path;
	struct stat st;
	uint32_t ext_id;
	bool expunged;
	int ret;

	list_view = mail_index_transaction_get_view(trans);
	if (mail_index_is_in_memory(mail_index_view_get_index(list_view)))
		return;

	/* get the current record */
	ext_id = index_list_get_ext_id(box, list_view);
	mail_index_lookup_ext(list_view, seq, ext_id, &data, &expunged);
	if (expunged)
		return;
	old_rec = data;

	ret = mailbox_get_path_to(box, MAILBOX_LIST_PATH_TYPE_INDEX, &dir);
	if (ret < 0)
		return;
	i_assert(ret > 0);

	path = t_strconcat(dir, "/", box->index_prefix, ".log", NULL);
	if (stat(path, &st) < 0) {
		mailbox_set_critical(box, "stat(%s) failed: %m", path);
		return;
	}

	i_zero(&new_rec);
	new_rec.size = st.st_size & 0xffffffffU;
	new_rec.mtime = st.st_mtime & 0xffffffffU;

	if (old_rec == NULL ||
	    memcmp(old_rec, &new_rec, sizeof(*old_rec)) != 0)
		mail_index_update_ext(trans, seq, ext_id, &new_rec, NULL);
}
