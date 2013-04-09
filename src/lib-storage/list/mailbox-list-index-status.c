/* Copyright (c) 2006-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-index-modseq.h"
#include "mailbox-list-index-storage.h"
#include "mailbox-list-index.h"

#define CACHED_STATUS_ITEMS \
	(STATUS_MESSAGES | STATUS_UNSEEN | STATUS_RECENT | \
	 STATUS_UIDNEXT | STATUS_UIDVALIDITY | STATUS_HIGHESTMODSEQ)

struct index_list_changes {
	struct mailbox_status status;
	guid_128_t guid;
	uint32_t seq;

	bool rec_changed;
	bool msgs_changed;
	bool hmodseq_changed;
};

struct index_list_storage_module index_list_storage_module =
	MODULE_CONTEXT_INIT(&mail_storage_module_register);

static int
index_list_open_view(struct mailbox *box, struct mail_index_view **view_r,
		     uint32_t *seq_r)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(box->list);
	struct mailbox_list_index_node *node;
	struct mail_index_view *view;
	uint32_t seq;
	int ret;

	if (mailbox_list_index_refresh(box->list) < 0)
		return -1;

	node = mailbox_list_index_lookup(box->list, box->name);
	if (node == NULL) {
		/* mailbox not found */
		return 0;
	}

	view = mail_index_view_open(ilist->index);
	if (!mail_index_lookup_seq(view, node->uid, &seq)) {
		/* our in-memory tree is out of sync */
		ret = 1;
	} else T_BEGIN {
		ret = box->v.list_index_has_changed == NULL ? 0 :
			box->v.list_index_has_changed(box, view, seq);
	} T_END;

	if (ret != 0) {
		/* error / mailbox has changed. we'll need to sync it. */
		mailbox_list_index_refresh_later(box->list);
		mail_index_view_close(&view);
		return ret < 0 ? -1 : 0;
	}

	*view_r = view;
	*seq_r = seq;
	return 1;
}

bool mailbox_list_index_status(struct mailbox_list *list,
			       struct mail_index_view *view,
			       uint32_t seq, enum mailbox_status_items items,
			       struct mailbox_status *status_r,
			       uint8_t *mailbox_guid)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);
	const void *data;
	bool expunged;
	bool ret = TRUE;

	if ((items & STATUS_UIDVALIDITY) != 0 || mailbox_guid != NULL) {
		const struct mailbox_list_index_record *rec;

		mail_index_lookup_ext(view, seq, ilist->ext_id,
				      &data, &expunged);
		rec = data;
		if (rec == NULL)
			ret = FALSE;
		else {
			if ((items & STATUS_UIDVALIDITY) != 0 &&
			    rec->uid_validity == 0)
				ret = FALSE;
			else
				status_r->uidvalidity = rec->uid_validity;
			if (mailbox_guid != NULL)
				memcpy(mailbox_guid, rec->guid, GUID_128_SIZE);
		}
	}

	if ((items & (STATUS_MESSAGES | STATUS_UNSEEN |
		      STATUS_RECENT | STATUS_UIDNEXT)) != 0) {
		const struct mailbox_list_index_msgs_record *rec;

		mail_index_lookup_ext(view, seq, ilist->msgs_ext_id,
				      &data, &expunged);
		rec = data;
		if (rec == NULL || rec->uidnext == 0)
			ret = FALSE;
		else {
			status_r->messages = rec->messages;
			status_r->unseen = rec->unseen;
			status_r->recent = rec->recent;
			status_r->uidnext = rec->uidnext;
		}
	}
	if ((items & STATUS_HIGHESTMODSEQ) != 0) {
		const uint64_t *rec;

		mail_index_lookup_ext(view, seq, ilist->hmodseq_ext_id,
				      &data, &expunged);
		rec = data;
		if (rec == NULL || *rec == 0)
			ret = FALSE;
		else
			status_r->highest_modseq = *rec;
	}
	return ret;
}

static int
index_list_get_cached_status(struct mailbox *box,
			     enum mailbox_status_items items,
			     struct mailbox_status *status_r)
{
	struct mail_index_view *view;
	uint32_t seq;
	int ret;

	if ((items & STATUS_UNSEEN) != 0 &&
	    (mailbox_get_private_flags_mask(box) & MAIL_SEEN) != 0) {
		/* can't get UNSEEN from list index, since each user has
		   different \Seen flags */
		return 0;
	}

	if ((ret = index_list_open_view(box, &view, &seq)) <= 0)
		return ret;

	ret = mailbox_list_index_status(box->list, view, seq, items,
					status_r, NULL) ? 1 : 0;
	mail_index_view_close(&view);
	return ret;
}

static int
index_list_get_status(struct mailbox *box, enum mailbox_status_items items,
		      struct mailbox_status *status_r)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	if ((items & ~CACHED_STATUS_ITEMS) == 0 && !box->opened) {
		if (index_list_get_cached_status(box, items, status_r) > 0)
			return 0;
		/* nonsynced / error, fallback to doing it the slow way */
	}
	return ibox->module_ctx.super.get_status(box, items, status_r);
}

static int
index_list_get_cached_guid(struct mailbox *box, guid_128_t guid_r)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(box->list);
	struct mailbox_status status;
	struct mail_index_view *view;
	uint32_t seq;
	int ret;

	if (ilist->syncing) {
		/* syncing wants to know the GUID for a new mailbox. */
		return 0;
	}

	if ((ret = index_list_open_view(box, &view, &seq)) <= 0)
		return ret;

	ret = mailbox_list_index_status(box->list, view, seq, 0,
					&status, guid_r) ? 1 : 0;
	if (ret > 0 && guid_128_is_empty(guid_r))
		ret = 0;
	mail_index_view_close(&view);
	return ret;
}

static int
index_list_get_metadata(struct mailbox *box,
			enum mailbox_metadata_items items,
			struct mailbox_metadata *metadata_r)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	if (items == MAILBOX_METADATA_GUID && !box->opened) {
		if (index_list_get_cached_guid(box, metadata_r->guid) > 0)
			return 0;
		/* nonsynced / error, fallback to doing it the slow way */
	}
	return ibox->module_ctx.super.get_metadata(box, items, metadata_r);
}

static bool
index_list_update_fill_changes(struct mailbox *box,
			       struct mail_index_view *list_view,
			       struct index_list_changes *changes_r)
{
	struct mailbox_list_index_node *node;
	struct mail_index_view *view;
	const struct mail_index_header *hdr;
	struct mailbox_metadata metadata;
	uint32_t seq1, seq2;

	memset(changes_r, 0, sizeof(*changes_r));

	node = mailbox_list_index_lookup(box->list, box->name);
	if (node == NULL)
		return FALSE;
	if (!mail_index_lookup_seq(list_view, node->uid, &changes_r->seq))
		return FALSE;

	/* get STATUS info using the latest data in index.
	   note that for shared mailboxes (with private indexes) this
	   also means that the unseen count is always the owner's
	   count, not what exists in the private index. */
	view = mail_index_view_open(box->index);
	hdr = mail_index_get_header(view);

	changes_r->status.messages = hdr->messages_count;
	changes_r->status.unseen =
		hdr->messages_count - hdr->seen_messages_count;
	changes_r->status.uidvalidity = hdr->uid_validity;
	changes_r->status.uidnext = hdr->next_uid;

	if (!mail_index_lookup_seq_range(view, hdr->first_recent_uid,
					 (uint32_t)-1, &seq1, &seq2))
		changes_r->status.recent = 0;
	else
		changes_r->status.recent = seq2 - seq1 + 1;

	changes_r->status.highest_modseq = mail_index_modseq_get_highest(view);
	if (changes_r->status.highest_modseq == 0) {
		/* modseqs not enabled yet, but we can't return 0 */
		changes_r->status.highest_modseq = 1;
	}
	mail_index_view_close(&view); hdr = NULL;

	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) == 0)
		memcpy(changes_r->guid, metadata.guid, sizeof(changes_r->guid));
	return TRUE;
}

static bool
index_list_has_changed(struct mailbox *box, struct mail_index_view *list_view,
		       struct index_list_changes *changes)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(box->list);
	struct mailbox_status old_status;
	guid_128_t old_guid;

	memset(&old_status, 0, sizeof(old_status));
	memset(old_guid, 0, sizeof(old_guid));
	(void)mailbox_list_index_status(box->list, list_view, changes->seq,
					CACHED_STATUS_ITEMS,
					&old_status, old_guid);

	changes->rec_changed =
		old_status.uidvalidity != changes->status.uidvalidity &&
		changes->status.uidvalidity != 0;
	if (!guid_128_equals(changes->guid, old_guid) &&
	    !guid_128_is_empty(changes->guid))
		changes->rec_changed = TRUE;
	changes->msgs_changed =
		old_status.messages != changes->status.messages ||
		old_status.unseen != changes->status.unseen ||
		old_status.recent != changes->status.recent ||
		old_status.uidnext != changes->status.uidnext;
	/* update highest-modseq only if they're ever been used */
	if (old_status.highest_modseq == changes->status.highest_modseq) {
		changes->hmodseq_changed = FALSE;
	} else if ((box->enabled_features & MAILBOX_FEATURE_CONDSTORE) != 0 ||
		   old_status.highest_modseq != 0) {
		changes->hmodseq_changed = TRUE;
	} else {
		const void *data;
		bool expunged;

		mail_index_lookup_ext(list_view, changes->seq,
				      ilist->hmodseq_ext_id, &data, &expunged);
		changes->hmodseq_changed = data != NULL;
	}

	if (changes->hmodseq_changed &&
	    old_status.highest_modseq != changes->status.highest_modseq)
		changes->hmodseq_changed = TRUE;

	return changes->rec_changed || changes->msgs_changed ||
		changes->hmodseq_changed;
}

static void
index_list_update(struct mailbox *box, struct mail_index_view *list_view,
		  struct mail_index_transaction *list_trans,
		  const struct index_list_changes *changes)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(box->list);

	if (changes->rec_changed) {
		struct mailbox_list_index_record rec;
		const void *old_data;
		bool expunged;

		mail_index_lookup_ext(list_view, changes->seq, ilist->ext_id,
				      &old_data, &expunged);
		i_assert(old_data != NULL);
		memcpy(&rec, old_data, sizeof(rec));

		if (changes->status.uidvalidity != 0)
			rec.uid_validity = changes->status.uidvalidity;
		if (!guid_128_is_empty(changes->guid))
			memcpy(rec.guid, changes->guid, sizeof(rec.guid));
		mail_index_update_ext(list_trans, changes->seq, ilist->ext_id,
				      &rec, NULL);
	}

	if (changes->msgs_changed) {
		struct mailbox_list_index_msgs_record msgs;

		memset(&msgs, 0, sizeof(msgs));
		msgs.messages = changes->status.messages;
		msgs.unseen = changes->status.unseen;
		msgs.recent = changes->status.recent;
		msgs.uidnext = changes->status.uidnext;

		mail_index_update_ext(list_trans, changes->seq,
				      ilist->msgs_ext_id, &msgs, NULL);
	}
	if (changes->hmodseq_changed) {
		mail_index_update_ext(list_trans, changes->seq,
				      ilist->hmodseq_ext_id,
				      &changes->status.highest_modseq, NULL);
	}
}

static int index_list_update_mailbox(struct mailbox *box)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(box->list);
	struct mail_index_sync_ctx *list_sync_ctx;
	struct mail_index_view *list_view;
	struct mail_index_transaction *list_trans;
	struct index_list_changes changes;
	int ret;

	i_assert(box->opened);

	if (ilist->syncing || ilist->updating_status)
		return 0;

	/* refresh the mailbox list index once. we can't do this again after
	   locking, because it could trigger list syncing. */
	(void)mailbox_list_index_refresh(box->list);

	/* first do a quick check while unlocked to see if anything changes */
	list_view = mail_index_view_open(ilist->index);
	if (!index_list_update_fill_changes(box, list_view, &changes))
		ret = -1;
	else if (!index_list_has_changed(box, list_view, &changes))
		ret = 0;
	else
		ret = 1;
	mail_index_view_close(&list_view);
	if (ret <= 0) {
		if (ret < 0)
			mailbox_list_index_refresh_later(box->list);
		return 0;
	}

	/* looks like there are some changes. now lock the list index and do
	   the whole thing all over again while locked. this guarantees
	   that we'll always write the latest state of the mailbox. */
	if (mail_index_sync_begin(ilist->index, &list_sync_ctx,
				  &list_view, &list_trans, 0) < 0) {
		mailbox_set_index_error(box);
		return -1;
	}
	/* refresh to latest state of the mailbox now that we're locked */
	if (mail_index_refresh(box->index) < 0) {
		mailbox_set_index_error(box);
		mail_index_sync_rollback(&list_sync_ctx);
		return -1;
	}

	if (!index_list_update_fill_changes(box, list_view, &changes))
		mailbox_list_index_refresh_later(box->list);
	else if (index_list_has_changed(box, list_view, &changes)) {
		ilist->updating_status = TRUE;
		index_list_update(box, list_view, list_trans, &changes);
		if (box->v.list_index_update_sync != NULL) {
			box->v.list_index_update_sync(box, list_trans,
						      changes.seq);
		}
		ilist->updating_status = FALSE;
	}

	if (mail_index_sync_commit(&list_sync_ctx) < 0) {
		mailbox_set_index_error(box);
		return -1;
	}
	return 0;
}

void mailbox_list_index_update_mailbox_index(struct mailbox *box,
					     const struct mailbox_update *update)
{
	struct mail_index_view *list_view;
	struct mail_index_transaction *list_trans;
	struct index_list_changes changes;
	struct mailbox_status status;
	guid_128_t mailbox_guid;
	bool guid_changed = FALSE;
	int ret;

	memset(&changes, 0, sizeof(changes));
	if ((ret = index_list_open_view(box, &list_view, &changes.seq)) <= 0)
		return;

	(void)mailbox_list_index_status(box->list, list_view, changes.seq,
					CACHED_STATUS_ITEMS, &status,
					mailbox_guid);
	if (update->uid_validity != 0) {
		changes.rec_changed = TRUE;
		changes.status.uidvalidity = update->uid_validity;
	}
	if (!guid_128_equals(update->mailbox_guid, mailbox_guid) &&
	    !guid_128_is_empty(update->mailbox_guid) &&
	    !guid_128_is_empty(mailbox_guid)) {
		changes.rec_changed = TRUE;
		memcpy(changes.guid, update->mailbox_guid, sizeof(changes.guid));
		guid_changed = TRUE;
	}
	if (guid_changed ||
	    update->uid_validity != 0 ||
	    update->min_next_uid != 0 ||
	    update->min_first_recent_uid != 0 ||
	    update->min_highest_modseq != 0) {
		/* reset status counters to 0. let the syncing later figure out
		   their correct values. */
		changes.msgs_changed = TRUE;
		changes.hmodseq_changed = TRUE;
	}
	list_trans = mail_index_transaction_begin(list_view,
					MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	index_list_update(box, list_view, list_trans, &changes);
	(void)mail_index_transaction_commit(&list_trans);
	mail_index_view_close(&list_view);
}

static int index_list_sync_deinit(struct mailbox_sync_context *ctx,
				  struct mailbox_sync_status *status_r)
{
	struct mailbox *box = ctx->box;
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	if (ibox->module_ctx.super.sync_deinit(ctx, status_r) < 0)
		return -1;
	ctx = NULL;

	(void)index_list_update_mailbox(box);
	return 0;
}

static int
index_list_transaction_commit(struct mailbox_transaction_context *t,
			      struct mail_transaction_commit_changes *changes_r)
{
	struct mailbox *box = t->box;
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	if (ibox->module_ctx.super.transaction_commit(t, changes_r) < 0)
		return -1;
	t = NULL;

	(void)index_list_update_mailbox(box);
	return 0;
}

void mailbox_list_index_status_set_info_flags(struct mailbox *box, uint32_t uid,
					      enum mailbox_info_flags *flags)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(box->list);
	struct mail_index_view *view;
	struct mailbox_status status;
	uint32_t seq;
	int ret;

	view = mail_index_view_open(ilist->index);
	if (!mail_index_lookup_seq(view, uid, &seq)) {
		/* our in-memory tree is out of sync */
		ret = 1;
	} else T_BEGIN {
		ret = box->v.list_index_has_changed == NULL ? 0 :
			box->v.list_index_has_changed(box, view, seq);
	} T_END;

	if (ret != 0) {
		/* error / not up to date. don't waste time with it. */
		mail_index_view_close(&view);
		return;
	}

	status.recent = 0;
	(void)mailbox_list_index_status(box->list, view, seq, STATUS_RECENT,
					&status, NULL);
	mail_index_view_close(&view);

	if (status.recent != 0)
		*flags |= MAILBOX_MARKED;
	else
		*flags |= MAILBOX_UNMARKED;
}

void mailbox_list_index_status_init_mailbox(struct mailbox *box)
{
	box->v.get_status = index_list_get_status;
	box->v.get_metadata = index_list_get_metadata;
	box->v.sync_deinit = index_list_sync_deinit;
	box->v.transaction_commit = index_list_transaction_commit;
}

void mailbox_list_index_status_init_finish(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT(list);

	ilist->msgs_ext_id = mail_index_ext_register(ilist->index, "msgs", 0,
		sizeof(struct mailbox_list_index_msgs_record),
		sizeof(uint32_t));

	ilist->hmodseq_ext_id =
		mail_index_ext_register(ilist->index, "hmodseq", 0,
					sizeof(uint64_t), sizeof(uint64_t));
}
