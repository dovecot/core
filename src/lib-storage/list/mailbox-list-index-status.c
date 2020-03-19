/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

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
	struct mailbox_index_vsize vsize;
	uint32_t first_uid;

	bool rec_changed;
	bool msgs_changed;
	bool hmodseq_changed;
	bool vsize_changed;
	bool first_saved_changed;
};

struct index_list_storage_module index_list_storage_module =
	MODULE_CONTEXT_INIT(&mail_storage_module_register);

static int
index_list_exists(struct mailbox *box, bool auto_boxes,
		  enum mailbox_existence *existence_r)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);
	struct mail_index_view *view;
	const struct mail_index_record *rec;
	enum mailbox_list_index_flags flags;
	uint32_t seq;

	if (mailbox_list_index_view_open(box, FALSE, &view, &seq) <= 0) {
		/* failure / not found. fallback to the real storage check
		   just in case to see if the mailbox was just created. */
		return ibox->module_ctx.super.
			exists(box, auto_boxes, existence_r);
	}
	rec = mail_index_lookup(view, seq);
	flags = rec->flags;
	mail_index_view_close(&view);

	if ((flags & MAILBOX_LIST_INDEX_FLAG_NONEXISTENT) != 0)
		*existence_r = MAILBOX_EXISTENCE_NONE;
	else if ((flags & MAILBOX_LIST_INDEX_FLAG_NOSELECT) != 0)
		*existence_r = MAILBOX_EXISTENCE_NOSELECT;
	else
		*existence_r = MAILBOX_EXISTENCE_SELECT;
	return 0;
}

bool mailbox_list_index_status(struct mailbox_list *list,
			       struct mail_index_view *view,
			       uint32_t seq, enum mailbox_status_items items,
			       struct mailbox_status *status_r,
			       uint8_t *mailbox_guid,
			       struct mailbox_index_vsize *vsize_r)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);
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
	if (vsize_r != NULL) {
		mail_index_lookup_ext(view, seq, ilist->vsize_ext_id,
				      &data, &expunged);
		if (data == NULL)
			ret = FALSE;
		else
			memcpy(vsize_r, data, sizeof(*vsize_r));
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

	if (items == 0)
		return 1;

	if ((items & STATUS_UNSEEN) != 0 &&
	    (mailbox_get_private_flags_mask(box) & MAIL_SEEN) != 0) {
		/* can't get UNSEEN from list index, since each user has
		   different \Seen flags */
		return 0;
	}

	if ((ret = mailbox_list_index_view_open(box, TRUE, &view, &seq)) <= 0)
		return ret;

	ret = mailbox_list_index_status(box->list, view, seq, items,
					status_r, NULL, NULL) ? 1 : 0;
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
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(box->list);
	struct mailbox_status status;
	struct mail_index_view *view;
	uint32_t seq;
	int ret;

	if (ilist->syncing) {
		/* syncing wants to know the GUID for a new mailbox. */
		return 0;
	}

	if ((ret = mailbox_list_index_view_open(box, FALSE, &view, &seq)) <= 0)
		return ret;

	ret = mailbox_list_index_status(box->list, view, seq, 0,
					&status, guid_r, NULL) ? 1 : 0;
	if (ret > 0 && guid_128_is_empty(guid_r))
		ret = 0;
	mail_index_view_close(&view);
	return ret;
}

static int index_list_get_cached_vsize(struct mailbox *box, uoff_t *vsize_r)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(box->list);
	struct mailbox_status status;
	struct mailbox_index_vsize vsize;
	struct mail_index_view *view;
	uint32_t seq;
	int ret;

	i_assert(!ilist->syncing);

	if ((ret = mailbox_list_index_view_open(box, TRUE, &view, &seq)) <= 0)
		return ret;

	ret = mailbox_list_index_status(box->list, view, seq,
					STATUS_MESSAGES | STATUS_UIDNEXT,
					&status, NULL, &vsize) ? 1 : 0;
	if (ret > 0 && status.messages == 0 && status.uidnext > 0) {
		/* mailbox is empty. its size has to be zero, regardless of
		   what the vsize header says. */
		vsize.vsize = 0;
	} else if (ret > 0 && (vsize.highest_uid + 1 != status.uidnext ||
			       vsize.message_count != status.messages)) {
		/* out of date vsize info */
		ret = 0;
	}
	if (ret > 0)
		*vsize_r = vsize.vsize;
	mail_index_view_close(&view);
	return ret;
}

static int
index_list_get_cached_first_saved(struct mailbox *box,
				  struct mailbox_index_first_saved *first_saved_r)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(box->list);
	struct mail_index_view *view;
	struct mailbox_status status;
	const void *data;
	bool expunged;
	uint32_t seq;
	int ret;

	i_zero(first_saved_r);

	if ((ret = mailbox_list_index_view_open(box, TRUE, &view, &seq)) <= 0)
		return ret;

	mail_index_lookup_ext(view, seq, ilist->first_saved_ext_id,
			      &data, &expunged);
	if (data != NULL)
		memcpy(first_saved_r, data, sizeof(*first_saved_r));
	if (first_saved_r->timestamp != 0 && first_saved_r->uid == 0) {
		/* mailbox was empty the last time we updated this.
		   we'll need to verify if it still is. */
		if (!mailbox_list_index_status(box->list, view, seq,
					       STATUS_MESSAGES,
					       &status, NULL, NULL) ||
		    status.messages != 0)
			first_saved_r->timestamp = 0;
	}
	mail_index_view_close(&view);
	return first_saved_r->timestamp != 0 ? 1 : 0;
}

static int
index_list_try_get_metadata(struct mailbox *box,
			    enum mailbox_metadata_items items,
			    struct mailbox_metadata *metadata_r)
{
	enum mailbox_metadata_items noncached_items;
	int ret;

	i_assert(metadata_r != NULL);

	if (box->opened) {
		/* if mailbox is already opened, don't bother using the values
		   in mailbox list index. they have a higher chance of being
		   wrong. */
		return 0;
	}
	/* see if we have a chance of fulfilling this without opening
	   the mailbox. */
	noncached_items = items & ~(MAILBOX_METADATA_GUID |
				    MAILBOX_METADATA_VIRTUAL_SIZE |
				    MAILBOX_METADATA_FIRST_SAVE_DATE);
	if ((noncached_items & MAILBOX_METADATA_PHYSICAL_SIZE) != 0 &&
	    box->mail_vfuncs->get_physical_size ==
	    box->mail_vfuncs->get_virtual_size)
		noncached_items = items & ~MAILBOX_METADATA_PHYSICAL_SIZE;

	if (noncached_items != 0)
		return 0;

	if ((items & MAILBOX_METADATA_GUID) != 0) {
		if ((ret = index_list_get_cached_guid(box, metadata_r->guid)) <= 0)
			return ret;
	}
	if ((items & (MAILBOX_METADATA_VIRTUAL_SIZE |
		      MAILBOX_METADATA_PHYSICAL_SIZE)) != 0) {
		if ((ret = index_list_get_cached_vsize(box, &metadata_r->virtual_size)) <= 0)
			return ret;
		if ((items & MAILBOX_METADATA_PHYSICAL_SIZE) != 0)
			metadata_r->physical_size = metadata_r->virtual_size;
	}
	if ((items & MAILBOX_METADATA_FIRST_SAVE_DATE) != 0) {
		struct mailbox_index_first_saved first_saved;

		/* start writing first_saved to mailbox list index if it wasn't
		   there already. */
		box->update_first_saved = TRUE;

		if ((ret = index_list_get_cached_first_saved(box, &first_saved)) <= 0)
			return ret;
		metadata_r->first_save_date =
			first_saved.timestamp == (uint32_t)-1 ? (time_t)-1 :
			(time_t)first_saved.timestamp;
	}
	return 1;
}

static int
index_list_get_metadata(struct mailbox *box,
			enum mailbox_metadata_items items,
			struct mailbox_metadata *metadata_r)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);

	if (index_list_try_get_metadata(box, items, metadata_r) != 0)
		return 0;
	return ibox->module_ctx.super.get_metadata(box, items, metadata_r);
}

static void
index_list_update_fill_vsize(struct mailbox *box,
			     struct mail_index_view *view,
			     struct index_list_changes *changes_r)
{
	const void *data;
	size_t size;

	mail_index_get_header_ext(view, box->vsize_hdr_ext_id,
				  &data, &size);
	if (size == sizeof(changes_r->vsize))
		memcpy(&changes_r->vsize, data, sizeof(changes_r->vsize));
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

	i_zero(changes_r);

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
	index_list_update_fill_vsize(box, view, changes_r);
	mail_index_view_close(&view); hdr = NULL;

	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) == 0)
		memcpy(changes_r->guid, metadata.guid, sizeof(changes_r->guid));
	return TRUE;
}

static void
index_list_first_saved_update_changes(struct mailbox *box,
				      struct mail_index_view *list_view,
				      struct index_list_changes *changes)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(box->list);
	struct mailbox_index_first_saved first_saved;
	const void *data;
	bool expunged;

	mail_index_lookup_ext(list_view, changes->seq,
			      ilist->first_saved_ext_id, &data, &expunged);
	if (data == NULL)
		i_zero(&first_saved);
	else
		memcpy(&first_saved, data, sizeof(first_saved));
	if (mail_index_view_get_messages_count(box->view) > 0)
		mail_index_lookup_uid(box->view, 1, &changes->first_uid);
	if (first_saved.uid == 0 && first_saved.timestamp == 0) {
		/* it's not in the index yet. we'll set it only if we've
		   just called MAILBOX_METADATA_FIRST_SAVE_DATE. */
		changes->first_saved_changed = box->update_first_saved;
	} else {
		changes->first_saved_changed =
			changes->first_uid != first_saved.uid;
	}
}

static bool
index_list_has_changed(struct mailbox *box, struct mail_index_view *list_view,
		       struct index_list_changes *changes)
{
	struct mailbox_status old_status;
	struct mailbox_index_vsize old_vsize;
	guid_128_t old_guid;

	i_zero(&old_status);
	i_zero(&old_vsize);
	memset(old_guid, 0, sizeof(old_guid));
	(void)mailbox_list_index_status(box->list, list_view, changes->seq,
					CACHED_STATUS_ITEMS,
					&old_status, old_guid, &old_vsize);

	changes->rec_changed =
		old_status.uidvalidity != changes->status.uidvalidity &&
		changes->status.uidvalidity != 0;
	if (!guid_128_equals(changes->guid, old_guid) &&
	    !guid_128_is_empty(changes->guid))
		changes->rec_changed = TRUE;

	if (MAILBOX_IS_NEVER_IN_INDEX(box)) {
		/* check only UIDVALIDITY and GUID changes for INBOX */
		return changes->rec_changed;
	}

	changes->msgs_changed =
		old_status.messages != changes->status.messages ||
		old_status.unseen != changes->status.unseen ||
		old_status.recent != changes->status.recent ||
		old_status.uidnext != changes->status.uidnext;
	/* update highest-modseq only if they're ever been used */
	if (old_status.highest_modseq == changes->status.highest_modseq) {
		changes->hmodseq_changed = FALSE;
	} else {
		changes->hmodseq_changed = TRUE;
	}
	if (memcmp(&old_vsize, &changes->vsize, sizeof(old_vsize)) != 0)
		changes->vsize_changed = TRUE;
	index_list_first_saved_update_changes(box, list_view, changes);

	return changes->rec_changed || changes->msgs_changed ||
		changes->hmodseq_changed || changes->vsize_changed ||
		changes->first_saved_changed;
}

static void
index_list_update_first_saved(struct mailbox *box,
			      struct mail_index_transaction *list_trans,
			      const struct index_list_changes *changes)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(box->list);
	struct mailbox_transaction_context *t;
	struct mail *mail;
	struct mailbox_index_first_saved first_saved;
	uint32_t seq, messages_count;
	time_t save_date;
	int ret = 0;

	i_zero(&first_saved);
	first_saved.timestamp = (uint32_t)-1;

	if (changes->first_uid != 0) {
		t = mailbox_transaction_begin(box, 0, __func__);
		mail = mail_alloc(t, MAIL_FETCH_SAVE_DATE, NULL);
		messages_count = mail_index_view_get_messages_count(box->view);
		for (seq = 1; seq <= messages_count; seq++) {
			mail_set_seq(mail, seq);
			if (mail_get_save_date(mail, &save_date) >= 0) {
				first_saved.uid = mail->uid;
				first_saved.timestamp = save_date;
				break;
			}
			if (mailbox_get_last_mail_error(box) != MAIL_ERROR_EXPUNGED) {
				ret = -1;
				break;
			}
		}
		mail_free(&mail);
		(void)mailbox_transaction_commit(&t);
	}
	if (ret == 0) {
		mail_index_update_ext(list_trans, changes->seq,
				      ilist->first_saved_ext_id,
				      &first_saved, NULL);
	}
}


static void
index_list_update(struct mailbox *box, struct mail_index_view *list_view,
		  struct mail_index_transaction *list_trans,
		  const struct index_list_changes *changes)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(box->list);

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

		i_zero(&msgs);
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
	if (changes->vsize_changed) {
		mail_index_update_ext(list_trans, changes->seq,
				      ilist->vsize_ext_id,
				      &changes->vsize, NULL);
	}
	if (changes->first_saved_changed)
		index_list_update_first_saved(box, list_trans, changes);
}

static int index_list_update_mailbox(struct mailbox *box)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(box->list);
	struct mail_index_sync_ctx *list_sync_ctx;
	struct mail_index_view *list_view;
	struct mail_index_transaction *list_trans;
	struct index_list_changes changes;
	int ret;

	i_assert(box->opened);

	if (ilist->syncing || ilist->updating_status)
		return 0;
	if (box->deleting) {
		/* don't update status info while mailbox is being deleted.
		   especially not a good idea if we're rolling back a created
		   mailbox that somebody else had just created */
		return 0;
	}

	/* refresh the mailbox list index once. we can't do this again after
	   locking, because it could trigger list syncing. */
	(void)mailbox_list_index_refresh(box->list);

	/* first do a quick check while unlocked to see if anything changes */
	list_view = mail_index_view_open(ilist->index);
	if (!index_list_update_fill_changes(box, list_view, &changes))
		ret = -1;
	else if (index_list_has_changed(box, list_view, &changes))
		ret = 1;
	else {
		/* if backend state changed on the last check, update it here
		   now. we probably don't need to bother checking again if the
		   state had changed? */
		ret = ilist->index_last_check_changed ? 1 : 0;
	}
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
	else {
		ilist->updating_status = TRUE;
		if (index_list_has_changed(box, list_view, &changes))
			index_list_update(box, list_view, list_trans, &changes);
		if (box->v.list_index_update_sync != NULL &&
		    !MAILBOX_IS_NEVER_IN_INDEX(box)) {
			box->v.list_index_update_sync(box, list_trans,
						      changes.seq);
		}
		ilist->updating_status = FALSE;
	}

	struct mail_index_sync_rec sync_rec;
	while (mail_index_sync_next(list_sync_ctx, &sync_rec)) ;
	if (mail_index_sync_commit(&list_sync_ctx) < 0) {
		mailbox_set_index_error(box);
		return -1;
	}
	ilist->index_last_check_changed = FALSE;
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

	i_zero(&changes);
	/* update the mailbox list index even if it has some other pending
	   changes. */
	if (mailbox_list_index_view_open(box, FALSE, &list_view, &changes.seq) <= 0)
		return;

	guid_128_empty(mailbox_guid);
	(void)mailbox_list_index_status(box->list, list_view, changes.seq,
					CACHED_STATUS_ITEMS, &status,
					mailbox_guid, NULL);

	if (update->uid_validity != 0) {
		changes.rec_changed = TRUE;
		changes.status.uidvalidity = update->uid_validity;
	}
	if (!guid_128_equals(update->mailbox_guid, mailbox_guid) &&
	    !guid_128_is_empty(update->mailbox_guid)) {
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

void mailbox_list_index_status_sync_init(struct mailbox *box)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);
	const struct mail_index_header *hdr;

	hdr = mail_index_get_header(box->view);
	ibox->pre_sync_log_file_seq = hdr->log_file_seq;
	ibox->pre_sync_log_file_head_offset = hdr->log_file_head_offset;
}

void mailbox_list_index_status_sync_deinit(struct mailbox *box)
{
	struct index_list_mailbox *ibox = INDEX_LIST_STORAGE_CONTEXT(box);
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(box->list);
	const struct mail_index_header *hdr;

	hdr = mail_index_get_header(box->view);
	if (!ilist->opened &&
	    ibox->pre_sync_log_file_head_offset == hdr->log_file_head_offset &&
	    ibox->pre_sync_log_file_seq == hdr->log_file_seq) {
		/* List index isn't open and sync changed nothing.
		   Don't bother opening the list index. */
		return;
	}

	/* it probably doesn't matter much here if we push/pop the error,
	   but might as well do it. */
	mail_storage_last_error_push(mailbox_get_storage(box));
	(void)index_list_update_mailbox(box);
	mail_storage_last_error_pop(mailbox_get_storage(box));
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

	/* check all changes here, because e.g. vsize update is _OTHERS */
	if (changes_r->changes_mask == 0)
		return 0;

	/* this transaction commit may have been done in error handling path
	   and the caller still wants to access the current error. make sure
	   that whatever we do here won't change the error. */
	mail_storage_last_error_push(mailbox_get_storage(box));
	(void)index_list_update_mailbox(box);
	mail_storage_last_error_pop(mailbox_get_storage(box));
	return 0;
}

void mailbox_list_index_status_set_info_flags(struct mailbox *box, uint32_t uid,
					      enum mailbox_info_flags *flags)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(box->list);
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
			box->v.list_index_has_changed(box, view, seq, TRUE);
	} T_END;

	if (ret != 0) {
		/* error / not up to date. don't waste time with it. */
		mail_index_view_close(&view);
		return;
	}

	status.recent = 0;
	(void)mailbox_list_index_status(box->list, view, seq, STATUS_RECENT,
					&status, NULL, NULL);
	mail_index_view_close(&view);

	if (status.recent != 0)
		*flags |= MAILBOX_MARKED;
	else
		*flags |= MAILBOX_UNMARKED;
}

void mailbox_list_index_status_init_mailbox(struct mailbox_vfuncs *v)
{
	v->exists = index_list_exists;
	v->get_status = index_list_get_status;
	v->get_metadata = index_list_get_metadata;
	v->transaction_commit = index_list_transaction_commit;
}

void mailbox_list_index_status_init_finish(struct mailbox_list *list)
{
	struct mailbox_list_index *ilist = INDEX_LIST_CONTEXT_REQUIRE(list);

	ilist->msgs_ext_id = mail_index_ext_register(ilist->index, "msgs", 0,
		sizeof(struct mailbox_list_index_msgs_record),
		sizeof(uint32_t));

	ilist->hmodseq_ext_id =
		mail_index_ext_register(ilist->index, "hmodseq", 0,
					sizeof(uint64_t), sizeof(uint64_t));
	ilist->vsize_ext_id =
		mail_index_ext_register(ilist->index, "vsize", 0,
			sizeof(struct mailbox_index_vsize), sizeof(uint64_t));
	ilist->first_saved_ext_id =
		mail_index_ext_register(ilist->index, "1saved", 0,
			sizeof(struct mailbox_index_first_saved), sizeof(uint32_t));
}
