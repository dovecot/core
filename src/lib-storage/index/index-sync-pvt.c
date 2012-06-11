/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-index-alloc-cache.h"
#include "mailbox-list-private.h"
#include "index-sync-private.h"

static int index_storage_mailbox_alloc_index_pvt(struct mailbox *box)
{
	const char *index_dir;

	if (box->index_pvt != NULL)
		return 1;

	index_dir = mailbox_list_get_path(box->list, box->name,
					  MAILBOX_LIST_PATH_TYPE_INDEX_PRIVATE);
	if (index_dir == NULL) {
		/* no private indexes */
		return 0;
	}

	if (mailbox_list_create_missing_index_pvt_dir(box->list, box->name) < 0) {
		mail_storage_set_internal_error(box->storage);
		return -1;
	}

	box->index_pvt = mail_index_alloc_cache_get(NULL, index_dir,
		t_strconcat(box->index_prefix, ".pvt", NULL));
	mail_index_set_fsync_mode(box->index_pvt,
				  box->storage->set->parsed_fsync_mode, 0);
	mail_index_set_lock_method(box->index_pvt,
		box->storage->set->parsed_lock_method,
		mail_storage_get_lock_timeout(box->storage, -1U));
	return 1;
}

static int index_storage_mailbox_open_index_pvt(struct mailbox *box)
{
	int ret;

	if (box->view_pvt != NULL)
		return 1;

	if ((ret = index_storage_mailbox_alloc_index_pvt(box)) <= 0)
		return ret;
	if (mail_index_open(box->index_pvt, MAIL_INDEX_OPEN_FLAG_CREATE) < 0)
		return -1;
	box->view_pvt = mail_index_view_open(box->index_pvt);
	return 1;
}

static int sync_pvt_expunges(struct mailbox *box,
			     struct mail_index_view *view_pvt,
			     struct mail_index_transaction *trans_pvt,
			     struct mail_index_view *view_shared)
{
	uint32_t seq_shared, seq_pvt, count_shared, count_pvt;
	uint32_t uid_shared, uid_pvt;

	count_shared = mail_index_view_get_messages_count(view_shared);
	count_pvt = mail_index_view_get_messages_count(view_pvt);
	seq_shared = seq_pvt = 1;
	while (seq_pvt <= count_pvt && seq_shared <= count_shared) {
		mail_index_lookup_uid(view_pvt, seq_pvt, &uid_pvt);
		mail_index_lookup_uid(view_shared, seq_shared, &uid_shared);
		if (uid_pvt == uid_shared) {
			seq_pvt++;
			seq_shared++;
		} else if (uid_pvt < uid_shared) {
			/* message expunged */
			mail_index_expunge(trans_pvt, seq_pvt);
			seq_pvt++;
		} else {
			mail_storage_set_critical(box->storage,
				"%s: Message UID=%u unexpectedly inserted to mailbox",
				box->index_pvt->filepath, uid_shared);
			return -1;
		}
	}
	return 0;
}

static void
sync_pvt_copy_self_flags(struct mailbox *box,
			 struct mail_index_view *view,
			 struct mail_index_transaction *trans,
			 ARRAY_TYPE(keyword_indexes) *keywords,
			 uint32_t seq_old, uint32_t seq_new)
{
	const struct mail_index_record *old_rec;

	old_rec = mail_index_lookup(view, seq_old);
	mail_index_lookup_keywords(view, seq_old, keywords);
	if (old_rec->flags != 0) {
		mail_index_update_flags(trans, seq_new,
					MODIFY_ADD, old_rec->flags);
	}
	if (array_count(keywords) > 0) {
		struct mail_keywords *kw;

		kw = mail_index_keywords_create_from_indexes(box->index_pvt,
							     keywords);
		mail_index_update_keywords(trans, seq_new, MODIFY_ADD, kw);
		mail_index_keywords_unref(&kw);
	}
}

static int
index_storage_mailbox_sync_pvt_index(struct mailbox *box)
{
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *view_pvt;
	struct mail_index_transaction *trans_pvt;
	const struct mail_index_header *hdr_shared, *hdr_pvt;
	struct mail_index_view *view_shared;
	ARRAY_TYPE(keyword_indexes) keywords;
	uint32_t seq_shared, seq_pvt, seq_old_pvt, seq2, count_shared, uid;
	bool reset = FALSE, preserve_old_flags = FALSE;
	int ret;

	/* open a view for the latest version of the index */
	if (mail_index_refresh(box->index) < 0) {
		mail_storage_set_index_error(box);
		return -1;
	}
	view_shared = mail_index_view_open(box->index);
	hdr_shared = mail_index_get_header(view_shared);
	if (hdr_shared->uid_validity == 0) {
		/* the mailbox hasn't been fully created yet,
		   no need for a private index yet */
		mail_index_view_close(&view_shared);
		return 0;
	}
	hdr_pvt = mail_index_get_header(box->view_pvt);
	if (hdr_pvt->next_uid == hdr_shared->next_uid) {
		/* no new mails, don't bother syncing */
		mail_index_view_close(&view_shared);
		return 0;
	}

	if (mail_index_sync_begin(box->index_pvt, &sync_ctx,
				  &view_pvt, &trans_pvt, 0) < 0) {
		mail_storage_set_index_error(box);
		mail_index_view_close(&view_shared);
		return -1;
	}
	/* get an updated private header */
	hdr_pvt = mail_index_get_header(view_pvt);

	if (hdr_shared->uid_validity == hdr_pvt->uid_validity) {
		/* same mailbox. expunge messages from private index that
		   no longer exist. */
		if (sync_pvt_expunges(box, view_pvt, trans_pvt, view_shared) < 0) {
			reset = TRUE;
			preserve_old_flags = TRUE;
			t_array_init(&keywords, 32);
		}
	} else if (hdr_pvt->uid_validity == 0 || hdr_pvt->uid_validity != 0) {
		/* mailbox created/recreated */
		reset = TRUE;
	}

	count_shared = mail_index_view_get_messages_count(view_shared);
	if (!reset) {
		if (!mail_index_lookup_seq_range(view_shared, hdr_pvt->next_uid,
						 hdr_shared->next_uid,
						 &seq_shared, &seq2)) {
			/* no new messages */
			seq_shared = count_shared+1;
		}
	} else {
		mail_index_reset(trans_pvt);
		mail_index_update_header(trans_pvt,
			offsetof(struct mail_index_header, uid_validity),
			&hdr_shared->uid_validity,
			sizeof(hdr_shared->uid_validity), TRUE);
		seq_shared = 1;
	}

	for (; seq_shared <= count_shared; seq_shared++) {
		mail_index_lookup_uid(view_shared, seq_shared, &uid);
		mail_index_append(trans_pvt, uid, &seq_pvt);
		if (preserve_old_flags &&
		    mail_index_lookup_seq(view_pvt, uid, &seq_old_pvt)) {
			/* copy flags from the original index */
			sync_pvt_copy_self_flags(box, view_pvt, trans_pvt,
						 &keywords,
						 seq_old_pvt, seq_pvt);
		}
	}
	if ((ret = mail_index_sync_commit(&sync_ctx)) < 0)
		mail_storage_set_index_error(box);
	mail_index_view_close(&view_shared);
	return ret;
}

int index_storage_mailbox_sync_pvt(struct mailbox *box)
{
	struct mail_index_view_sync_ctx *view_sync_ctx;
	enum mail_flags pvt_flags;
	bool delayed_expunges;
	int ret;

	pvt_flags = mailbox_get_private_flags_mask(box);
	if (pvt_flags == 0)
		return 0;

	if ((ret = index_storage_mailbox_open_index_pvt(box)) <= 0)
		return ret;

	/* sync private index against shared index by adding/removing mails */
	if (index_storage_mailbox_sync_pvt_index(box) < 0)
		return -1;

	/* sync the private view */
	view_sync_ctx = mail_index_view_sync_begin(box->view_pvt,
		MAIL_INDEX_VIEW_SYNC_FLAG_FIX_INCONSISTENT);
	if (mail_index_view_sync_commit(&view_sync_ctx, &delayed_expunges) < 0)
		return -1;
	return 0;
}
