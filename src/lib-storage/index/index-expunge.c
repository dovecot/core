/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"

int index_expunge_seek_first(struct index_mailbox *ibox, unsigned int *seq,
			     struct mail_index_record **rec)
{
	struct mail_index_header *hdr;

	i_assert(ibox->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	hdr = ibox->index->get_header(ibox->index);
	if (hdr->deleted_messages_count == 0) {
		/* no deleted messages */
		*seq = 0;
		*rec = NULL;
		return TRUE;
	}

	/* find mails with DELETED flag and expunge them */
	if (hdr->first_deleted_uid_lowwater > 1) {
		*rec = hdr->first_deleted_uid_lowwater >= hdr->next_uid ? NULL :
			ibox->index->lookup_uid_range(ibox->index,
						hdr->first_deleted_uid_lowwater,
						hdr->next_uid-1, seq);
		if (*rec == NULL) {
			mail_storage_set_critical(ibox->box.storage,
				"index header's deleted_messages_count (%u) "
				"or first_deleted_uid_lowwater (%u) "
				"is invalid.", hdr->deleted_messages_count,
				hdr->first_deleted_uid_lowwater);

			/* fsck should be enough to fix it */
			ibox->index->set_flags |= MAIL_INDEX_FLAG_FSCK;
			return FALSE;
		}
	} else {
		*rec = ibox->index->lookup(ibox->index, 1);
		*seq = 1;
	}

	return TRUE;
}

int index_expunge_mails(struct index_mailbox *ibox,
			struct mail_index_record *first_rec,
			struct mail_index_record *last_rec,
			unsigned int first_seq, unsigned int last_seq,
			int notify)
{
	unsigned int max;

	if (!ibox->index->expunge(ibox->index, first_rec, last_rec,
				  first_seq, last_seq, FALSE))
		return FALSE;

	if (first_seq > ibox->synced_messages_count)
		return TRUE;

	max = last_seq > ibox->synced_messages_count ?
		ibox->synced_messages_count : last_seq;

	ibox->synced_messages_count -= max - first_seq + 1;
	if (notify) {
		struct mail_storage_callbacks *cb;
		void *cb_ctx;

		cb = ibox->box.storage->callbacks;
		cb_ctx = ibox->box.storage->callback_context;

		while (max >= first_seq) {
			cb->expunge(&ibox->box, first_seq, cb_ctx);
			max--;
		}
	}

	return TRUE;
}

int index_storage_expunge(struct mailbox *box, int notify)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	int failed;

	if (box->readonly) {
		box->storage->callbacks->
			notify_no(&ibox->box,
				  "Mailbox is read-only, ignoring expunge",
				  box->storage->callback_context);
		return TRUE;
	}

	if (!index_storage_lock(ibox, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (!index_storage_sync_and_lock(ibox, FALSE, TRUE,
					 MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* modifylog must be marked synced before expunging
	   anything new */
	if (!index_storage_sync_modifylog(ibox, TRUE))
		failed = TRUE;
	else
		failed = !ibox->expunge_locked(ibox, notify);

	if (!index_storage_lock(ibox, MAIL_LOCK_UNLOCK))
		return FALSE;

	return !failed;
}
