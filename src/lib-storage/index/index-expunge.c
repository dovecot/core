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

int index_expunge_mail(struct index_mailbox *ibox,
		       struct mail_index_record *rec,
		       unsigned int seq, int notify)
{
	if (!ibox->index->expunge(ibox->index, rec, seq, FALSE))
		return FALSE;

	if (seq <= ibox->synced_messages_count) {
		if (notify) {
			struct mail_storage *storage = ibox->box.storage;
			storage->callbacks->expunge(&ibox->box, seq,
						    storage->callback_context);
		}
		ibox->synced_messages_count--;
	}

	return TRUE;
}

int index_storage_expunge(struct mailbox *box, int notify)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	int failed;

	if (box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return FALSE;
	}

	if (!index_storage_lock(ibox, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (!index_storage_sync_and_lock(ibox, FALSE, MAIL_LOCK_EXCLUSIVE))
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
