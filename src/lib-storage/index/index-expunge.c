/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"

int index_expunge_seek_first(IndexMailbox *ibox, unsigned int *seq,
			     MailIndexRecord **rec)
{
	MailIndexHeader *hdr;

	i_assert(ibox->index->lock_type == MAIL_LOCK_EXCLUSIVE);

	hdr = ibox->index->get_header(ibox->index);
	if (hdr->deleted_messages_count == 0) {
		/* no deleted messages */
		return TRUE;
	}

	/* find mails with DELETED flag and expunge them */
	if (hdr->first_deleted_uid_lowwater > 1) {
		*rec = hdr->first_deleted_uid_lowwater >= hdr->next_uid ? NULL :
			ibox->index->lookup_uid_range(ibox->index,
						hdr->first_deleted_uid_lowwater,
						hdr->next_uid-1);
		if (*rec == NULL) {
			mail_storage_set_critical(ibox->box.storage,
				"index header's deleted_messages_count (%u) "
				"or first_deleted_uid_lowwater (%u) "
				"is invalid.", hdr->deleted_messages_count,
				hdr->first_deleted_uid_lowwater);

			/* fsck should be enough to fix it */
			ibox->index->header->flags |= MAIL_INDEX_FLAG_FSCK;
			return FALSE;
		} else {
			*seq = ibox->index->get_sequence(ibox->index, *rec);
		}
	} else {
		*rec = ibox->index->lookup(ibox->index, 1);
		*seq = 1;
	}

	return TRUE;
}

int index_storage_expunge(Mailbox *box)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	int failed;

	if (box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return FALSE;
	}

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_EXCLUSIVE))
		return mail_storage_set_index_error(ibox);

	failed = !ibox->expunge_locked(ibox, NULL, NULL);

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK) || failed)
		return mail_storage_set_index_error(ibox);
	return TRUE;
}
