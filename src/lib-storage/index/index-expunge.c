/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"

MailIndexRecord *index_expunge_seek_first(IndexMailbox *ibox,
					  unsigned int *seq)
{
	MailIndexHeader *hdr;
	MailIndexRecord *rec;

	hdr = ibox->index->get_header(ibox->index);
	if (hdr->deleted_messages_count == 0)
		return NULL;

	/* find mails with DELETED flag and expunge them */
	if (hdr->first_deleted_uid_lowwater > 1) {
		rec = ibox->index->lookup_uid_range(ibox->index,
			hdr->first_deleted_uid_lowwater, hdr->next_uid-1);
		if (rec == NULL) {
			i_warning("index header's deleted_messages_count or "
				  "first_deleted_uid_lowwater is invalid.");
                        INDEX_MARK_CORRUPTED(ibox->index);
			return NULL;
		} else {
			*seq = ibox->index->get_sequence(ibox->index, rec);
		}
	} else {
		rec = ibox->index->lookup(ibox->index, 1);
		*seq = 1;
	}

	return rec;
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
