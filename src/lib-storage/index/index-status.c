/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-custom-flags.h"
#include "index-storage.h"

static unsigned int get_first_unseen_seq(MailIndex *index)
{
	MailIndexHeader *hdr;
	MailIndexRecord *rec;
	unsigned int seq, lowwater_uid;

	hdr = mail_index_get_header(index);
	if (hdr->seen_messages_count == hdr->messages_count) {
		/* no unseen messages */
		return 0;
	}

	lowwater_uid = hdr->first_unseen_uid_lowwater;
	if (lowwater_uid != 0) {
		/* begin scanning from the low water mark */
		rec = index->lookup_uid_range(index, lowwater_uid,
					      hdr->next_uid - 1);
		if (rec == NULL) {
			i_error("index header's seen_messages_count or "
				"first_unseen_uid_lowwater is invalid.");
                        INDEX_MARK_CORRUPTED(index);
			return 0;
		} else {
			seq = index->get_sequence(index, rec);
		}
	} else {
		/* begin scanning from the beginning */
		rec = index->lookup(index, 1);
		seq = 1;
	}

	while (rec != NULL && (rec->msg_flags & MAIL_SEEN)) {
		rec = index->next(index, rec);
		seq++;
	}

	if (rec != NULL && rec->uid != lowwater_uid) {
		/* update the low water mark if we can get exclusive
		   lock immediately. */
		if (index->try_lock(index, MAIL_LOCK_EXCLUSIVE))
			hdr->first_unseen_uid_lowwater = rec->uid;
	}

	return rec == NULL ? 0 : seq;
}

static void
get_custom_flags(MailCustomFlags *mcf,
		 const char *result[MAIL_CUSTOM_FLAGS_COUNT])
{
	const char **flags;
	int i;

	flags = mail_custom_flags_list_get(mcf);
	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++)
		result[i] = t_strdup(flags[i]);
	mail_custom_flags_list_unref(mcf);
}

int index_storage_get_status(Mailbox *box, MailboxStatusItems items,
			     MailboxStatus *status)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	MailIndexHeader *hdr;

	memset(status, 0, sizeof(MailboxStatus));

	if (!index_storage_sync_if_possible(ibox))
		return FALSE;

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_SHARED))
		return mail_storage_set_index_error(ibox);

	/* we can get most of the status items without any trouble */
	hdr = mail_index_get_header(ibox->index);
	status->messages = hdr->messages_count;
	status->unseen = hdr->messages_count - hdr->seen_messages_count;
	status->uidvalidity = hdr->uid_validity;
	status->uidnext = hdr->next_uid;
	status->diskspace_full = ibox->index->nodiskspace;

	if (items & STATUS_FIRST_UNSEEN_SEQ) {
		status->first_unseen_seq =
			get_first_unseen_seq(ibox->index);
	}

	if (items & STATUS_RECENT)
		status->recent = index_storage_get_recent_count(ibox->index);

	if (items & STATUS_CUSTOM_FLAGS) {
		get_custom_flags(ibox->index->custom_flags,
				 status->custom_flags);
	}

	/* STATUS sends EXISTS, so we've synced it */
	ibox->synced_messages_count = hdr->messages_count;

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
		return mail_storage_set_index_error(ibox);
	return TRUE;
}
