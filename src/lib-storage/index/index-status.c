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
					      hdr->next_uid - 1, &seq);
		if (rec == NULL) {
			i_error("index header's seen_messages_count or "
				"first_unseen_uid_lowwater is invalid.");
                        INDEX_MARK_CORRUPTED(index);
			return 0;
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
get_custom_flags(MailCustomFlags *mcf, MailboxStatus *status)
{
	const char **flags;
	unsigned int i;

	status->custom_flags_count = MAIL_CUSTOM_FLAGS_COUNT;
	status->custom_flags = t_new(const char *, MAIL_CUSTOM_FLAGS_COUNT);

	flags = mail_custom_flags_list_get(mcf);
	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++)
		status->custom_flags[i] = t_strdup(flags[i]);
}

int index_storage_get_status(Mailbox *box, MailboxStatusItems items,
			     MailboxStatus *status)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	MailIndexHeader *hdr;

	memset(status, 0, sizeof(MailboxStatus));

	/* if we're doing STATUS for selected mailbox, we have to sync it
	   first or STATUS reply may give different data */
	if (!index_storage_sync_index_if_possible(ibox, TRUE))
		return FALSE;

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_SHARED))
		return mail_storage_set_index_error(ibox);

	if (!index_storage_sync_modifylog(ibox)) {
		if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
			return mail_storage_set_index_error(ibox);
		return FALSE;
	}

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

	if (items & STATUS_CUSTOM_FLAGS)
		get_custom_flags(ibox->index->custom_flags, status);

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
		return mail_storage_set_index_error(ibox);
	return TRUE;
}
