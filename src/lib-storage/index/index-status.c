/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-custom-flags.h"
#include "mail-index-util.h"
#include "index-storage.h"

#define STATUS_MESSAGE_COUNTS \
	(STATUS_MESSAGES | STATUS_RECENT | STATUS_UIDNEXT | \
	 STATUS_UIDVALIDITY | STATUS_UNSEEN | STATUS_FIRST_UNSEEN_SEQ)

static unsigned int get_first_unseen_seq(struct mail_index *index)
{
	struct mail_index_header *hdr;
	struct mail_index_record *rec;
	unsigned int seq, lowwater_uid;

	hdr = mail_index_get_header(index);
	if (hdr->seen_messages_count == hdr->messages_count) {
		/* no unseen messages */
		return 0;
	}

	lowwater_uid = hdr->first_unseen_uid_lowwater;
	if (lowwater_uid == hdr->next_uid) {
		/* no unseen messages */
		rec = NULL;
	} else if (lowwater_uid > hdr->next_uid) {
		index_set_corrupted(index, "first_unseen_uid_lowwater %u >= "
				    "next_uid %u", lowwater_uid, hdr->next_uid);
		return 0;
	} else if (lowwater_uid != 0) {
		/* begin scanning from the low water mark */
		rec = index->lookup_uid_range(index, lowwater_uid,
					      hdr->next_uid - 1, &seq);
	} else {
		/* begin scanning from the beginning */
		rec = index->lookup(index, 1);
		seq = 1;
	}

	while (rec != NULL && (rec->msg_flags & MAIL_SEEN)) {
		rec = index->next(index, rec);
		seq++;
	}

	if (rec == NULL) {
		index_set_corrupted(index, "No unseen messages found with "
				    "first_unseen_uid_lowwater %u, "
				    "seen_messages_count %u, messages_count %u",
				    lowwater_uid, hdr->seen_messages_count,
				    hdr->messages_count);
		return 0;
	}

	if (rec->uid != lowwater_uid) {
		/* update the low water mark if we can get exclusive
		   lock immediately. */
		if (index->try_lock(index, MAIL_LOCK_EXCLUSIVE))
			hdr->first_unseen_uid_lowwater = rec->uid;
	}

	return seq;
}

static void
get_custom_flags(struct mail_custom_flags *mcf, struct mailbox_status *status)
{
	const char **flags;
	unsigned int i;

	status->custom_flags_count = MAIL_CUSTOM_FLAGS_COUNT;
	status->custom_flags = t_new(const char *, MAIL_CUSTOM_FLAGS_COUNT);

	flags = mail_custom_flags_list_get(mcf);
	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++)
		status->custom_flags[i] = t_strdup(flags[i]);
}

int index_storage_get_status(struct mailbox *box,
			     enum mailbox_status_items items,
			     struct mailbox_status *status)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	struct mail_index_header *hdr;

	memset(status, 0, sizeof(struct mailbox_status));

	if ((items & STATUS_MESSAGE_COUNTS) != 0) {
		/* if we're doing STATUS for selected mailbox, we have to sync
		   it first or STATUS reply may give different data */
		if (!index_storage_sync_and_lock(ibox, TRUE, MAIL_LOCK_UNLOCK))
			return FALSE;

		if (!index_storage_sync_modifylog(ibox, FALSE)) {
			(void)index_storage_lock(ibox, MAIL_LOCK_UNLOCK);
			return FALSE;
		}
	} else {
		if (!index_storage_lock(ibox, MAIL_LOCK_SHARED))
			return FALSE;
	}

	/* we can get most of the status items without any trouble */
	hdr = mail_index_get_header(ibox->index);
	if ((items & STATUS_MESSAGE_COUNTS) != 0) {
		status->messages = hdr->messages_count;
		status->unseen = hdr->messages_count - hdr->seen_messages_count;
		status->uidvalidity = hdr->uid_validity;
		status->uidnext = hdr->next_uid;
	}
	status->diskspace_full = ibox->index->nodiskspace;

	if (items & STATUS_FIRST_UNSEEN_SEQ) {
		status->first_unseen_seq =
			get_first_unseen_seq(ibox->index);
	}

	if (items & STATUS_RECENT)
		status->recent = index_storage_get_recent_count(ibox->index);

	if (items & STATUS_CUSTOM_FLAGS)
		get_custom_flags(ibox->index->custom_flags, status);

	if (!index_storage_lock(ibox, MAIL_LOCK_UNLOCK))
		return FALSE;
	return TRUE;
}
