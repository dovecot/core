/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"
#include "mail-index-util.h"
#include "mail-modifylog.h"
#include "mail-custom-flags.h"

static void index_storage_sync_size(IndexMailbox *ibox)
{
	unsigned int messages, recent;

	messages = ibox->index->get_header(ibox->index)->messages_count;
	messages += mail_modifylog_get_expunge_count(ibox->index->modifylog);

	if (messages != ibox->synced_messages_count) {
		i_assert(messages > ibox->synced_messages_count);

		/* new messages in mailbox */
		recent = index_storage_get_recent_count(ibox->index);
		ibox->sync_callbacks.new_messages(&ibox->box, messages, recent,
						  ibox->sync_context);
		ibox->synced_messages_count = messages;
	}
}

/* may leave the index locked */
int index_storage_sync_index_if_possible(IndexMailbox *ibox, int sync_size)
{
	MailIndex *index = ibox->index;

	if (index->sync(index)) {
		/* reset every time it has worked */
		ibox->sent_diskspace_warning = FALSE;
	} else {
		if (!index->is_diskspace_error(index)) {
			(void)index->set_lock(index, MAIL_LOCK_UNLOCK);
			return mail_storage_set_index_error(ibox);
		}

		/* notify client once about it */
		if (!ibox->sent_diskspace_warning) {
			ibox->sent_diskspace_warning = TRUE;
			ibox->sync_callbacks.alert_no_diskspace(
						&ibox->box, ibox->sync_context);
		}

		index_reset_error(index);
	}

	/* notify about changes in mailbox size. */
	if (index->lock_type == MAIL_LOCK_UNLOCK)
		return TRUE; /* no changes - must be no new mail either */

	if (sync_size)
		index_storage_sync_size(ibox);

	/* notify changes in custom flags */
	if (mail_custom_flags_has_changes(index->custom_flags)) {
		ibox->sync_callbacks.new_custom_flags(&ibox->box,
                	mail_custom_flags_list_get(index->custom_flags),
			MAIL_CUSTOM_FLAGS_COUNT, ibox->sync_context);
	}

	return TRUE;
}

int index_storage_sync_modifylog(IndexMailbox *ibox)
{
	const ModifyLogRecord *log;
	MailIndexRecord *rec;
	MailFlags flags;
        MailboxSyncCallbacks *sc;
	void *sc_context;
	const char **custom_flags;
	unsigned int count, seq, seq_count, i, first_flag_change, messages;

	/* show the log */
	log = mail_modifylog_get_nonsynced(ibox->index->modifylog, &count);
	if (log == NULL)
		return mail_storage_set_index_error(ibox);

	sc = &ibox->sync_callbacks;
	sc_context = ibox->sync_context;

	/* first show expunges. this makes it easier to deal with sequence
	   numbers. */
	messages = ibox->synced_messages_count;
	first_flag_change = count;
	for (i = 0; i < count; i++) {
		if (log[i].seq1 > messages) {
			/* client doesn't know about this message yet */
			continue;
		}

		switch (log[i].type) {
		case RECORD_TYPE_EXPUNGE:
			seq_count = (log[i].seq2 - log[i].seq1) + 1;
			messages -= seq_count;

			for (; seq_count > 0; seq_count--) {
				sc->expunge(&ibox->box, log[i].seq1,
					    sc_context);
			}
			break;
		case RECORD_TYPE_FLAGS_CHANGED:
			if (first_flag_change == count)
				first_flag_change = i;
			break;
		}
	}

	/* now show the flags */
	messages = ibox->synced_messages_count;
	custom_flags = mail_custom_flags_list_get(ibox->index->custom_flags);
	for (i = first_flag_change; i < count; i++) {
		if (log[i].seq1 > messages) {
			/* client doesn't know about this message yet */
			continue;
		}

		switch (log[i].type) {
		case RECORD_TYPE_EXPUNGE:
			messages -= (log[i].seq2 - log[i].seq1) + 1;
			break;
		case RECORD_TYPE_FLAGS_CHANGED:
			rec = ibox->index->lookup_uid_range(ibox->index,
							    log[i].uid1,
							    log[i].uid2, &seq);
			while (rec != NULL && rec->uid <= log[i].uid2) {
				flags = rec->msg_flags;
				if (rec->uid >= ibox->index->first_recent_uid)
					flags |= MAIL_RECENT;

				sc->update_flags(&ibox->box, seq, rec->uid,
						 flags, custom_flags,
						 MAIL_CUSTOM_FLAGS_COUNT,
						 sc_context);

                                seq++;
				rec = ibox->index->next(ibox->index, rec);
			}
			break;
		}
	}

	ibox->synced_messages_count = messages;

	/* mark synced */
	if (!mail_modifylog_mark_synced(ibox->index->modifylog))
		return mail_storage_set_index_error(ibox);

	return TRUE;
}

int index_storage_sync(Mailbox *box, int sync_expunges)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	int failed;

	if (!index_storage_sync_index_if_possible(ibox, FALSE))
		return FALSE;

	if (!sync_expunges) {
		/* FIXME: we could still send flag changes */
		failed = FALSE;
	} else {
		if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_SHARED))
			return mail_storage_set_index_error(ibox);

		failed = !index_storage_sync_modifylog(ibox);
	}

	/* check size only if we're locked (== at least something changed) */
	if (ibox->index->lock_type != MAIL_LOCK_UNLOCK)
		index_storage_sync_size(ibox);

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
		return mail_storage_set_index_error(ibox);

	return !failed;
}
