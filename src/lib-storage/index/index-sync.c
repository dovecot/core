/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"
#include "mail-index-util.h"
#include "mail-modifylog.h"
#include "mail-custom-flags.h"

/* may leave the index locked */
int index_storage_sync_index_if_possible(IndexMailbox *ibox)
{
	unsigned int messages, recent;
	const char **custom_flags;

	if (ibox->index->sync(ibox->index)) {
		/* reset every time it has worked */
		ibox->sent_diskspace_warning = FALSE;
	} else {
		if (!ibox->index->is_diskspace_error(ibox->index)) {
			(void)ibox->index->set_lock(ibox->index,
						    MAIL_LOCK_UNLOCK);
			return mail_storage_set_index_error(ibox);
		}

		/* notify client once about it */
		if (!ibox->sent_diskspace_warning) {
			ibox->sent_diskspace_warning = TRUE;
			ibox->sync_callbacks.alert_no_diskspace(
						&ibox->box, ibox->sync_context);
		}

		index_reset_error(ibox->index);
	}

	/* notify about changes in mailbox size. */
	if (ibox->index->lock_type == MAIL_LOCK_UNLOCK)
		return TRUE; /* no changes - must be no new mail either */

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

	/* notify changes in custom flags */
	if (mail_custom_flags_has_changes(ibox->index->custom_flags)) {
		custom_flags = mail_custom_flags_list_get(
					ibox->index->custom_flags);
		ibox->sync_callbacks.new_custom_flags(
			&ibox->box, custom_flags, MAIL_CUSTOM_FLAGS_COUNT,
			ibox->sync_context);
		mail_custom_flags_list_unref(ibox->index->custom_flags);
	}

	return TRUE;
}

int index_storage_sync_modifylog(IndexMailbox *ibox)
{
	ModifyLogRecord *log;
	MailIndexRecord *rec;
	MailFlags flags;
        MailboxSyncCallbacks *sc;
	void *sc_context;
	const char **custom_flags;
	unsigned int count, seq;

	/* show the log */
	log = mail_modifylog_get_nonsynced(ibox->index->modifylog, &count);
	if (log == NULL)
		return mail_storage_set_index_error(ibox);

	sc = &ibox->sync_callbacks;
	sc_context = ibox->sync_context;

	custom_flags = mail_custom_flags_list_get(ibox->index->custom_flags);
	for (; count > 0; count--, log++) {
		if (log->seq > ibox->synced_messages_count) {
			/* client doesn't know about this message yet */
			continue;
		}

		switch (log->type) {
		case RECORD_TYPE_EXPUNGE:
			sc->expunge(&ibox->box, log->seq,
				    log->uid, sc_context);
                        ibox->synced_messages_count--;
			break;
		case RECORD_TYPE_FLAGS_CHANGED:
			rec = ibox->index->lookup_uid_range(ibox->index,
							    log->uid, log->uid,
							    &seq);
			if (rec == NULL)
				break;

			flags = rec->msg_flags;
			if (rec->uid >= ibox->index->first_recent_uid)
				flags |= MAIL_RECENT;

			sc->update_flags(&ibox->box, log->seq, log->uid, flags,
					 custom_flags, MAIL_CUSTOM_FLAGS_COUNT,
					 sc_context);
			break;
		}
	}
	mail_custom_flags_list_unref(ibox->index->custom_flags);

	/* mark synced */
	if (!mail_modifylog_mark_synced(ibox->index->modifylog))
		return mail_storage_set_index_error(ibox);

	return TRUE;
}

int index_storage_sync(Mailbox *box, int sync_expunges)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	int failed;

	if (!index_storage_sync_index_if_possible(ibox))
		return FALSE;

	if (!sync_expunges) {
		/* FIXME: we could still send flag changes */
		failed = FALSE;
	} else {
		if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_SHARED))
			return mail_storage_set_index_error(ibox);

		failed = !index_storage_sync_modifylog(ibox);
	}

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
		return mail_storage_set_index_error(ibox);

	return !failed;
}
