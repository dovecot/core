/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"
#include "mail-index-util.h"
#include "mail-modifylog.h"
#include "mail-custom-flags.h"

/* may leave the index locked */
int index_storage_sync_if_possible(IndexMailbox *ibox)
{
	if (!ibox->index->sync(ibox->index)) {
		if (!ibox->index->is_diskspace_error(ibox->index)) {
			(void)ibox->index->set_lock(ibox->index,
						    MAIL_LOCK_UNLOCK);
			return mail_storage_set_index_error(ibox);
		}

		/* not enough disk space to sync. can't do much about it
		   though, giving error message would just make it impossible
		   to delete messages. */
		index_reset_error(ibox->index);
	}

	return TRUE;
}

int index_storage_sync(Mailbox *box, unsigned int *messages, int expunge,
		       MailExpungeFunc expunge_func,
		       MailFlagUpdateFunc flag_func,
		       void *context)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	ModifyLogRecord *log;
	MailIndexRecord *rec;
	MailFlags flags;
	const char **custom_flags;
	unsigned int count;
	int failed;

	if (expunge && box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return FALSE;
	}

	*messages = 0;

	if (!index_storage_sync_if_possible(ibox))
		return FALSE;

	if (!ibox->index->set_lock(ibox->index, expunge ?
				   MAIL_LOCK_EXCLUSIVE : MAIL_LOCK_SHARED))
		return mail_storage_set_index_error(ibox);

	/* show the log */
	log = mail_modifylog_get_nonsynced(ibox->index->modifylog, &count);
	if (log == NULL)
		failed = TRUE;

	custom_flags = mail_custom_flags_list_get(ibox->index->custom_flags);
	for (; count > 0; count--, log++) {
		switch (log->type) {
		case RECORD_TYPE_EXPUNGE:
			if (expunge_func != NULL) {
				expunge_func(box, log->seq,
					     log->uid, context);
			}
			break;
		case RECORD_TYPE_FLAGS_CHANGED:
			if (flag_func == NULL)
				break;

			rec = ibox->index->lookup_uid_range(ibox->index,
							    log->uid, log->uid);
			if (rec != NULL) {
				flags = rec->msg_flags;
				if (rec->uid >= ibox->index->first_recent_uid)
					flags |= MAIL_RECENT;

				flag_func(box, log->seq, log->uid, flags,
					  custom_flags, context);
			}
			break;
		}
	}
	mail_custom_flags_list_unref(ibox->index->custom_flags);

	/* mark synced */
	failed = !mail_modifylog_mark_synced(ibox->index->modifylog);

	if (!failed && expunge) {
		/* expunge messages */
		failed = !ibox->expunge_locked(ibox, expunge_func, context);
	}

	/* get the messages count even if there was some failures.
	   also it must be done after expunging messages */
	count = ibox->index->get_header(ibox->index)->messages_count;
	if (count != ibox->synced_messages_count) {
		if (count > ibox->synced_messages_count) {
			/* new messages in mailbox */
			*messages = count;
		}
		ibox->synced_messages_count = count;
	}

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK) || failed)
		return mail_storage_set_index_error(ibox);
	return TRUE;
}
