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

static int index_storage_sync_log(Mailbox *box, MailIndex *index,
				  MailExpungeFunc expunge_func,
				  MailFlagUpdateFunc flag_func,
				  void *context)
{
	ModifyLogRecord *log;
	MailIndexRecord *rec;
	MailFlags flags;
	const char **custom_flags;
	unsigned int count, seq;

	/* show the log */
	log = mail_modifylog_get_nonsynced(index->modifylog, &count);
	if (log == NULL)
		return FALSE;

	custom_flags = mail_custom_flags_list_get(index->custom_flags);
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

			rec = index->lookup_uid_range(index,
						      log->uid, log->uid, &seq);
			if (rec != NULL) {
				flags = rec->msg_flags;
				if (rec->uid >= index->first_recent_uid)
					flags |= MAIL_RECENT;

				flag_func(box, log->seq, log->uid, flags,
					  custom_flags, context);
			}
			break;
		}
	}
	mail_custom_flags_list_unref(index->custom_flags);

	/* mark synced */
	return mail_modifylog_mark_synced(index->modifylog);
}

int index_storage_sync(Mailbox *box, int expunge,
		       unsigned int *messages, unsigned int *recent,
		       MailExpungeFunc expunge_func,
		       MailFlagUpdateFunc flag_func,
		       void *context)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	unsigned int count;
	int failed;

	if (expunge && box->readonly) {
		mail_storage_set_error(box->storage, "Mailbox is read-only");
		return FALSE;
	}

	*messages = *recent = 0;

	if (!index_storage_sync_if_possible(ibox))
		return FALSE;

	if (!ibox->index->set_lock(ibox->index, expunge ?
				   MAIL_LOCK_EXCLUSIVE : MAIL_LOCK_SHARED))
		return mail_storage_set_index_error(ibox);

	failed = FALSE;

	if (expunge_func != NULL || flag_func != NULL) {
		failed = !index_storage_sync_log(box, ibox->index, expunge_func,
						 flag_func, context);
	}

	if (!failed && expunge) {
		/* expunge messages */
		failed = !ibox->expunge_locked(ibox, expunge_func, context);
	}

	/* get the messages count even if there was some failures.
	   also it must be done after expunging messages */
	count = ibox->index->get_header(ibox->index)->messages_count;
	count += mail_modifylog_get_expunge_count(ibox->index->modifylog);
	if (count != ibox->synced_messages_count) {
		if (count > ibox->synced_messages_count) {
			/* new messages in mailbox */
			*messages = count;
			*recent = index_storage_get_recent_count(ibox->index);
		}
		ibox->synced_messages_count = count;
	}

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK) || failed)
		return mail_storage_set_index_error(ibox);
	return TRUE;
}
