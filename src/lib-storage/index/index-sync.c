/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "index-storage.h"
#include "mail-index-util.h"
#include "mail-modifylog.h"
#include "mail-custom-flags.h"

static void index_storage_sync_size(struct index_mailbox *ibox)
{
	struct mail_storage *storage = ibox->box.storage;
	unsigned int messages, recent;

	if (storage->callbacks->new_messages == NULL)
		return;

	messages = ibox->index->get_header(ibox->index)->messages_count;
	messages += mail_modifylog_get_expunge_count(ibox->index->modifylog);

	if (messages != ibox->synced_messages_count) {
		i_assert(messages > ibox->synced_messages_count);

		/* new messages in mailbox */
		recent = index_storage_get_recent_count(ibox->index);
		storage->callbacks->new_messages(&ibox->box, messages, recent,
						 storage->callback_context);
		ibox->synced_messages_count = messages;
	}
}

int index_storage_sync_and_lock(struct index_mailbox *ibox, int sync_size,
				enum mail_lock_type data_lock_type)
{
	struct mail_storage *storage = ibox->box.storage;
	struct mail_index *index = ibox->index;
	int failed, changes, set_shared_lock;

        set_shared_lock = ibox->index->lock_type != MAIL_LOCK_EXCLUSIVE;

        index_storage_init_lock_notify(ibox);
	failed = !index->sync_and_lock(index, data_lock_type, &changes);
	ibox->index->set_lock_notify_callback(ibox->index, NULL, NULL);

	if (!failed) {
		/* reset every time it has worked */
		ibox->sent_diskspace_warning = FALSE;
	} else {
		if (index->get_last_error(index) !=
		    MAIL_INDEX_ERROR_DISKSPACE) {
			(void)index_storage_lock(ibox, MAIL_LOCK_UNLOCK);
			return mail_storage_set_index_error(ibox);
		}

		/* notify client once about it */
		if (!ibox->sent_diskspace_warning &&
		    storage->callbacks->alert_no_diskspace != NULL) {
			ibox->sent_diskspace_warning = TRUE;
			storage->callbacks->alert_no_diskspace(
				&ibox->box, storage->callback_context);
		}

		index_reset_error(index);
	}

	if (set_shared_lock) {
		/* just make sure we are locked, and that we drop our
		   exclusive lock if it wasn't wanted originally */
		if (!index_storage_lock(ibox, MAIL_LOCK_SHARED)) {
			(void)index_storage_lock(ibox, MAIL_LOCK_UNLOCK);
			return FALSE;
		}
	}

	/* notify about changes in mailbox size. */
	if (!changes)
		return TRUE; /* no changes - must be no new mail either */

	if (sync_size)
		index_storage_sync_size(ibox);

	/* notify changes in custom flags */
	if (mail_custom_flags_has_changes(index->custom_flags) &&
	    storage->callbacks->new_custom_flags != NULL) {
		storage->callbacks->new_custom_flags(&ibox->box,
                	mail_custom_flags_list_get(index->custom_flags),
			MAIL_CUSTOM_FLAGS_COUNT, storage->callback_context);
	}

	return TRUE;
}

int index_storage_sync_modifylog(struct index_mailbox *ibox, int hide_deleted)
{
	const struct modify_log_record *log1, *log2, *log, *first_flag_log;
	struct mail_index_record *rec;
	enum mail_flags flags;
        struct mail_storage_callbacks *sc;
	void *sc_context;
	const char **custom_flags;
	unsigned int count1, count2, total_count, seq, seq_count, i, messages;
	unsigned int first_flag_change, first_flag_messages_count;

	/* show the log */
	if (!mail_modifylog_get_nonsynced(ibox->index->modifylog,
					  &log1, &count1, &log2, &count2))
		return mail_storage_set_index_error(ibox);

	sc = ibox->box.storage->callbacks;
	sc_context = ibox->box.storage->callback_context;

	/* first show expunges. this makes it easier to deal with sequence
	   numbers. */
	total_count = count1 + count2;
	messages = ibox->synced_messages_count;
	first_flag_change = total_count;
	first_flag_log = NULL;
        first_flag_messages_count = 0;

	for (i = 0, log = log1; i < total_count; i++, log++) {
		if (i == count1)
			log = log2;

		if (log->seq1 > messages) {
			/* client doesn't know about this message yet */
			continue;
		}

		switch (log->type) {
		case RECORD_TYPE_EXPUNGE:
			seq_count = (log->seq2 - log->seq1) + 1;
			messages -= seq_count;

			if (sc->expunge == NULL)
				break;

			for (; seq_count > 0; seq_count--) {
				sc->expunge(&ibox->box, log->seq1,
					    sc_context);
			}
			break;
		case RECORD_TYPE_FLAGS_CHANGED:
			if (first_flag_change == total_count) {
				first_flag_change = i;
				first_flag_log = log;
				first_flag_messages_count = messages;
			}
			break;
		}
	}

	/* set synced messages count before flag changes break it */
	ibox->synced_messages_count = messages;

	/* now show the flags */
	messages = first_flag_messages_count;
	custom_flags = mail_custom_flags_list_get(ibox->index->custom_flags);

	if (sc->update_flags == NULL) {
		/* don't bother going through, we're not printing them anyway */
		total_count = 0;
	}

	log = first_flag_log;
	for (i = first_flag_change; i < total_count; i++, log++) {
		if (i == count1)
			log = log2;

		if (log->seq1 > messages) {
			/* client doesn't know about this message yet */
			continue;
		}

		switch (log->type) {
		case RECORD_TYPE_EXPUNGE:
			messages -= (log->seq2 - log->seq1) + 1;
			break;
		case RECORD_TYPE_FLAGS_CHANGED:
			rec = ibox->index->lookup_uid_range(ibox->index,
							    log->uid1,
							    log->uid2, &seq);
			while (rec != NULL && rec->uid <= log->uid2) {
				flags = rec->msg_flags;
				if (rec->uid >= ibox->index->first_recent_uid)
					flags |= MAIL_RECENT;

				/* \Deleted-hiding is useful when syncing just
				   before doing EXPUNGE. */
				if ((flags & MAIL_DELETED) == 0 ||
				    !hide_deleted) {
					sc->update_flags(
						&ibox->box, seq, rec->uid,
						flags, custom_flags,
						MAIL_CUSTOM_FLAGS_COUNT,
						sc_context);
				}

                                seq++;
				rec = ibox->index->next(ibox->index, rec);
			}
			break;
		}
	}

	/* mark synced */
	if (!mail_modifylog_mark_synced(ibox->index->modifylog))
		return mail_storage_set_index_error(ibox);

	return TRUE;
}

int index_storage_sync(struct mailbox *box, int sync_expunges)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	int ret;

	ibox->last_check = ioloop_time;

	if (!index_storage_sync_and_lock(ibox, FALSE, MAIL_LOCK_UNLOCK))
		return FALSE;

	/* FIXME: we could sync flags always, but expunges in the middle
	   could make it a bit more difficult and slower */
	if (sync_expunges ||
	    mail_modifylog_get_expunge_count(ibox->index->modifylog) == 0)
		ret = index_storage_sync_modifylog(ibox, FALSE);
	else
		ret = TRUE;

	index_storage_sync_size(ibox);

	if (!index_storage_lock(ibox, MAIL_LOCK_UNLOCK))
		return FALSE;

	return ret;
}
