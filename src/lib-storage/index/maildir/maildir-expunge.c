/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "maildir-storage.h"

#include <unistd.h>

static int expunge_msg(IndexMailbox *ibox, MailIndexRecord *rec)
{
	const char *fname;
	char path[1024];

	fname = ibox->index->lookup_field(ibox->index, rec,
					  DATA_FIELD_LOCATION);
	if (fname != NULL) {
		i_snprintf(path, sizeof(path), "%s/cur/%s",
			   ibox->index->dir, fname);
		if (unlink(path) < 0) {
			/* if it didn't exist, someone just had either
			   deleted it or changed it's flags */
			mail_storage_set_error(ibox->box.storage,
					       "unlink() failed for "
					       "message file %s: %m", path);
			return FALSE;
		}
	}

	return TRUE;

}

int maildir_expunge_locked(IndexMailbox *ibox, int notify)
{
	MailIndexRecord *rec;
	unsigned int seq;

	if (!index_expunge_seek_first(ibox, &seq, &rec))
		return FALSE;

	while (rec != NULL) {
		if (rec->msg_flags & MAIL_DELETED) {
			if (!expunge_msg(ibox, rec))
				return FALSE;

			if (!index_expunge_mail(ibox, rec, seq, notify))
				return FALSE;
		} else {
			seq++;
		}

		rec = ibox->index->next(ibox->index, rec);
	}

	return TRUE;
}
