/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "maildir-storage.h"

#include <unistd.h>

static int expunge_msg(IndexMailbox *ibox, MailIndexRecord *rec,
		       unsigned int seq)
{
	const char *fname;
	char path[1024];

	/* get our file name - ignore if it's missing,
	   we're deleting it after all.. */
	fname = ibox->index->lookup_field(ibox->index, rec,
					  FIELD_TYPE_LOCATION);
	if (fname != NULL) {
		i_snprintf(path, sizeof(path), "%s/cur/%s",
			   ibox->index->dir, fname);
		if (unlink(path) == -1 && errno != ENOENT) {
			mail_storage_set_error(ibox->box.storage,
					       "unlink() failed for "
					       "message file %s: %m", path);
			/* continue anyway */
		}
	}

	return ibox->index->expunge(ibox->index, rec, seq, FALSE);

}

int maildir_expunge_locked(IndexMailbox *ibox,
			   MailExpungeFunc expunge_func, void *context)
{
	MailIndexRecord *rec;
	unsigned int seq, uid;

	if (!index_expunge_seek_first(ibox, &seq, &rec))
		return FALSE;

	while (rec != NULL) {
		if (rec->msg_flags & MAIL_DELETED) {
			/* save UID before deletion */
			uid = rec->uid;

			if (!expunge_msg(ibox, rec, seq))
				return FALSE;

			if (expunge_func != NULL)
				expunge_func(&ibox->box, seq, uid, context);
			seq--;
		}
		rec = ibox->index->next(ibox->index, rec);
		seq++;
	}

	return TRUE;
}
