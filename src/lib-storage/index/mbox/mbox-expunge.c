/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mbox-storage.h"

int mbox_expunge_locked(IndexMailbox *ibox,
			MailExpungeFunc expunge_func, void *context)
{
	MailIndexRecord *rec;
	unsigned int seq, uid;

	/* FIXME: open the mbox file, lock it, and remove the deleted
	   blocks. probably better to do it in small blocks than to
	   memmove() megabytes of data.. */

	if (!index_expunge_seek_first(ibox, &seq, &rec))
		return FALSE;

	while (rec != NULL) {
		if (rec->msg_flags & MAIL_DELETED) {
			/* save UID before deletion */
			uid = rec->uid;

			if (!ibox->index->expunge(ibox->index, rec,
						  seq, FALSE))
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
