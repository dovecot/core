/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "maildir-index.h"
#include "maildir-storage.h"

int maildir_expunge_locked(struct index_mailbox *ibox, int notify)
{
	struct mail_index_record *rec;
	unsigned int seq;
	int ret, no_permission = FALSE;

	if (!index_expunge_seek_first(ibox, &seq, &rec))
		return FALSE;

	while (rec != NULL) {
		if (rec->msg_flags & MAIL_DELETED) {
			t_push();
			ret = maildir_expunge_mail(ibox->index, rec);
			t_pop();

			if (!ret) {
				if (errno != EACCES)
					return FALSE;
				no_permission = TRUE;
				seq++;
			} else {
				if (!index_expunge_mail(ibox, rec, seq, notify))
					return FALSE;
			}
		} else {
			seq++;
		}

		rec = ibox->index->next(ibox->index, rec);
	}

	if (no_permission) {
		ibox->box.storage->callbacks->notify_no(&ibox->box,
			"We didn't have permission to expunge all the mails",
			ibox->box.storage->callback_context);
	}

	return TRUE;
}
