/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "maildir-index.h"
#include "maildir-storage.h"

int maildir_expunge_locked(struct index_mailbox *ibox, int notify)
{
	struct mail_index_record *rec, *first_rec, *last_rec;
	unsigned int seq, first_seq, last_seq;
	int ret, no_permission = FALSE;

	if (!index_expunge_seek_first(ibox, &seq, &rec))
		return FALSE;

	first_rec = last_rec = NULL;
	first_seq = last_seq = 0;
	while (rec != NULL) {
		if ((rec->msg_flags & MAIL_DELETED) == 0)
			ret = FALSE;
		else {
			t_push();
			ret = maildir_expunge_mail(ibox->index, rec);
			t_pop();

			if (!ret) {
				if (errno != EACCES)
					return FALSE;
				no_permission = TRUE;
			} else {
				if (first_rec == NULL) {
					first_rec = rec;
					first_seq = seq;
				}
				last_rec = rec;
				last_seq = seq;
			}
		}

		if (!ret && first_rec != NULL) {
			if (!index_expunge_mails(ibox, first_rec, last_rec,
						 first_seq, last_seq, notify))
				return FALSE;
			first_rec = NULL;

			seq = first_seq;
			rec = ibox->index->lookup(ibox->index, seq);
		} else {
			seq++;
			rec = ibox->index->next(ibox->index, rec);
		}
	}

	if (first_rec != NULL) {
		if (!index_expunge_mails(ibox, first_rec, last_rec,
					 first_seq, last_seq, notify))
			return FALSE;
	}

	if (no_permission) {
		ibox->box.storage->callbacks->notify_no(&ibox->box,
			"We didn't have permission to expunge all the mails",
			ibox->box.storage->callback_context);
	}

	return TRUE;
}
