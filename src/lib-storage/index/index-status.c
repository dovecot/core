/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"

/*static void
get_keywords(struct mail_keywords *mcf, struct mailbox_status *status)
{
	const char **flags;
	unsigned int i;

	status->keywords_count = MAIL_KEYWORDS_COUNT;
	status->keywords = t_new(const char *, MAIL_KEYWORDS_COUNT);

	flags = mail_keywords_list_get(mcf);
	for (i = 0; i < MAIL_KEYWORDS_COUNT; i++)
		status->keywords[i] = t_strdup(flags[i]);
}*/

int index_storage_get_status_locked(struct index_mailbox *ibox,
				    enum mailbox_status_items items,
				    struct mailbox_status *status_r)
{
	const struct mail_index_header *hdr;

	memset(status_r, 0, sizeof(struct mailbox_status));

	/* we can get most of the status items without any trouble */
	hdr = mail_index_get_header(ibox->view);
	status_r->messages = hdr->messages_count;
	status_r->recent = ibox->synced_recent_count;
	status_r->unseen =
		hdr->messages_count - hdr->seen_messages_count;
	status_r->uidvalidity = hdr->uid_validity;
	status_r->uidnext = hdr->next_uid;
	//FIXME:status_r->diskspace_full = ibox->nodiskspace;

	if (items & STATUS_FIRST_UNSEEN_SEQ) {
		if (mail_index_lookup_first(ibox->view, 0, MAIL_SEEN,
					    &status_r->first_unseen_seq) < 0) {
			mail_storage_set_index_error(ibox);
			return -1;
		}
	}

	/*FIXME:if (items & STATUS_KEYWORDS)
		get_keywords(ibox, status_r);*/
	return 0;
}

int index_storage_get_status(struct mailbox *box,
			     enum mailbox_status_items items,
			     struct mailbox_status *status)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
	int ret;

	ret = index_storage_get_status_locked(ibox, items, status);
	mail_index_view_unlock(ibox->view);
	return ret;
}
