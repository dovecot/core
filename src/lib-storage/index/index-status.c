/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "index-storage.h"

#define STATUS_MESSAGE_COUNTS \
	(STATUS_MESSAGES | STATUS_RECENT | STATUS_UIDNEXT | \
	 STATUS_UIDVALIDITY | STATUS_UNSEEN | STATUS_FIRST_UNSEEN_SEQ)

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

int index_storage_get_status(struct mailbox *box,
			     enum mailbox_status_items items,
			     struct mailbox_status *status)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	const struct mail_index_header *hdr;

	memset(status, 0, sizeof(struct mailbox_status));

	if ((items & STATUS_MESSAGE_COUNTS) != 0) {
		/* sync mailbox to update message counts */
		if (mailbox_sync(box, 0) < 0)
			return -1;
	}

	/* we can get most of the status items without any trouble */
	if (mail_index_get_header(ibox->view, &hdr) < 0)
		return -1;
	if ((items & STATUS_MESSAGE_COUNTS) != 0) {
		status->messages = hdr->messages_count;
		status->unseen = hdr->messages_count - hdr->seen_messages_count;
		status->uidvalidity = hdr->uid_validity;
		status->uidnext = hdr->next_uid;
	}
	//FIXME:status->diskspace_full = ibox->nodiskspace;

	if (items & STATUS_FIRST_UNSEEN_SEQ) {
		if (mail_index_lookup_first(ibox->view, 0, MAIL_SEEN,
					    &status->first_unseen_seq) < 0) {
			mail_storage_set_index_error(ibox);
			return -1;
		}
	}

	if ((items & STATUS_RECENT) != 0)
		status->recent = ibox->get_recent_count(ibox);

	/*FIXME:if (items & STATUS_KEYWORDS)
		get_keywords(ibox, status);*/

	mail_index_view_unlock(ibox->view);
	return 0;
}
