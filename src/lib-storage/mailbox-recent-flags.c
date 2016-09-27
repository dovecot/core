/* Copyright (c) 2002-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage-private.h"
#include "mailbox-recent-flags.h"

void mailbox_recent_flags_set_uid(struct mailbox *box, uint32_t uid)
{
	if (uid <= box->recent_flags_prev_uid) {
		if (seq_range_exists(&box->recent_flags, uid))
			return;

		mail_storage_set_critical(box->storage,
			"Recent flags state corrupted for mailbox %s",
			box->vname);
		array_clear(&box->recent_flags);
		box->recent_flags_count = 0;
	}
	mailbox_recent_flags_set_uid_forced(box, uid);
}

void mailbox_recent_flags_set_uid_forced(struct mailbox *box, uint32_t uid)
{
	box->recent_flags_prev_uid = uid;

	if (!mailbox_recent_flags_have_uid(box, uid)) {
		seq_range_array_add_with_init(&box->recent_flags, 64, uid);
		box->recent_flags_count++;
	}
}

void mailbox_recent_flags_set_seqs(struct mailbox *box,
				   struct mail_index_view *view,
				   uint32_t seq1, uint32_t seq2)
{
	uint32_t uid;

	for (; seq1 <= seq2; seq1++) {
		mail_index_lookup_uid(view, seq1, &uid);
		mailbox_recent_flags_set_uid(box, uid);
	}
}

bool mailbox_recent_flags_have_uid(struct mailbox *box, uint32_t uid)
{
	return array_is_created(&box->recent_flags) &&
		seq_range_exists(&box->recent_flags, uid);
}

void mailbox_recent_flags_reset(struct mailbox *box)
{
	if (array_is_created(&box->recent_flags))
		array_clear(&box->recent_flags);
	box->recent_flags_count = 0;
	box->recent_flags_prev_uid = 0;
}

unsigned int mailbox_recent_flags_count(struct mailbox *box)
{
	const struct mail_index_header *hdr;
	const struct seq_range *range;
	unsigned int i, count, recent_count;

	if (!array_is_created(&box->recent_flags))
		return 0;

	hdr = mail_index_get_header(box->view);
	recent_count = box->recent_flags_count;
	range = array_get(&box->recent_flags, &count);
	for (i = count; i > 0; ) {
		i--;
		if (range[i].seq2 < hdr->next_uid)
			break;

		if (range[i].seq1 >= hdr->next_uid) {
			/* completely invisible to this view */
			recent_count -= range[i].seq2 - range[i].seq1 + 1;
		} else {
			/* partially invisible */
			recent_count -= range[i].seq2 - hdr->next_uid + 1;
			break;
		}
	}
	return recent_count;
}

void mailbox_recent_flags_expunge_seqs(struct mailbox *box,
				       uint32_t seq1, uint32_t seq2)
{
	uint32_t uid;

	if (!array_is_created(&box->recent_flags))
		return;

	for (; seq1 <= seq2; seq1++) {
		mail_index_lookup_uid(box->view, seq1, &uid);
		if (seq_range_array_remove(&box->recent_flags, uid))
			box->recent_flags_count--;
	}
}

void mailbox_recent_flags_expunge_uid(struct mailbox *box, uint32_t uid)
{
	if (array_is_created(&box->recent_flags)) {
		if (seq_range_array_remove(&box->recent_flags, uid))
			box->recent_flags_count--;
	}
}
