/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-index.h"
#include "mail-index-util.h"

#define CHECK(field) \
	if (old_hdr->field != new_hdr->field) \
		i_warning("fsck: "#field" %u != %u", \
			  old_hdr->field, new_hdr->field);


static void print_differences(MailIndexHeader *old_hdr,
			      MailIndexHeader *new_hdr)
{
	if (old_hdr->first_hole_index != new_hdr->first_hole_index) {
		i_warning("fsck: first_hole_position %u != %u",
			  old_hdr->first_hole_index,
			  new_hdr->first_hole_index);
	}
	CHECK(first_hole_records);

	CHECK(next_uid);

	CHECK(messages_count);
	CHECK(seen_messages_count);
	CHECK(deleted_messages_count);
	CHECK(last_nonrecent_uid);

	if (new_hdr->first_unseen_uid_lowwater != 0 &&
	    old_hdr->first_unseen_uid_lowwater >
	    new_hdr->first_unseen_uid_lowwater) {
		i_warning("fsck: first_unseen_uid_lowwater %u > %u",
			  old_hdr->first_unseen_uid_lowwater,
                          new_hdr->first_unseen_uid_lowwater);
	}

	if (new_hdr->first_deleted_uid_lowwater != 0 &&
	    old_hdr->first_deleted_uid_lowwater >
	    new_hdr->first_deleted_uid_lowwater) {
		i_warning("fsck: first_deleted_uid_lowwater %u > %u",
			  old_hdr->first_deleted_uid_lowwater,
                          new_hdr->first_deleted_uid_lowwater);
	}
}

int mail_index_fsck(MailIndex *index)
{
	/* we verify only the fields in the header. other problems will be
	   noticed and fixed while reading the messages. */
	MailIndexHeader old_hdr;
	MailIndexHeader *hdr;
	MailIndexRecord *rec, *end_rec;
	unsigned int max_uid, pos;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (!mail_index_set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	hdr = index->header;
	memcpy(&old_hdr, hdr, sizeof(MailIndexHeader));

	hdr->first_hole_index = 0;
	hdr->first_hole_records = 0;

	hdr->messages_count = 0;
	hdr->seen_messages_count = 0;
	hdr->deleted_messages_count = 0;

	hdr->first_unseen_uid_lowwater = 0;
	hdr->first_deleted_uid_lowwater = 0;

	rec = (MailIndexRecord *) ((char *) index->mmap_base +
				   sizeof(MailIndexHeader));
	end_rec = (MailIndexRecord *) ((char *) index->mmap_base +
				       index->mmap_used_length);

	max_uid = 0;
	for (; rec < end_rec; rec++) {
		if (rec->uid == 0) {
			/* expunged message */
			pos = INDEX_RECORD_INDEX(index, rec);
			if (hdr->first_hole_index == 0) {
				hdr->first_hole_index = pos;
				hdr->first_hole_records = 1;
			} else if (hdr->first_hole_index +
				   hdr->first_hole_records == pos) {
				/* hole continues */
				hdr->first_hole_records++;
			}
			continue;
		}

		if (rec->uid < max_uid) {
			index_set_corrupted(index, "UIDs are not ordered "
					    "(%u < %u)", rec->uid, max_uid);
			return FALSE;
		}
		max_uid = rec->uid;

		if (rec->msg_flags & MAIL_SEEN)
			hdr->seen_messages_count++;
		else if (hdr->first_unseen_uid_lowwater)
			hdr->first_unseen_uid_lowwater = rec->uid;

		if (rec->msg_flags & MAIL_DELETED) {
			if (hdr->first_deleted_uid_lowwater == 0)
                                hdr->first_deleted_uid_lowwater = rec->uid;
			hdr->deleted_messages_count++;
		}
		hdr->messages_count++;
	}

	if (hdr->next_uid <= max_uid)
		hdr->next_uid = max_uid+1;
	if (hdr->last_nonrecent_uid >= hdr->next_uid)
		hdr->last_nonrecent_uid = hdr->next_uid-1;

	print_differences(&old_hdr, hdr);

	/* FSCK flag is removed automatically by set_lock() */
	return TRUE;
}
