/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "mail-index.h"
#include "mail-index-util.h"

#define CHECK(field) \
	if (old_hdr->field != new_hdr->field) \
		i_warning("fsck %s: "#field" %u != %u", \
			  index->filepath, old_hdr->field, new_hdr->field);


static void print_differences(struct mail_index *index,
			      struct mail_index_header *old_hdr,
			      struct mail_index_header *new_hdr)
{
	CHECK(next_uid);

	CHECK(messages_count);
	CHECK(seen_messages_count);
	CHECK(deleted_messages_count);
	CHECK(last_nonrecent_uid);

	if (old_hdr->first_unseen_uid_lowwater >
	    new_hdr->first_unseen_uid_lowwater) {
		i_warning("fsck %s: first_unseen_uid_lowwater %u > %u",
			  index->filepath,
			  old_hdr->first_unseen_uid_lowwater,
                          new_hdr->first_unseen_uid_lowwater);
	}

	if (old_hdr->first_deleted_uid_lowwater >
	    new_hdr->first_deleted_uid_lowwater) {
		i_warning("fsck %s: first_deleted_uid_lowwater %u > %u",
			  index->filepath,
			  old_hdr->first_deleted_uid_lowwater,
                          new_hdr->first_deleted_uid_lowwater);
	}
}

int mail_index_fsck(struct mail_index *index)
{
	struct mail_index_header old_hdr, *hdr;
	struct mail_index_record *rec, *end_rec;
	unsigned int max_uid;

	i_assert(index->lock_type != MAIL_LOCK_SHARED);

	if (!mail_index_compress(index))
		return FALSE;

	/* then we verify only the fields in the header. other problems will
	   be noticed and fixed while reading the messages. */
	hdr = index->header;
	memcpy(&old_hdr, hdr, sizeof(struct mail_index_header));

	hdr->messages_count = 0;
	hdr->seen_messages_count = 0;
	hdr->deleted_messages_count = 0;

	hdr->first_unseen_uid_lowwater = 0;
	hdr->first_deleted_uid_lowwater = 0;

	rec = INDEX_RECORD_AT(index, 0);
	end_rec = INDEX_END_RECORD(index);

	max_uid = 0;
	for (; rec < end_rec; rec++) {
		if (rec->uid < max_uid) {
			index_set_corrupted(index, "UIDs are not ordered "
					    "(%u < %u)", rec->uid, max_uid);
			return FALSE;
		}
		max_uid = rec->uid;

		if (rec->msg_flags & MAIL_SEEN)
			hdr->seen_messages_count++;
		else if (hdr->first_unseen_uid_lowwater == 0)
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

	if (hdr->first_unseen_uid_lowwater == 0)
		hdr->first_unseen_uid_lowwater = hdr->next_uid;
	if (hdr->first_deleted_uid_lowwater == 0)
		hdr->first_deleted_uid_lowwater = hdr->next_uid;

	print_differences(index, &old_hdr, hdr);

	/* FSCK flag is removed automatically by set_lock() */
	return TRUE;
}
