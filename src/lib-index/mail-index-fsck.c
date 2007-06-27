/* Copyright (C) 2004-2007 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "mail-index-private.h"
#include "mail-transaction-log.h"

static void mail_index_fsck_error(struct mail_index *index,
				  const char *fmt, ...) __attr_format__(2, 3);
static void mail_index_fsck_error(struct mail_index *index,
				  const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	mail_index_set_error(index, "Fixed index file %s: %s",
			     index->filepath, t_strdup_vprintf(fmt, va));
	va_end(va);
}

#define CHECK(field, oper) \
	if (hdr.field oper map->hdr.field) { \
		mail_index_fsck_error(index, #field" %u -> %u", \
				      map->hdr.field, hdr.field); \
	}

static int
mail_index_fsck_map(struct mail_index *index, struct mail_index_map *map,
		    bool *lock, const char **error_r)
{
	struct mail_index_header hdr;
	const struct mail_index_record *rec;
	uint32_t file_seq;
	uoff_t file_offset;
	uint32_t i, last_uid;

	*error_r = NULL;

	if (*lock) {
		if (mail_transaction_log_sync_lock(index->log, &file_seq,
						   &file_offset) < 0) {
			*lock = FALSE;
			return -1;
		}
	} else {
		mail_transaction_log_get_head(index->log, &file_seq,
					      &file_offset);
	}

	/* Remember the log head position. If we go back in the index's head
	   offset, ignore errors in the log up to this offset. */
	index->fsck_log_head_file_seq = file_seq;
	index->fsck_log_head_file_offset = file_offset;

	/* locking already does the most important sanity checks for header */
	hdr = map->hdr;

	if (hdr.uid_validity == 0 && hdr.next_uid != 1)
		hdr.uid_validity = ioloop_time;

	hdr.flags &= ~MAIL_INDEX_HDR_FLAG_FSCK;

	if (hdr.log_file_seq < file_seq) {
		hdr.log_file_head_offset = hdr.log_file_tail_offset =
			sizeof(struct mail_transaction_log_header);
	} else {
		if (hdr.log_file_head_offset > file_offset)
			hdr.log_file_head_offset = file_offset;
		if (hdr.log_file_tail_offset > hdr.log_file_head_offset)
			hdr.log_file_tail_offset = hdr.log_file_head_offset;
	}
	hdr.log_file_seq = file_seq;

	hdr.messages_count = 0;
	hdr.recent_messages_count = 0;
	hdr.seen_messages_count = 0;
	hdr.deleted_messages_count = 0;

	hdr.first_recent_uid_lowwater = 0;
	hdr.first_unseen_uid_lowwater = 0;
	hdr.first_deleted_uid_lowwater = 0;

	rec = map->records; last_uid = 0;
	for (i = 0; i < map->records_count; i++) {
		if (rec->uid <= last_uid) {
			*error_r = "Record UIDs are not ordered";
			return 0;
		}

		hdr.messages_count++;
		if ((rec->flags & MAIL_RECENT) != 0)
			hdr.recent_messages_count++;
		if ((rec->flags & MAIL_SEEN) != 0)
			hdr.seen_messages_count++;
		if ((rec->flags & MAIL_DELETED) != 0)
			hdr.deleted_messages_count++;

		if ((rec->flags & MAIL_RECENT) != 0 &&
		    hdr.first_recent_uid_lowwater == 0)
			hdr.first_recent_uid_lowwater = rec->uid;
		if ((rec->flags & MAIL_SEEN) == 0 &&
		    hdr.first_unseen_uid_lowwater == 0)
			hdr.first_unseen_uid_lowwater = rec->uid;
		if ((rec->flags & MAIL_DELETED) != 0 &&
		    hdr.first_deleted_uid_lowwater == 0)
			hdr.first_deleted_uid_lowwater = rec->uid;

		last_uid = rec->uid;
		rec = CONST_PTR_OFFSET(rec, hdr.record_size);
	}

	if (hdr.next_uid <= last_uid) {
		mail_index_fsck_error(index, "next_uid %u -> %u",
				      hdr.next_uid, last_uid+1);
		hdr.next_uid = last_uid+1;
	}

	if (hdr.first_recent_uid_lowwater == 0)
                hdr.first_recent_uid_lowwater = hdr.next_uid;
	if (hdr.first_unseen_uid_lowwater == 0)
                hdr.first_unseen_uid_lowwater = hdr.next_uid;
	if (hdr.first_deleted_uid_lowwater == 0)
                hdr.first_deleted_uid_lowwater = hdr.next_uid;

        CHECK(log_file_seq, !=);
        CHECK(log_file_head_offset, !=);
        CHECK(log_file_tail_offset, !=);

	CHECK(uid_validity, !=);
        CHECK(messages_count, !=);
        CHECK(recent_messages_count, !=);
        CHECK(seen_messages_count, !=);
        CHECK(deleted_messages_count, !=);

        CHECK(first_recent_uid_lowwater, <);
        CHECK(first_unseen_uid_lowwater, <);
	CHECK(first_deleted_uid_lowwater, <);

	map->hdr = hdr;
	return 1;
}

int mail_index_fsck(struct mail_index *index)
{
	const char *error = NULL;
	struct mail_index_map *map;
	bool lock = !index->log_locked;
	int ret;

	i_warning("fscking index file %s", index->filepath);

	map = mail_index_map_clone(index->map);
	mail_index_unmap(index, &index->map);
	index->map = map;

	ret = mail_index_fsck_map(index, map, &lock, &error);
	if (ret > 0) {
		map->write_base_header = TRUE;
		map->write_atomic = TRUE;

		mail_index_write(index, FALSE);
	}

	if (error != NULL) {
		mail_index_set_error(index, "Corrupted index file %s: %s",
				     index->filepath, error);
	}
	if (ret == 0)
		mail_index_mark_corrupted(index);

	if (lock)
		mail_transaction_log_sync_unlock(index->log);
	return ret;
}
