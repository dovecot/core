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
	if (hdr->field oper map->hdr.field) { \
		mail_index_fsck_error(index, #field" %u -> %u", \
				      map->hdr.field, hdr->field); \
	}

static void
mail_index_fsck_header(struct mail_index *index, struct mail_index_map *map,
		       struct mail_index_header *hdr)
{
	uint32_t file_seq;
	uoff_t file_offset;

	/* mail_index_map_check_header() has already checked that the index
	   isn't completely broken. */
	if (hdr->uid_validity == 0 && hdr->next_uid != 1)
		hdr->uid_validity = ioloop_time;

	mail_transaction_log_get_head(index->log, &file_seq, &file_offset);
	if (hdr->log_file_seq < file_seq) {
		hdr->log_file_head_offset = hdr->log_file_tail_offset =
			sizeof(struct mail_transaction_log_header);
	} else {
		if (hdr->log_file_head_offset > file_offset)
			hdr->log_file_head_offset = file_offset;
		if (hdr->log_file_tail_offset > hdr->log_file_head_offset)
			hdr->log_file_tail_offset = hdr->log_file_head_offset;
	}
	hdr->log_file_seq = file_seq;

        CHECK(log_file_seq, !=);
	if (hdr->log_file_seq == map->hdr.log_file_seq) {
		/* don't bother complaining about these if file changed too */
		CHECK(log_file_head_offset, !=);
		CHECK(log_file_tail_offset, !=);
	}
}

static void
mail_index_fsck_records(struct mail_index *index, struct mail_index_map *map,
			struct mail_index_header *hdr)
{
	struct mail_index_record *rec, *next_rec;
	uint32_t i, last_uid;
	bool logged_unordered_uids = FALSE, logged_zero_uids = FALSE;
	bool records_dropped = FALSE;

	hdr->messages_count = 0;
	hdr->seen_messages_count = 0;
	hdr->deleted_messages_count = 0;

	hdr->first_unseen_uid_lowwater = 0;
	hdr->first_deleted_uid_lowwater = 0;

	rec = map->rec_map->records; last_uid = 0;
	for (i = 0; i < map->rec_map->records_count; ) {
		next_rec = PTR_OFFSET(rec, hdr->record_size);
		if (rec->uid <= last_uid) {
			/* log an error once, and skip this record */
			if (rec->uid == 0) {
				if (!logged_zero_uids) {
					mail_index_fsck_error(index,
						"Record UIDs have zeroes");
					logged_zero_uids = TRUE;
				}
			} else {
				if (!logged_unordered_uids) {
					mail_index_fsck_error(index,
						"Record UIDs unordered");
					logged_unordered_uids = TRUE;
				}
			}
			/* not the fastest way when we're skipping lots of
			   records, but this should happen rarely so don't
			   bother optimizing. */
			memmove(rec, next_rec, hdr->record_size *
				(map->rec_map->records_count - i - 1));
			map->rec_map->records_count--;
			records_dropped = TRUE;
			continue;
		}

		hdr->messages_count++;
		if ((rec->flags & MAIL_SEEN) != 0)
			hdr->seen_messages_count++;
		if ((rec->flags & MAIL_DELETED) != 0)
			hdr->deleted_messages_count++;

		if ((rec->flags & MAIL_SEEN) == 0 &&
		    hdr->first_unseen_uid_lowwater == 0)
			hdr->first_unseen_uid_lowwater = rec->uid;
		if ((rec->flags & MAIL_DELETED) != 0 &&
		    hdr->first_deleted_uid_lowwater == 0)
			hdr->first_deleted_uid_lowwater = rec->uid;

		last_uid = rec->uid;
		rec = next_rec;
		i++;
	}

	if (records_dropped) {
		/* all existing views are broken now */
		index->inconsistency_id++;
	}

	if (hdr->next_uid <= last_uid) {
		mail_index_fsck_error(index, "next_uid %u -> %u",
				      hdr->next_uid, last_uid+1);
		hdr->next_uid = last_uid+1;
	}

	if (hdr->first_unseen_uid_lowwater == 0)
                hdr->first_unseen_uid_lowwater = hdr->next_uid;
	if (hdr->first_deleted_uid_lowwater == 0)
                hdr->first_deleted_uid_lowwater = hdr->next_uid;
	if (hdr->first_recent_uid > hdr->next_uid)
		hdr->first_recent_uid = hdr->next_uid;
	if (hdr->first_recent_uid == 0)
		hdr->first_recent_uid = 1;

	CHECK(uid_validity, !=);
        CHECK(messages_count, !=);
        CHECK(seen_messages_count, !=);
        CHECK(deleted_messages_count, !=);

        CHECK(first_unseen_uid_lowwater, <);
	CHECK(first_deleted_uid_lowwater, <);
	CHECK(first_recent_uid, !=);
}

static void
mail_index_fsck_map(struct mail_index *index, struct mail_index_map *map)
{
	struct mail_index_header hdr;

	/* Remember the log head position. If we go back in the index's head
	   offset, ignore errors in the log up to this offset. */
	mail_transaction_log_get_head(index->log,
				      &index->fsck_log_head_file_seq,
				      &index->fsck_log_head_file_offset);

	hdr = map->hdr;

	mail_index_fsck_header(index, map, &hdr);
	mail_index_fsck_records(index, map, &hdr);

	map->hdr = hdr;
}

int mail_index_fsck(struct mail_index *index)
{
	bool orig_locked = index->log_locked;
	struct mail_index_map *map;
	uint32_t file_seq;
	uoff_t file_offset;

	i_warning("fscking index file %s", index->filepath);

	if (!orig_locked) {
		if (mail_transaction_log_sync_lock(index->log, &file_seq,
						   &file_offset) < 0)
			return -1;
	}

	map = mail_index_map_clone(index->map);
	mail_index_unmap(&index->map);
	index->map = map;

	mail_index_fsck_map(index, map);

	map->write_base_header = TRUE;
	map->write_atomic = TRUE;
	mail_index_write(index, FALSE);

	if (!orig_locked)
		mail_transaction_log_sync_unlock(index->log);
	return 0;
}

void mail_index_fsck_locked(struct mail_index *index)
{
	int ret;

	i_assert(index->log_locked);
	ret = mail_index_fsck(index);
	i_assert(ret == 0);
}
