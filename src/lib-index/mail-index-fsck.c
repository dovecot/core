/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
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
		    const char **error_r)
{
	struct mail_index_header hdr;
	const struct mail_index_record *rec;
	uint32_t i, last_uid;

	*error_r = NULL;

	/* locking already does the most important sanity checks for header */
	hdr = map->hdr;

	if (hdr.uid_validity == 0 && hdr.next_uid != 1) {
		*error_r = "uid_validity = 0 && next_uid != 1";
		return 0;
	}

	hdr.flags &= ~MAIL_INDEX_HDR_FLAG_FSCK;

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
	const char *error;
	unsigned int lock_id;
	int ret;

	i_warning("fscking index file %s", index->filepath);

	// FIXME: should we be fscking a given map instead? anyway we probably
	// want to rewrite the main index after fsck is finished.
	error = NULL;
	ret = mail_index_map(index, MAIL_INDEX_SYNC_HANDLER_HEAD, &lock_id);
	if (ret > 0) {
		ret = mail_index_fsck_map(index, index->map, &error);
		if (ret > 0) {
			if (mail_index_write_base_header(index,
							 &index->map->hdr) < 0)
				ret = -1;
		}
	}

	mail_index_unlock(index, lock_id);

	if (error != NULL) {
		mail_index_set_error(index, "Corrupted index file %s: %s",
				     index->filepath, error);
	}
	if (ret == 0)
		mail_index_mark_corrupted(index);
	return ret;
}
