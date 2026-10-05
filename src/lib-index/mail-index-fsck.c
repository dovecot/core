/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "mail-index-private.h"
#include "mail-transaction-log-private.h"

static void mail_index_fsck_error(struct mail_index *index,
				  const char *fmt, ...) ATTR_FORMAT(2, 3);
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
mail_index_fsck_log_pos(struct mail_index *index, struct mail_index_map *map,
			struct mail_index_header *hdr)
{
	unsigned int hdr_size = index->log->head->hdr.hdr_size;
	uint32_t file_seq;
	uoff_t file_offset;

	mail_transaction_log_get_head(index->log, &file_seq, &file_offset);
	if (hdr->log_file_seq < file_seq) {
		/* index's log_file_seq is too old. move it to log head. */
		hdr->log_file_head_offset = hdr->log_file_tail_offset =
			sizeof(struct mail_transaction_log_header);
	} else if (hdr->log_file_seq == file_seq) {
		/* index's log_file_seq matches the current log. make sure the
		   offsets are valid. */
		if (hdr->log_file_head_offset > file_offset)
			hdr->log_file_head_offset = file_offset;
		else if (hdr->log_file_head_offset < hdr_size)
			hdr->log_file_head_offset = hdr_size;

		if (hdr->log_file_tail_offset > hdr->log_file_head_offset)
			hdr->log_file_tail_offset = hdr->log_file_head_offset;
		else if (hdr->log_file_tail_offset != 0 &&
			 hdr->log_file_tail_offset < hdr_size)
			hdr->log_file_tail_offset = hdr_size;
	} else {
		/* index's log_file_seq is newer than exists. move it to
		   end of the current log head. */
		hdr->log_file_head_offset = hdr->log_file_tail_offset =
			file_offset;
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
mail_index_fsck_header(struct mail_index *index, struct mail_index_map *map,
		       struct mail_index_header *hdr)
{
	/* mail_index_map_check_header() has already checked that the index
	   isn't completely broken. */
	if (hdr->uid_validity == 0 && hdr->next_uid != 1)
		hdr->uid_validity = ioloop_time32;

	if (index->log->head != NULL)
		mail_index_fsck_log_pos(index, map, hdr);
}

static bool
array_has_name(const ARRAY_TYPE(const_string) *names, const char *name)
{
	const char *arr_name;

	array_foreach_elem(names, arr_name) {
		if (strcmp(arr_name, name) == 0)
			return TRUE;
	}
	return FALSE;
}

static unsigned int
mail_index_fsck_find_keyword_count(struct mail_index_map *map,
				   const struct mail_index_ext_header *ext_hdr)
{
	const struct mail_index_record *rec;
	const uint8_t *kw;
	unsigned int r, i, j, cur, max = 0, kw_pos, kw_size;

	kw_pos = ext_hdr->record_offset;
	kw_size = ext_hdr->record_size;

	rec = map->rec_map->records;
	for (r = 0; r < map->rec_map->records_count; r++) {
		kw = CONST_PTR_OFFSET(rec, kw_pos);
		for (i = cur = 0; i < kw_size; i++) {
			if (kw[i] != 0) {
				for (j = 0; j < 8; j++) {
					if ((kw[i] & (1 << j)) != 0)
						cur = i * 8 + j + 1;
				}
			}
		}
		if (cur > max) {
			max = cur;
			if (max == kw_size*8)
				return max;
		}
		rec = CONST_PTR_OFFSET(rec, map->hdr.record_size);
	}
	return max;
}

static bool
keyword_name_is_valid(const char *buffer, unsigned int pos, unsigned int size)
{
	for (; pos < size; pos++) {
		if (buffer[pos] == '\0')
			return TRUE;
		if (((unsigned char)buffer[pos] & 0x7f) < 32) {
			/* control characters aren't valid */
			return FALSE;
		}
	}
	return FALSE;
}

static void
mail_index_fsck_keywords(struct mail_index *index, struct mail_index_map *map,
			 struct mail_index_header *hdr,
			 const struct mail_index_ext_header *ext_hdr,
			 unsigned int ext_offset, unsigned int *offset_p)
{
	const struct mail_index_keyword_header *kw_hdr;
	struct mail_index_keyword_header *new_kw_hdr;
	const struct mail_index_keyword_header_rec *kw_rec;
	struct mail_index_keyword_header_rec new_kw_rec;
	const char *name, *name_buffer, **name_array;
	unsigned int i, j, name_pos, name_size, rec_pos, hdr_offset, diff;
	unsigned int changed_count, keywords_count, name_base_pos, count;
	ARRAY_TYPE(const_string) names;
	buffer_t *dest;
	bool changed = FALSE, hdr_broken;

	hdr_offset = ext_offset +
		mail_index_map_ext_hdr_offset(sizeof(MAIL_INDEX_EXT_KEYWORDS)-1);
	kw_hdr = MAIL_INDEX_MAP_HDR_OFFSET(map, hdr_offset);
	kw_rec = (const void *)(kw_hdr + 1);
	if (ext_hdr->hdr_size < sizeof(*kw_hdr)) {
		/* too small to contain keywords_count */
		hdr_broken = TRUE;
	} else {
		/* Check keywords_count before calculating name_pos, which
		   could otherwise wrap. */
		unsigned int max_keywords_count =
			(ext_hdr->hdr_size - sizeof(*kw_hdr)) / sizeof(*kw_rec);
		hdr_broken = kw_hdr->keywords_count > max_keywords_count;
	}
	if (hdr_broken) {
		/* the header is completely broken */
		keywords_count =
			mail_index_fsck_find_keyword_count(map, ext_hdr);
		mail_index_fsck_error(index, "Assuming keywords_count = %u",
				      keywords_count);
		kw_rec = NULL;
		name_buffer = NULL;
		name_size = 0;
		changed = TRUE;
	} else {
		keywords_count = kw_hdr->keywords_count;
		name_pos = sizeof(*kw_hdr) + keywords_count * sizeof(*kw_rec);
		i_assert(name_pos <= ext_hdr->hdr_size);
		name_buffer = (const char *)kw_hdr + name_pos;
		name_size = ext_hdr->hdr_size - name_pos;
	}

	/* create keyword name array. invalid keywords are added as
	   empty strings */
	t_array_init(&names, keywords_count);
	for (i = 0; i < keywords_count; i++) {
		if (name_size == 0 ||
		    !keyword_name_is_valid(name_buffer, kw_rec[i].name_offset,
					   name_size))
			name = "";
		else
			name = name_buffer + kw_rec[i].name_offset;

		if (*name != '\0' && array_has_name(&names, name)) {
			/* duplicate */
			name = "";
		}
		array_push_back(&names, &name);
	}

	/* give new names to invalid keywords */
	changed_count = 0;
	/* keywords_count may be 0, so don't use array_front_modifiable() */
	name_array = array_get_modifiable(&names, &count);
	i_assert(count == keywords_count);
	for (i = j = 0; i < keywords_count; i++) {
		while (name_array[i][0] == '\0') {
			name = t_strdup_printf("unknown-%d", j++);
			if (!array_has_name(&names, name)) {
				name_array[i] = name;
				changed = TRUE;
				changed_count++;
			}
		}
	}

	if (!changed) {
		/* nothing was broken */
		return;
	}

	mail_index_fsck_error(index, "Renamed %u keywords to unknown-*",
			      changed_count);

	dest = buffer_create_dynamic(default_pool,
				     I_MAX(ext_hdr->hdr_size, 128));
	new_kw_hdr = buffer_append_space_unsafe(dest, sizeof(*new_kw_hdr));
	new_kw_hdr->keywords_count = keywords_count;

	/* add keyword records so we can start appending names directly */
	rec_pos = dest->used;
	i_zero(&new_kw_rec);
	(void)buffer_append_space_unsafe(dest, keywords_count * sizeof(*kw_rec));

	/* write the actual records and names */
	name_base_pos = dest->used;
	for (i = 0; i < keywords_count; i++) {
		new_kw_rec.name_offset = dest->used - name_base_pos;
		buffer_write(dest, rec_pos, &new_kw_rec, sizeof(new_kw_rec));
		rec_pos += sizeof(*kw_rec);

		buffer_append(dest, name_array[i], strlen(name_array[i]) + 1);
	}

	/* keep the header size at least the same size as before */
	if (dest->used < ext_hdr->hdr_size)
		buffer_append_zero(dest, ext_hdr->hdr_size - dest->used);

	if (dest->used > ext_hdr->hdr_size) {
		/* need to resize the header */
		/* ext_hdr points to hdr_copy_buf, which may be reallocated
		   by buffer_copy(). Copy it first. */
		struct mail_index_ext_header new_ext_hdr = *ext_hdr;

		/* the header contents are padded to 64bit alignment, so
		   the following extensions must move by an aligned amount */
		diff = MAIL_INDEX_HEADER_SIZE_ALIGN(dest->used) -
			MAIL_INDEX_HEADER_SIZE_ALIGN(ext_hdr->hdr_size);
		buffer_copy(map->hdr_copy_buf, hdr_offset + diff,
			    map->hdr_copy_buf, hdr_offset, SIZE_MAX);
		hdr->header_size += diff;
		*offset_p += diff;

		new_ext_hdr.hdr_size = dest->used;
		buffer_write(map->hdr_copy_buf, ext_offset,
			     &new_ext_hdr, sizeof(new_ext_hdr));
	}

	i_assert(hdr_offset + dest->used <= map->hdr_copy_buf->used);
	buffer_write(map->hdr_copy_buf, hdr_offset, dest->data, dest->used);

	/* keywords changed unexpectedly, so all views are broken now */
	index->inconsistency_id++;

	buffer_free(&dest);
}

static void
mail_index_fsck_extensions(struct mail_index *index, struct mail_index_map *map,
			   struct mail_index_header *hdr)
{
	const struct mail_index_ext_header *ext_hdr;
	ARRAY_TYPE(const_string) names;
	const char *name, *error;
	unsigned int offset, next_offset, i;

	t_array_init(&names, 64);
	offset = MAIL_INDEX_HEADER_SIZE_ALIGN(hdr->base_header_size);
	for (i = 0; offset < hdr->header_size; i++) {
		/* mail_index_map_ext_get_next() uses map->hdr, so make sure
		   it's up-to-date */
		map->hdr = *hdr;

		next_offset = offset;
		if (mail_index_map_ext_get_next(map, &next_offset,
						&ext_hdr, &name) < 0) {
			/* the extension continued outside header, drop it */
			mail_index_fsck_error(index,
					      "Dropped extension #%d (%s) "
					      "with invalid header size",
					      i, name);
			hdr->header_size = offset;
			buffer_set_used_size(map->hdr_copy_buf, hdr->header_size);
			break;
		}
		if (mail_index_map_ext_hdr_check(hdr, ext_hdr, name,
						 &error) < 0) {
			mail_index_fsck_error(index,
				"Dropped broken extension #%d (%s)", i, name);
		} else if (array_has_name(&names, name)) {
			mail_index_fsck_error(index,
				"Dropped duplicate extension %s", name);
		} else {
			/* name may change if header buffer is changed */
			name = t_strdup(name);

			if (strcmp(name, MAIL_INDEX_EXT_KEYWORDS) == 0) {
				mail_index_fsck_keywords(index, map, hdr,
							 ext_hdr, offset,
							 &next_offset);
			}
			array_push_back(&names, &name);
			offset = next_offset;
			continue;
		}

		/* drop the field */
		hdr->header_size -= next_offset - offset;
		buffer_copy(map->hdr_copy_buf, offset,
			    map->hdr_copy_buf, next_offset, SIZE_MAX);
		buffer_set_used_size(map->hdr_copy_buf, hdr->header_size);
	}
}

static void
mail_index_fsck_records(struct mail_index *index, struct mail_index_map *map,
			struct mail_index_header *hdr)
{
	struct mail_index_record *rec, *next_rec;
	uint32_t i, last_uid;
	bool logged_unordered_uids = FALSE, logged_zero_uids = FALSE;
	bool logged_max_uids = FALSE;
	bool records_dropped = FALSE;

	hdr->messages_count = 0;
	hdr->seen_messages_count = 0;
	hdr->deleted_messages_count = 0;

	hdr->first_unseen_uid_lowwater = 0;
	hdr->first_deleted_uid_lowwater = 0;

	rec = map->rec_map->records; last_uid = 0;
	for (i = 0; i < map->rec_map->records_count; ) {
		next_rec = PTR_OFFSET(rec, hdr->record_size);
		/* UID UINT32_MAX can't be valid, since next_uid must be
		   larger than it. */
		if (rec->uid <= last_uid || rec->uid == UINT32_MAX) {
			/* log an error once, and skip this record */
			if (rec->uid == 0) {
				if (!logged_zero_uids) {
					mail_index_fsck_error(index,
						"Record UIDs have zeroes");
					logged_zero_uids = TRUE;
				}
			} else if (rec->uid == UINT32_MAX) {
				if (!logged_max_uids) {
					mail_index_fsck_error(index,
						"Record UIDs have %u",
						UINT32_MAX);
					logged_max_uids = TRUE;
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

	if (index->log->head != NULL) {
		/* Remember the log head position. If we go back in the index's
		   head offset, ignore errors in the log up to this offset. */
		mail_transaction_log_get_head(index->log,
			&index->fsck_log_head_file_seq,
			&index->fsck_log_head_file_offset);
	}
	hdr = map->hdr;

	mail_index_fsck_header(index, map, &hdr);
	mail_index_fsck_extensions(index, map, &hdr);
	mail_index_fsck_records(index, map, &hdr);

	hdr.flags |= MAIL_INDEX_HDR_FLAG_FSCKD;
	map->hdr = hdr;
	i_assert(map->hdr_copy_buf->used == map->hdr.header_size);
}

int mail_index_fsck(struct mail_index *index)
{
	bool orig_locked = index->log_sync_locked;
	struct mail_index_map *map;
	uint32_t file_seq;
	uoff_t file_offset;

	e_warning(index->event, "fscking index file %s", index->filepath);

	index->fscked = TRUE;

	if (index->log->head == NULL) {
		/* we're trying to open the index files, but there wasn't
		   any .log file. */
		if (mail_transaction_log_create(index->log, FALSE) < 0)
			return -1;
	}

	if (!orig_locked) {
		if (mail_transaction_log_sync_lock(index->log, "fscking",
						   &file_seq, &file_offset) < 0)
			return -1;
	}

	map = mail_index_map_clone(index->map);
	mail_index_unmap(&index->map);
	index->map = map;
	/* fsck modifies the records directly. Make sure they're not shared
	   with other maps, which would then see records_count changing
	   without their messages_count changing. This also drops any records
	   after messages_count, which belong only to newer maps. A corrupted
	   messages_count may be larger than records_count, so temporarily
	   limit it. fsck recalculates (and logs) messages_count anyway. */
	uint32_t messages_count = map->hdr.messages_count;
	if (map->hdr.messages_count > map->rec_map->records_count)
		map->hdr.messages_count = map->rec_map->records_count;
	mail_index_map_move_to_memory(map);
	mail_index_record_map_move_to_private(map);
	map->hdr.messages_count = messages_count;

	T_BEGIN {
		mail_index_fsck_map(index, map);
		/* fsck may have dropped or modified extension headers, so
		   the map's parsed extensions and keywords must be updated
		   to match them. */
		if (array_is_created(&map->keyword_idx_map))
			array_clear(&map->keyword_idx_map);
		if (mail_index_map_parse_extensions(map) < 0 ||
		    mail_index_map_parse_keywords(map) < 0) {
			mail_index_set_error(index,
				"fsck left broken extension headers to index file %s",
				index->filepath);
		}
	} T_END;

	mail_index_write(index, FALSE, "fscking");

	if (!orig_locked)
		mail_transaction_log_sync_unlock(index->log, "fscking");
	return 0;
}

static bool
mail_index_map_verify_records(struct mail_index_map *map,
			      const char **error_r)
{
	const struct mail_index_record *rec;
	uint32_t seq, prev_uid = 0;

	for (seq = 1; seq <= map->hdr.messages_count; seq++) {
		rec = MAIL_INDEX_REC_AT_SEQ(map, seq);
		if (rec->uid <= prev_uid) {
			*error_r = t_strdup_printf(
				"Record seq=%u UID %u <= previous UID %u",
				seq, rec->uid, prev_uid);
			return FALSE;
		}
		if (rec->uid >= map->hdr.next_uid) {
			*error_r = t_strdup_printf(
				"Record seq=%u UID %u >= next_uid %u",
				seq, rec->uid, map->hdr.next_uid);
			return FALSE;
		}
		prev_uid = rec->uid;
	}
	return TRUE;
}

int mail_index_verify_records(struct mail_index *index)
{
	const char *error;
	bool valid;

	i_assert(index->open_count > 0);

	T_BEGIN {
		valid = mail_index_map_verify_records(index->map, &error);
		if (!valid) {
			mail_index_set_error(index,
				"Corrupted index file %s: %s",
				index->filepath, error);
		}
	} T_END;
	if (valid)
		return 1;
	return mail_index_fsck(index) < 0 ? -1 : 0;
}

bool mail_index_view_verify_records(struct mail_index_view *view)
{
	struct mail_index *index = view->index;
	const char *error;
	bool valid, fsck = FALSE;

	T_BEGIN {
		valid = mail_index_map_verify_records(view->map, &error);
		if (!valid) {
			mail_index_set_error(index,
				"Corrupted index file %s: %s",
				index->filepath, error);
			/* The index's map may have already been fixed, but
			   the view hasn't been synced yet. */
			fsck = view->map == index->map ||
				!mail_index_map_verify_records(index->map,
							       &error);
		}
	} T_END;
	if (fsck)
		(void)mail_index_fsck(index);
	return valid;
}

void mail_index_fsck_locked(struct mail_index *index)
{
	int ret;

	i_assert(index->log_sync_locked);
	ret = mail_index_fsck(index);
	i_assert(ret == 0);
}

bool mail_index_reset_fscked(struct mail_index *index)
{
	bool ret = index->fscked;

	index->fscked = FALSE;
	return ret;
}
