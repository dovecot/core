/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

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
		else if (hdr->log_file_head_offset < MAIL_TRANSACTION_LOG_HEADER_MIN_SIZE)
			hdr->log_file_head_offset = MAIL_TRANSACTION_LOG_HEADER_MIN_SIZE;

		if (hdr->log_file_tail_offset > hdr->log_file_head_offset)
			hdr->log_file_tail_offset = hdr->log_file_head_offset;
		else if (hdr->log_file_tail_offset != 0 &&
			 hdr->log_file_tail_offset < MAIL_TRANSACTION_LOG_HEADER_MIN_SIZE)
			hdr->log_file_tail_offset = MAIL_TRANSACTION_LOG_HEADER_MIN_SIZE;
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
		hdr->uid_validity = ioloop_time;

	if (index->log->head != NULL)
		mail_index_fsck_log_pos(index, map, hdr);
}

static bool
array_has_name(const ARRAY_TYPE(const_string) *names, const char *name)
{
	const char *const *namep;

	array_foreach(names, namep) {
		if (strcmp(*namep, name) == 0)
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
	unsigned int changed_count, keywords_count, name_base_pos;
	ARRAY_TYPE(const_string) names;
	buffer_t *dest;
	bool changed = FALSE;

	hdr_offset = ext_offset +
		mail_index_map_ext_hdr_offset(sizeof(MAIL_INDEX_EXT_KEYWORDS)-1);
	kw_hdr = CONST_PTR_OFFSET(map->hdr_base, hdr_offset);
	keywords_count = kw_hdr->keywords_count;

	kw_rec = (const void *)(kw_hdr + 1);
	name_buffer = (const char *)(kw_rec + keywords_count);

	name_pos = (size_t)(name_buffer - (const char *)kw_hdr);
	if (name_pos > ext_hdr->hdr_size) {
		/* the header is completely broken */
		keywords_count =
			mail_index_fsck_find_keyword_count(map, ext_hdr);
		mail_index_fsck_error(index, "Assuming keywords_count = %u",
				      keywords_count);
		kw_rec = NULL;
		name_size = 0;
		changed = TRUE;
	} else {
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
		array_append(&names, &name, 1);
	}

	/* give new names to invalid keywords */
	changed_count = 0;
	name_array = array_idx_modifiable(&names, 0);
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
		struct mail_index_ext_header new_ext_hdr;

		diff = dest->used - ext_hdr->hdr_size;
		buffer_copy(map->hdr_copy_buf, hdr_offset + diff,
			    map->hdr_copy_buf, hdr_offset, (size_t)-1);
		map->hdr_base = map->hdr_copy_buf->data;
		hdr->header_size += diff;
		*offset_p += diff;

		new_ext_hdr = *ext_hdr;
		new_ext_hdr.hdr_size += diff;
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
			array_append(&names, &name, 1);
			offset = next_offset;
			continue;
		}

		/* drop the field */
		hdr->header_size -= next_offset - offset;
		buffer_copy(map->hdr_copy_buf, offset,
			    map->hdr_copy_buf, next_offset, (size_t)-1);
		buffer_set_used_size(map->hdr_copy_buf, hdr->header_size);
		map->hdr_base = map->hdr_copy_buf->data;
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

	i_warning("fscking index file %s", index->filepath);

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

	T_BEGIN {
		mail_index_fsck_map(index, map);
	} T_END;

	mail_index_write(index, FALSE);

	if (!orig_locked)
		mail_transaction_log_sync_unlock(index->log, "fscking");
	return 0;
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
