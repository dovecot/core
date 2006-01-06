/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-transaction-log.h"

void mail_index_view_clone(struct mail_index_view *dest,
			   const struct mail_index_view *src)
{
	memset(dest, 0, sizeof(dest));
	dest->refcount = 1;
	dest->methods = src->methods;
	dest->index = src->index;
	dest->log_view = mail_transaction_log_view_open(src->index->log);

	dest->indexid = src->indexid;
	dest->map = src->map;
	dest->map->refcount++;
	dest->hdr = src->hdr;

	dest->log_file_seq = src->log_file_seq;
	dest->log_file_offset = src->log_file_offset;
}

void mail_index_view_ref(struct mail_index_view *view)
{
	view->refcount++;
}

static void _view_close(struct mail_index_view *view)
{
	i_assert(view->refcount == 0);

	mail_index_view_unlock(view);
	mail_transaction_log_view_close(view->log_view);

	if (array_is_created(&view->log_syncs))
		array_free(&view->log_syncs);
	mail_index_unmap(view->index, view->map);
	if (array_is_created(&view->map_refs)) {
		mail_index_view_unref_maps(view);
		array_free(&view->map_refs);
	}
	i_free(view);
}

int mail_index_view_lock_head(struct mail_index_view *view, int update_index)
{
	unsigned int lock_id;

	if (MAIL_INDEX_MAP_IS_IN_MEMORY(view->index->map))
		return 0;

	if (!mail_index_is_locked(view->index, view->lock_id)) {
		if (mail_index_lock_shared(view->index, update_index,
					   &view->lock_id) < 0)
			return -1;

		if (mail_index_map(view->index, FALSE) <= 0) {
			view->inconsistent = TRUE;
			return -1;
		}

		if (view->index->indexid != view->indexid) {
			/* index was rebuilt */
			view->inconsistent = TRUE;
			return -1;
		}
	} else if (update_index) {
		if (mail_index_lock_shared(view->index, TRUE, &lock_id) < 0)
			return -1;

		mail_index_unlock(view->index, view->lock_id);
		view->lock_id = lock_id;
	}

	i_assert(view->index->lock_type != F_UNLCK);

	return 0;
}

int mail_index_view_lock(struct mail_index_view *view)
{
	if (mail_index_view_is_inconsistent(view))
		return -1;

	return mail_index_view_lock_head(view, FALSE);
}

void mail_index_view_unlock(struct mail_index_view *view)
{
	if (view->lock_id != 0) {
		mail_index_unlock(view->index, view->lock_id);
		view->lock_id = 0;
	}
}

int mail_index_view_is_inconsistent(struct mail_index_view *view)
{
	if (view->index->indexid != view->indexid)
		view->inconsistent = TRUE;
	return view->inconsistent;
}

struct mail_index *mail_index_view_get_index(struct mail_index_view *view)
{
	return view->index;
}

void mail_index_view_transaction_ref(struct mail_index_view *view)
{
	view->transactions++;
}

void mail_index_view_transaction_unref(struct mail_index_view *view)
{
	i_assert(view->transactions > 0);

	view->transactions--;
}

static void mail_index_view_ref_map(struct mail_index_view *view,
				    struct mail_index_map *map)
{
	struct mail_index_map *const *maps;
	unsigned int i, count;

	if (array_is_created(&view->map_refs)) {
		maps = array_get(&view->map_refs, &count);

		/* if map is already referenced, do nothing */
		for (i = 0; i < count; i++) {
			if (maps[i] == map)
				return;
		}
	} else {
		ARRAY_CREATE(&view->map_refs, default_pool,
			     struct mail_index_map *, 4);
	}

	/* reference the given mapping. the reference is dropped when the view
	   is synchronized or closed. */
	map->refcount++;
	array_append(&view->map_refs, &map, 1);
}

void mail_index_view_unref_maps(struct mail_index_view *view)
{
	struct mail_index_map *const *maps;
	unsigned int i, count;

	if (!array_is_created(&view->map_refs))
		return;

	maps = array_get(&view->map_refs, &count);
	for (i = 0; i < count; i++)
		mail_index_unmap(view->index, maps[i]);

	array_clear(&view->map_refs);
}

static uint32_t _view_get_messages_count(struct mail_index_view *view)
{
	return view->hdr.messages_count;
}

static const struct mail_index_header *
_view_get_header(struct mail_index_view *view)
{
	return &view->hdr;
}

static int _view_lookup_full(struct mail_index_view *view, uint32_t seq,
			     struct mail_index_map **map_r,
			     const struct mail_index_record **rec_r)
{
	struct mail_index_map *map;
	const struct mail_index_record *rec, *head_rec;

	i_assert(seq > 0 && seq <= mail_index_view_get_messages_count(view));

	if (mail_index_view_lock(view) < 0)
		return -1;

	/* look up the record */
	rec = MAIL_INDEX_MAP_IDX(view->map, seq-1);
	if (view->map == view->index->map) {
		/* view's mapping is latest. we can use it directly. */
		*map_r = view->map;
		*rec_r = rec;
		return 1;
	}

	/* look up the record from head mapping. it may contain some changes. */
	if (mail_index_view_lock_head(view, FALSE) < 0)
		return -1;

	/* start looking up from the same sequence as in the old view.
	   if there are no expunges, it's there. otherwise it's somewhere
	   before (since records can't be inserted).

	   usually there are only a few expunges, so just going downwards from
	   our initial sequence position is probably faster than binary
	   search. */
	if (seq > view->index->hdr->messages_count)
		seq = view->index->hdr->messages_count;
	if (seq == 0) {
		/* everything is expunged from head. use the old record. */
		*map_r = view->map;
		*rec_r = rec;
		return 0;
	}

	map = view->index->map;
	do {
		seq--;
		head_rec = MAIL_INDEX_MAP_IDX(map, seq);
		if (head_rec->uid <= rec->uid)
			break;
	} while (seq > 0);

	if (head_rec->uid == rec->uid) {
		/* found it. use it. reference the index mapping so that the
		   returned record doesn't get invalidated after next sync. */
		mail_index_view_ref_map(view, view->index->map);
		*map_r = view->index->map;
		*rec_r = head_rec;
		return 1;
	} else {
		/* expuned from head. use the old record. */
		*map_r = view->map;
		*rec_r = rec;
		return 0;
	}
}

static int _view_lookup_uid(struct mail_index_view *view, uint32_t seq,
			    uint32_t *uid_r)
{
	i_assert(seq > 0 && seq <= mail_index_view_get_messages_count(view));

	if (mail_index_view_lock(view) < 0)
		return -1;

	*uid_r = MAIL_INDEX_MAP_IDX(view->map, seq-1)->uid;
	return 0;
}

static uint32_t mail_index_bsearch_uid(struct mail_index_view *view,
				       uint32_t uid, uint32_t *left_idx_p,
				       int nearest_side)
{
	const struct mail_index_record *rec_base, *rec;
	uint32_t idx, left_idx, right_idx, record_size;

	i_assert(view->hdr.messages_count <= view->map->records_count);

	rec_base = view->map->records;
	record_size = view->map->hdr.record_size;

	idx = left_idx = *left_idx_p;
	right_idx = view->hdr.messages_count;

	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

                rec = CONST_PTR_OFFSET(rec_base, idx * record_size);
		if (rec->uid < uid)
			left_idx = idx+1;
		else if (rec->uid > uid)
			right_idx = idx;
		else
			break;
	}

	if (idx == view->hdr.messages_count) {
		/* no messages available */
		return 0;
	}

        *left_idx_p = left_idx;
	rec = CONST_PTR_OFFSET(rec_base, idx * record_size);
	if (rec->uid != uid) {
		if (nearest_side > 0) {
			/* we want uid or larger */
			return rec->uid > uid ? idx+1 :
				idx == view->hdr.messages_count-1 ? 0 : idx+2;
		} else {
			/* we want uid or smaller */
			return rec->uid < uid ? idx + 1 : idx;
		}
	}

	return idx+1;
}

static int _view_lookup_uid_range(struct mail_index_view *view,
				  uint32_t first_uid, uint32_t last_uid,
				  uint32_t *first_seq_r, uint32_t *last_seq_r)
{
	uint32_t left_idx;

	i_assert(first_uid > 0);
	i_assert(first_uid <= last_uid);

	if (mail_index_view_lock(view) < 0)
		return -1;

	if (last_uid >= view->map->hdr.next_uid) {
		last_uid = view->map->hdr.next_uid-1;
		if (first_uid > last_uid) {
			*first_seq_r = 0;
			*last_seq_r = 0;
			return 0;
		}
	}

	left_idx = 0;
	*first_seq_r = mail_index_bsearch_uid(view, first_uid, &left_idx, 1);
	if (*first_seq_r == 0 ||
	    MAIL_INDEX_MAP_IDX(view->map, *first_seq_r-1)->uid > last_uid) {
		*first_seq_r = 0;
		*last_seq_r = 0;
		return 0;
	}
	if (first_uid == last_uid) {
		*last_seq_r = *first_seq_r;
		return 0;
	}

	/* optimization - binary lookup only from right side: */
	*last_seq_r = mail_index_bsearch_uid(view, last_uid, &left_idx, -1);
	i_assert(*last_seq_r >= *first_seq_r);
	return 0;
}

static int _view_lookup_first(struct mail_index_view *view,
			      enum mail_flags flags, uint8_t flags_mask,
			      uint32_t *seq_r)
{
#define LOW_UPDATE(x) \
	STMT_START { if ((x) > low_uid) low_uid = x; } STMT_END
	const struct mail_index_record *rec;
	uint32_t seq, low_uid = 1;

	*seq_r = 0;

	if (mail_index_view_lock(view) < 0)
		return -1;

	if ((flags_mask & MAIL_RECENT) != 0 && (flags & MAIL_RECENT) != 0)
		LOW_UPDATE(view->map->hdr.first_recent_uid_lowwater);
	if ((flags_mask & MAIL_SEEN) != 0 && (flags & MAIL_SEEN) == 0)
		LOW_UPDATE(view->map->hdr.first_unseen_uid_lowwater);
	if ((flags_mask & MAIL_DELETED) != 0 && (flags & MAIL_DELETED) != 0)
		LOW_UPDATE(view->map->hdr.first_deleted_uid_lowwater);

	if (low_uid == 1)
		seq = 1;
	else {
		if (mail_index_lookup_uid_range(view, low_uid, low_uid,
						&seq, &seq) < 0)
			return -1;

		if (seq == 0)
			return 0;
	}

	i_assert(view->hdr.messages_count <= view->map->records_count);

	for (; seq <= view->hdr.messages_count; seq++) {
		rec = MAIL_INDEX_MAP_IDX(view->map, seq-1);
		if ((rec->flags & flags_mask) == (uint8_t)flags) {
			*seq_r = seq;
			break;
		}
	}

	return 0;
}

static int _view_lookup_ext_full(struct mail_index_view *view, uint32_t seq,
				 uint32_t ext_id, struct mail_index_map **map_r,
				 const void **data_r)
{
	const struct mail_index_ext *ext;
	const struct mail_index_record *rec;
	uint32_t idx, offset;
	int ret;

	if ((ret = mail_index_lookup_full(view, seq, map_r, &rec)) < 0)
		return -1;

	if (rec == NULL || !mail_index_map_get_ext_idx(*map_r, ext_id, &idx)) {
		*data_r = NULL;
		return ret;
	}

	ext = array_idx(&(*map_r)->extensions, idx);
	offset = ext->record_offset;

	*data_r = offset == 0 ? NULL : CONST_PTR_OFFSET(rec, offset);
	return ret;
}

static int _view_get_header_ext(struct mail_index_view *view,
				struct mail_index_map *map, uint32_t ext_id,
				const void **data_r, size_t *data_size_r)
{
	const struct mail_index_ext *ext;
	uint32_t idx;

	if (map != NULL) {
		if (mail_index_view_lock(view) < 0)
			return -1;
	} else {
		if (mail_index_view_lock_head(view, FALSE) < 0)
			return -1;

		map = view->index->map;
	}

	if (!mail_index_map_get_ext_idx(map, ext_id, &idx)) {
		*data_r = NULL;
		*data_size_r = 0;
		return 0;
	}

	ext = array_idx(&map->extensions, idx);
	*data_r = CONST_PTR_OFFSET(map->hdr_base, ext->hdr_offset);
	*data_size_r = ext->hdr_size;
	return 0;
}

void mail_index_view_close(struct mail_index_view *view)
{
	if (--view->refcount > 0)
		return;

	view->methods.close(view);
}

uint32_t mail_index_view_get_messages_count(struct mail_index_view *view)
{
	return view->methods.get_messages_count(view);
}

const struct mail_index_header *
mail_index_get_header(struct mail_index_view *view)
{
	return view->methods.get_header(view);
}

int mail_index_lookup(struct mail_index_view *view, uint32_t seq,
		      const struct mail_index_record **rec_r)
{
	struct mail_index_map *map;

	return mail_index_lookup_full(view, seq, &map, rec_r);
}

int mail_index_lookup_full(struct mail_index_view *view, uint32_t seq,
			   struct mail_index_map **map_r,
			   const struct mail_index_record **rec_r)
{
	return view->methods.lookup_full(view, seq, map_r, rec_r);
}

int mail_index_lookup_keywords(struct mail_index_view *view, uint32_t seq,
			       array_t *keyword_idx)
{
	ARRAY_SET_TYPE(keyword_idx, unsigned int);
	struct mail_index_map *map;
	const struct mail_index_ext *ext;
	const void *data;
	const unsigned int *keyword_idx_map;
	unsigned int i, j, keyword_count, index_idx;
	uint32_t ext_id, idx;
	int ret;

	array_clear(keyword_idx);

	ext_id = view->index->keywords_ext_id;
	ret = mail_index_lookup_ext_full(view, seq, ext_id, &map, &data);
	if (ret < 0)
		return -1;

	if (!mail_index_map_get_ext_idx(map, ext_id, &idx))
		return ret;

	ext = array_idx(&map->extensions, idx);
	if (!array_is_created(&map->keyword_idx_map)) {
		keyword_idx_map = NULL;
		keyword_count = 0;
	} else {
		keyword_idx_map = array_get(&map->keyword_idx_map,
					    &keyword_count);
	}

	for (i = 0, idx = 0; i < ext->record_size; i++) {
		if (((const unsigned char *)data)[i] == 0)
			continue;

		idx = i * CHAR_BIT;
		for (j = 0; j < CHAR_BIT; j++, idx++) {
			if ((((const unsigned char *)data)[i] & (1 << j)) == 0)
				continue;

			if (idx >= keyword_count) {
				/* keyword header is updated, re-read
				   it so we know what this one is
				   called */
				if (mail_index_map_read_keywords(view->index,
								 map) < 0)
					return -1;

				if (!array_is_created(&map->keyword_idx_map))
					return ret;

				keyword_idx_map =
					array_get(&map->keyword_idx_map,
						  &keyword_count);

				if (idx >= keyword_count) {
					/* extra bits set in keyword bytes.
					   shouldn't happen, but just ignore. */
					break;
				}
			}

			index_idx = keyword_idx_map[idx];
			array_append(keyword_idx, &index_idx, 1);
		}
	}
	return ret;
}

int mail_index_lookup_uid(struct mail_index_view *view, uint32_t seq,
			  uint32_t *uid_r)
{
	return view->methods.lookup_uid(view, seq, uid_r);
}

int mail_index_lookup_uid_range(struct mail_index_view *view,
				uint32_t first_uid, uint32_t last_uid,
				uint32_t *first_seq_r, uint32_t *last_seq_r)
{
	return view->methods.lookup_uid_range(view, first_uid, last_uid,
					      first_seq_r, last_seq_r);
}

int mail_index_lookup_first(struct mail_index_view *view, enum mail_flags flags,
			    uint8_t flags_mask, uint32_t *seq_r)
{
	return view->methods.lookup_first(view, flags, flags_mask, seq_r);
}

int mail_index_lookup_ext(struct mail_index_view *view, uint32_t seq,
			  uint32_t ext_id, const void **data_r)
{
	struct mail_index_map *map;

	return view->methods.lookup_ext_full(view, seq, ext_id, &map, data_r);
}

int mail_index_lookup_ext_full(struct mail_index_view *view, uint32_t seq,
			       uint32_t ext_id, struct mail_index_map **map_r,
			       const void **data_r)
{
	return view->methods.lookup_ext_full(view, seq, ext_id, map_r, data_r);
}

int mail_index_get_header_ext(struct mail_index_view *view, uint32_t ext_id,
			      const void **data_r, size_t *data_size_r)
{
	return view->methods.get_header_ext(view, NULL, ext_id,
					    data_r, data_size_r);
}

int mail_index_map_get_header_ext(struct mail_index_view *view,
				  struct mail_index_map *map, uint32_t ext_id,
				  const void **data_r, size_t *data_size_r)
{
	return view->methods.get_header_ext(view, map, ext_id,
					    data_r, data_size_r);
}

static struct mail_index_view_methods view_methods = {
	_view_close,
	_view_get_messages_count,
	_view_get_header,
	_view_lookup_full,
	_view_lookup_uid,
	_view_lookup_uid_range,
	_view_lookup_first,
	_view_lookup_ext_full,
	_view_get_header_ext
};

struct mail_index_view *mail_index_view_open(struct mail_index *index)
{
	struct mail_index_view *view;

	i_assert(index->map != NULL);

	view = i_new(struct mail_index_view, 1);
	view->refcount = 1;
	view->methods = view_methods;
	view->index = index;
	view->log_view = mail_transaction_log_view_open(index->log);

	view->indexid = index->indexid;
	view->map = index->map;
	view->map->refcount++;

	view->hdr = view->map->hdr;

	view->log_file_seq = view->map->hdr.log_file_seq;
	view->log_file_offset =
		I_MIN(view->map->hdr.log_file_int_offset,
		      view->map->hdr.log_file_ext_offset);
	return view;
}

const struct mail_index_ext *
mail_index_view_get_ext(struct mail_index_view *view, uint32_t ext_id)
{
	uint32_t idx;

	if (!mail_index_map_get_ext_idx(view->map, ext_id, &idx))
		return 0;

	return array_idx(&view->map->extensions, idx);
}
