/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

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
	dest->v = src->v;
	dest->index = src->index;
	if (src->log_view != NULL) {
		dest->log_view =
			mail_transaction_log_view_open(src->index->log);
	}

	dest->indexid = src->indexid;
	dest->inconsistency_id = src->inconsistency_id;
	dest->map = src->map;
	if (dest->map != NULL)
		dest->map->refcount++;

	dest->log_file_expunge_seq = src->log_file_expunge_seq;
	dest->log_file_expunge_offset = src->log_file_expunge_offset;
	dest->log_file_head_seq = src->log_file_head_seq;
	dest->log_file_head_offset = src->log_file_head_offset;

	i_array_init(&dest->module_contexts,
		     I_MIN(5, mail_index_module_register.id));
}

void mail_index_view_ref(struct mail_index_view *view)
{
	view->refcount++;
}

static void view_close(struct mail_index_view *view)
{
	i_assert(view->refcount == 0);

	mail_transaction_log_view_close(&view->log_view);

	if (array_is_created(&view->syncs_hidden))
		array_free(&view->syncs_hidden);
	mail_index_unmap(&view->map);
	if (array_is_created(&view->map_refs)) {
		mail_index_view_unref_maps(view);
		array_free(&view->map_refs);
	}
	array_free(&view->module_contexts);
	i_free(view);
}

bool mail_index_view_is_inconsistent(struct mail_index_view *view)
{
	if (view->index->indexid != view->indexid ||
	    view->index->inconsistency_id != view->inconsistency_id)
		view->inconsistent = TRUE;
	return view->inconsistent;
}

struct mail_index *mail_index_view_get_index(struct mail_index_view *view)
{
	return view->index;
}

unsigned int
mail_index_view_get_transaction_count(struct mail_index_view *view)
{
	i_assert(view->transactions >= 0);

	return view->transactions;
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
		i_array_init(&view->map_refs, 4);
	}

	/* reference the given mapping. the reference is dropped when the view
	   is synchronized or closed. */
	map->refcount++;
	array_append(&view->map_refs, &map, 1);
}

void mail_index_view_unref_maps(struct mail_index_view *view)
{
	struct mail_index_map **maps;
	unsigned int i, count;

	if (!array_is_created(&view->map_refs))
		return;

	maps = array_get_modifiable(&view->map_refs, &count);
	for (i = 0; i < count; i++)
		mail_index_unmap(&maps[i]);

	array_clear(&view->map_refs);
}

static uint32_t view_get_messages_count(struct mail_index_view *view)
{
	return view->map->hdr.messages_count;
}

static const struct mail_index_header *
view_get_header(struct mail_index_view *view)
{
	return &view->map->hdr;
}

static const struct mail_index_record *
view_lookup_full(struct mail_index_view *view, uint32_t seq,
		 struct mail_index_map **map_r, bool *expunged_r)
{
	static struct mail_index_record broken_rec;
	struct mail_index_map *map;
	const struct mail_index_record *rec, *head_rec;

	i_assert(seq > 0 && seq <= mail_index_view_get_messages_count(view));

	/* look up the record */
	rec = MAIL_INDEX_MAP_IDX(view->map, seq-1);
	if (unlikely(rec->uid == 0)) {
		if (!view->inconsistent) {
			mail_index_set_error(view->index,
				"Corrupted Index file %s: Record [%u].uid=0",
				view->index->filepath, seq);
			(void)mail_index_fsck(view->index);
			view->inconsistent = TRUE;
		}

		/* we'll need to return something so the caller doesn't crash */
		*map_r = view->map;
		*expunged_r = TRUE;
		return &broken_rec;
	}
	if (view->map == view->index->map) {
		/* view's mapping is latest. we can use it directly. */
		*map_r = view->map;
		*expunged_r = FALSE;
		return rec;
	}

	/* look up the record from head mapping. it may contain some changes.

	   start looking up from the same sequence as in the old view.
	   if there are no expunges, it's there. otherwise it's somewhere
	   before (since records can't be inserted).

	   usually there are only a few expunges, so just going downwards from
	   our initial sequence position is probably faster than binary
	   search. */
	if (seq > view->index->map->hdr.messages_count)
		seq = view->index->map->hdr.messages_count;
	if (seq == 0) {
		/* everything is expunged from head. use the old record. */
		*map_r = view->map;
		*expunged_r = TRUE;
		return rec;
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
		*expunged_r = FALSE;
		return head_rec;
	} else {
		/* expuned from head. use the old record. */
		*map_r = view->map;
		*expunged_r = TRUE;
		return rec;
	}
}

static void view_lookup_uid(struct mail_index_view *view, uint32_t seq,
			    uint32_t *uid_r)
{
	i_assert(seq > 0 && seq <= mail_index_view_get_messages_count(view));

	*uid_r = MAIL_INDEX_MAP_IDX(view->map, seq-1)->uid;
}

static void view_lookup_seq_range(struct mail_index_view *view,
				  uint32_t first_uid, uint32_t last_uid,
				  uint32_t *first_seq_r, uint32_t *last_seq_r)
{
	mail_index_map_lookup_seq_range(view->map, first_uid, last_uid,
					first_seq_r, last_seq_r);
}

static void view_lookup_first(struct mail_index_view *view,
			      enum mail_flags flags, uint8_t flags_mask,
			      uint32_t *seq_r)
{
#define LOW_UPDATE(x) \
	STMT_START { if ((x) > low_uid) low_uid = x; } STMT_END
	const struct mail_index_header *hdr = &view->map->hdr;
	const struct mail_index_record *rec;
	uint32_t seq, seq2, low_uid = 1;

	*seq_r = 0;

	if ((flags_mask & MAIL_SEEN) != 0 && (flags & MAIL_SEEN) == 0)
		LOW_UPDATE(hdr->first_unseen_uid_lowwater);
	if ((flags_mask & MAIL_DELETED) != 0 && (flags & MAIL_DELETED) != 0)
		LOW_UPDATE(hdr->first_deleted_uid_lowwater);

	if (low_uid == 1)
		seq = 1;
	else {
		if (!mail_index_lookup_seq_range(view, low_uid, hdr->next_uid,
						 &seq, &seq2))
			return;
	}

	i_assert(hdr->messages_count <= view->map->rec_map->records_count);
	for (; seq <= hdr->messages_count; seq++) {
		rec = MAIL_INDEX_MAP_IDX(view->map, seq-1);
		if ((rec->flags & flags_mask) == (uint8_t)flags) {
			*seq_r = seq;
			break;
		}
	}
}

static void
mail_index_data_lookup_keywords(struct mail_index_map *map,
				const unsigned char *data,
				ARRAY_TYPE(keyword_indexes) *keyword_idx)
{
	const unsigned int *keyword_idx_map;
	unsigned int i, j, keyword_count, index_idx;
	uint32_t idx;
	uint16_t record_size;

	array_clear(keyword_idx);
	if (data == NULL) {
		/* no keywords at all in index */
		return;
	}
	(void)mail_index_ext_get_size(NULL, map->index->keywords_ext_id,
				      map, NULL, &record_size, NULL);

	/* keyword_idx_map[] contains file => index keyword mapping */
	if (!array_is_created(&map->keyword_idx_map))
		return;

	keyword_idx_map = array_get(&map->keyword_idx_map, &keyword_count);
	for (i = 0; i < record_size; i++) {
		/* first do the quick check to see if there's keywords at all */
		if (data[i] == 0)
			continue;

		idx = i * CHAR_BIT;
		for (j = 0; j < CHAR_BIT; j++, idx++) {
			if ((data[i] & (1 << j)) == 0)
				continue;

			if (idx >= keyword_count) {
				/* extra bits set in keyword bytes.
				   shouldn't happen, but just ignore. */
				break;
			}

			index_idx = keyword_idx_map[idx];
			array_append(keyword_idx, &index_idx, 1);
		}
	}
}

static void view_lookup_keywords(struct mail_index_view *view, uint32_t seq,
				 ARRAY_TYPE(keyword_indexes) *keyword_idx)
{
	struct mail_index_map *map;
	const void *data;

	mail_index_lookup_ext_full(view, seq, view->index->keywords_ext_id,
				   &map, &data, NULL);
	mail_index_data_lookup_keywords(map, data, keyword_idx);
}

static const void *
view_map_lookup_ext_full(struct mail_index_map *map,
			 const struct mail_index_record *rec, uint32_t ext_id)
{
	const struct mail_index_ext *ext;
	uint32_t idx;

	if (!mail_index_map_get_ext_idx(map, ext_id, &idx))
		return NULL;

	ext = array_idx(&map->extensions, idx);
	return ext->record_offset == 0 ? NULL :
		CONST_PTR_OFFSET(rec, ext->record_offset);
}

static void
view_lookup_ext_full(struct mail_index_view *view, uint32_t seq,
		     uint32_t ext_id, struct mail_index_map **map_r,
		     const void **data_r, bool *expunged_r)
{
	const struct mail_index_record *rec;

	rec = view->v.lookup_full(view, seq, map_r, expunged_r);
	*data_r = view_map_lookup_ext_full(*map_r, rec, ext_id);
}

static void view_get_header_ext(struct mail_index_view *view,
				struct mail_index_map *map, uint32_t ext_id,
				const void **data_r, size_t *data_size_r)
{
	const struct mail_index_ext *ext;
	uint32_t idx;

	if (map == NULL) {
		/* no mapping given, use head mapping */
		map = view->index->map;
	}

	if (!mail_index_map_get_ext_idx(map, ext_id, &idx)) {
		/* extension doesn't exist in this index file */
		*data_r = NULL;
		*data_size_r = 0;
		return;
	}

	ext = array_idx(&map->extensions, idx);
	*data_r = CONST_PTR_OFFSET(map->hdr_base, ext->hdr_offset);
	*data_size_r = ext->hdr_size;
}

static bool view_ext_get_reset_id(struct mail_index_view *view ATTR_UNUSED,
				  struct mail_index_map *map,
				  uint32_t ext_id, uint32_t *reset_id_r)
{
	const struct mail_index_ext *ext;
	uint32_t idx;

	if (!mail_index_map_get_ext_idx(map, ext_id, &idx))
		return FALSE;

	ext = array_idx(&map->extensions, idx);
	*reset_id_r = ext->reset_id;
	return TRUE;
}

void mail_index_view_close(struct mail_index_view **_view)
{
	struct mail_index_view *view = *_view;

	*_view = NULL;
	if (--view->refcount > 0)
		return;

	i_assert(view->transactions == 0);

	view->v.close(view);
}

uint32_t mail_index_view_get_messages_count(struct mail_index_view *view)
{
	return view->v.get_messages_count(view);
}

const struct mail_index_header *
mail_index_get_header(struct mail_index_view *view)
{
	return view->v.get_header(view);
}

const struct mail_index_record *
mail_index_lookup(struct mail_index_view *view, uint32_t seq)
{
	struct mail_index_map *map;

	return mail_index_lookup_full(view, seq, &map);
}

const struct mail_index_record *
mail_index_lookup_full(struct mail_index_view *view, uint32_t seq,
		       struct mail_index_map **map_r)
{
	bool expunged;

	return view->v.lookup_full(view, seq, map_r, &expunged);
}

bool mail_index_is_expunged(struct mail_index_view *view, uint32_t seq)
{
	struct mail_index_map *map;
	bool expunged;

	(void)view->v.lookup_full(view, seq, &map, &expunged);
	return expunged;
}

void mail_index_map_lookup_keywords(struct mail_index_map *map, uint32_t seq,
				    ARRAY_TYPE(keyword_indexes) *keyword_idx)
{
	const struct mail_index_ext *ext;
	const struct mail_index_record *rec;
	const void *data;
	uint32_t idx;

	if (!mail_index_map_get_ext_idx(map, map->index->keywords_ext_id, &idx))
		data = NULL;
	else {
		rec = MAIL_INDEX_MAP_IDX(map, seq-1);
		ext = array_idx(&map->extensions, idx);
		data = ext->record_offset == 0 ? NULL :
			CONST_PTR_OFFSET(rec, ext->record_offset);
	}
	mail_index_data_lookup_keywords(map, data, keyword_idx);
}

void mail_index_lookup_keywords(struct mail_index_view *view, uint32_t seq,
				ARRAY_TYPE(keyword_indexes) *keyword_idx)
{
	view->v.lookup_keywords(view, seq, keyword_idx);
}

void mail_index_lookup_view_flags(struct mail_index_view *view, uint32_t seq,
				  enum mail_flags *flags_r,
				  ARRAY_TYPE(keyword_indexes) *keyword_idx)
{
	const struct mail_index_record *rec;
	const unsigned char *keyword_data;

	i_assert(seq > 0 && seq <= mail_index_view_get_messages_count(view));

	rec = MAIL_INDEX_MAP_IDX(view->map, seq-1);
	*flags_r = rec->flags;

	keyword_data = view_map_lookup_ext_full(view->map, rec,
						view->index->keywords_ext_id);
	mail_index_data_lookup_keywords(view->map, keyword_data, keyword_idx);
}

void mail_index_lookup_uid(struct mail_index_view *view, uint32_t seq,
			   uint32_t *uid_r)
{
	view->v.lookup_uid(view, seq, uid_r);
}

bool mail_index_lookup_seq_range(struct mail_index_view *view,
				 uint32_t first_uid, uint32_t last_uid,
				 uint32_t *first_seq_r, uint32_t *last_seq_r)
{
	view->v.lookup_seq_range(view, first_uid, last_uid,
				 first_seq_r, last_seq_r);
	return *first_seq_r != 0;
}

bool mail_index_lookup_seq(struct mail_index_view *view,
			   uint32_t uid, uint32_t *seq_r)
{
	view->v.lookup_seq_range(view, uid, uid, seq_r, seq_r);
	return *seq_r != 0;
}

void mail_index_lookup_first(struct mail_index_view *view,
			     enum mail_flags flags, uint8_t flags_mask,
			     uint32_t *seq_r)
{
	view->v.lookup_first(view, flags, flags_mask, seq_r);
}

void mail_index_lookup_ext(struct mail_index_view *view, uint32_t seq,
			   uint32_t ext_id, const void **data_r,
			   bool *expunged_r)
{
	struct mail_index_map *map;

	mail_index_lookup_ext_full(view, seq, ext_id, &map, data_r, expunged_r);
}

void mail_index_lookup_ext_full(struct mail_index_view *view, uint32_t seq,
				uint32_t ext_id, struct mail_index_map **map_r,
				const void **data_r, bool *expunged_r)
{
	bool expunged;

	if (expunged_r == NULL)
		expunged_r = &expunged;

	view->v.lookup_ext_full(view, seq, ext_id, map_r, data_r, expunged_r);
}

void mail_index_get_header_ext(struct mail_index_view *view, uint32_t ext_id,
			       const void **data_r, size_t *data_size_r)
{
	view->v.get_header_ext(view, NULL, ext_id, data_r, data_size_r);
}

void mail_index_map_get_header_ext(struct mail_index_view *view,
				   struct mail_index_map *map, uint32_t ext_id,
				   const void **data_r, size_t *data_size_r)
{
	view->v.get_header_ext(view, map, ext_id, data_r, data_size_r);
}

bool mail_index_ext_get_reset_id(struct mail_index_view *view,
				 struct mail_index_map *map,
				 uint32_t ext_id, uint32_t *reset_id_r)
{
	return view->v.ext_get_reset_id(view, map, ext_id, reset_id_r);
}

void mail_index_ext_get_size(struct mail_index_view *view ATTR_UNUSED,
			     uint32_t ext_id, struct mail_index_map *map,
			     uint32_t *hdr_size_r, uint16_t *record_size_r,
			     uint16_t *record_align_r)
{
	const struct mail_index_ext *ext;
	uint32_t idx;

	i_assert(map != NULL);

	if (!mail_index_map_get_ext_idx(map, ext_id, &idx)) {
		/* extension doesn't exist in this index file */
		if (hdr_size_r != NULL)
			*hdr_size_r = 0;
		if (record_size_r != NULL)
			*record_size_r = 0;
		if (record_align_r != NULL)
			*record_align_r = 0;
		return;
	}

	ext = array_idx(&map->extensions, idx);
	if (hdr_size_r != NULL)
		*hdr_size_r = ext->hdr_size;
	if (record_size_r != NULL)
		*record_size_r = ext->record_size;
	if (record_align_r != NULL)
		*record_align_r = ext->record_align;
}

static struct mail_index_view_vfuncs view_vfuncs = {
	view_close,
	view_get_messages_count,
	view_get_header,
	view_lookup_full,
	view_lookup_uid,
	view_lookup_seq_range,
	view_lookup_first,
	view_lookup_keywords,
	view_lookup_ext_full,
	view_get_header_ext,
	view_ext_get_reset_id
};

struct mail_index_view *
mail_index_view_open_with_map(struct mail_index *index,
			      struct mail_index_map *map)
{
	struct mail_index_view *view;

	view = i_new(struct mail_index_view, 1);
	view->refcount = 1;
	view->v = view_vfuncs;
	view->index = index;
	view->log_view = mail_transaction_log_view_open(index->log);

	view->indexid = index->indexid;
	view->inconsistency_id = index->inconsistency_id;
	view->map = map;
	view->map->refcount++;

	view->log_file_expunge_seq = view->log_file_head_seq =
		view->map->hdr.log_file_seq;
	view->log_file_expunge_offset = view->log_file_head_offset =
		view->map->hdr.log_file_head_offset;

	i_array_init(&view->module_contexts,
		     I_MIN(5, mail_index_module_register.id));
	return view;
}

struct mail_index_view *mail_index_view_open(struct mail_index *index)
{
	return mail_index_view_open_with_map(index, index->map);
}

const struct mail_index_ext *
mail_index_view_get_ext(struct mail_index_view *view, uint32_t ext_id)
{
	uint32_t idx;

	if (!mail_index_map_get_ext_idx(view->map, ext_id, &idx))
		return NULL;

	return array_idx(&view->map->extensions, idx);
}
