/* Copyright (C) 2003-2004 Timo Sirainen */

/* Inside transaction we keep messages stored in sequences in uid fields.
   Before they're written to transaction log the sequences are changed to
   UIDs. This is because we're able to compress sequence ranges better. */

#include "lib.h"
#include "array.h"
#include "seq-range-array.h"
#include "mail-index-view-private.h"
#include "mail-transaction-log.h"
#include "mail-cache-private.h"
#include "mail-index-transaction-private.h"

#include <stddef.h>
#include <stdlib.h>

void (*hook_mail_index_transaction_created)
		(struct mail_index_transaction *t) = NULL;

static void mail_index_transaction_free(struct mail_index_transaction *t)
{
	ARRAY_TYPE(seq_array) *recs;
	unsigned i, count;

	if (array_is_created(&t->ext_rec_updates)) {
		recs = array_get_modifiable(&t->ext_rec_updates, &count);

		for (i = 0; i < count; i++) {
			if (array_is_created(&recs[i]))
				array_free(&recs[i]);
		}
		array_free(&t->ext_rec_updates);
	}

	if (array_is_created(&t->keyword_updates)) {
		struct mail_index_transaction_keyword_update *u;

		u = array_get_modifiable(&t->keyword_updates, &count);

		for (i = 0; i < count; i++) {
			if (array_is_created(&u[i].add_seq))
				array_free(&u[i].add_seq);
			if (array_is_created(&u[i].remove_seq))
				array_free(&u[i].remove_seq);
		}
		array_free(&t->keyword_updates);
	}
	if (array_is_created(&t->keyword_resets))
		array_free(&t->keyword_resets);

	if (array_is_created(&t->appends))
		array_free(&t->appends);
	if (array_is_created(&t->expunges))
		array_free(&t->expunges);
	if (array_is_created(&t->updates))
		array_free(&t->updates);
	if (array_is_created(&t->ext_resizes))
		array_free(&t->ext_resizes);
	if (array_is_created(&t->ext_resets))
		array_free(&t->ext_resets);

	array_free(&t->mail_index_transaction_module_contexts);
	mail_index_view_transaction_unref(t->view);
	mail_index_view_close(&t->view);
	i_free(t);
}

void mail_index_transaction_ref(struct mail_index_transaction *t)
{
	t->refcount++;
}

void mail_index_transaction_unref(struct mail_index_transaction **_t)
{
	struct mail_index_transaction *t = *_t;

	*_t = NULL;
	if (--t->refcount == 0)
		mail_index_transaction_free(t);
}

bool mail_index_seq_array_lookup(const ARRAY_TYPE(seq_array) *array,
				 uint32_t seq, unsigned int *idx_r)
{
	unsigned int idx, left_idx, right_idx, count;
	const uint32_t *seq_p;

	count = array_count(array);
	if (count == 0) {
		*idx_r = 0;
		return FALSE;
	}

	/* we're probably appending it, check */
	seq_p = array_idx(array, count-1);
	if (*seq_p < seq)
		idx = count;
	else {
		idx = 0; left_idx = 0; right_idx = count;
		while (left_idx < right_idx) {
			idx = (left_idx + right_idx) / 2;

			seq_p = array_idx(array, idx);
			if (*seq_p < seq)
				left_idx = idx+1;
			else if (*seq_p > seq)
				right_idx = idx;
			else {
				*idx_r = idx;
				return TRUE;
			}
		}
	}

	*idx_r = idx;
	return FALSE;
}

static bool mail_index_seq_array_add(ARRAY_TYPE(seq_array) *array, uint32_t seq,
				     const void *record, size_t record_size,
				     void *old_record)
{
	void *p;
	unsigned int idx;

	/* records need to be 32bit aligned */
	record_size = (record_size + 3) & ~3;

	if (!array_is_created(array)) {
		array_create(array, default_pool, sizeof(seq) + record_size,
			     1024 / (sizeof(seq) + record_size));
	}
	i_assert(array->arr.element_size == sizeof(seq) + record_size);

	if (mail_index_seq_array_lookup(array, seq, &idx)) {
		/* already there, update */
		p = array_idx_modifiable(array, idx);
		if (old_record != NULL) {
			/* save the old record before overwriting it */
			memcpy(old_record, PTR_OFFSET(p, sizeof(seq)),
			       record_size);
		}
		memcpy(PTR_OFFSET(p, sizeof(seq)), record, record_size);
		return TRUE;
	} else {
		/* insert */
                p = array_insert_space(array, idx);
		memcpy(p, &seq, sizeof(seq));
		memcpy(PTR_OFFSET(p, sizeof(seq)), record, record_size);
		return FALSE;
	}
}

static void
mail_index_buffer_convert_to_uids(struct mail_index_transaction *t,
				  ARRAY_TYPE(seq_array) *array, bool range)
{
        struct mail_index_view *view = t->view;
	const struct mail_index_record *rec;
	uint32_t *seq;
	unsigned int i, j, count, range_count;

	if (!array_is_created(array))
		return;

	count = array_count(array);
	range_count = range ? 1 : 0;
	for (i = 0; i < count; i++) {
		seq = array_idx_modifiable(array, i);

		for (j = 0; j <= range_count; j++, seq++) {
			i_assert(*seq > 0);

			if (*seq >= t->first_new_seq)
				rec = mail_index_transaction_lookup(t, *seq);
			else {
				i_assert(*seq <= view->map->records_count);
				rec = MAIL_INDEX_MAP_IDX(view->map, *seq - 1);
			}

			if (rec->uid == 0) {
				/* FIXME: replace with simple assert once we
				   figure out why this happens.. */
				i_panic("seq = %u, rec->uid = %u, "
					"first_new_seq = %u, records = %u",
					*seq, rec->uid, t->first_new_seq,
					view->map->records_count);
			}
			*seq = rec->uid;
		}
	}
}

static void keyword_updates_convert_to_uids(struct mail_index_transaction *t)
{
        struct mail_index_transaction_keyword_update *updates;
	unsigned int i, count;

	if (!array_is_created(&t->keyword_updates))
		return;

	updates = array_get_modifiable(&t->keyword_updates, &count);
	for (i = 0; i < count; i++) {
		if (array_is_created(&updates[i].add_seq)) {
			mail_index_buffer_convert_to_uids(t,
				(void *)&updates[i].add_seq, TRUE);
		}
		if (array_is_created(&updates[i].remove_seq)) {
			mail_index_buffer_convert_to_uids(t,
				(void *)&updates[i].remove_seq, TRUE);
		}
	}
}

static int
mail_index_transaction_convert_to_uids(struct mail_index_transaction *t)
{
	ARRAY_TYPE(seq_array) *updates;
	unsigned int i, count;

	if (mail_index_view_lock(t->view) < 0)
		return -1;

	if (array_is_created(&t->ext_rec_updates)) {
		updates = array_get_modifiable(&t->ext_rec_updates, &count);
		for (i = 0; i < count; i++) {
			if (!array_is_created(&updates[i]))
				continue;
			mail_index_buffer_convert_to_uids(t, &updates[i],
							  FALSE);
		}
	}

        keyword_updates_convert_to_uids(t);

	mail_index_buffer_convert_to_uids(t, (void *)&t->expunges, TRUE);
	mail_index_buffer_convert_to_uids(t, (void *)&t->updates, TRUE);
	mail_index_buffer_convert_to_uids(t, (void *)&t->keyword_resets, TRUE);
	return 0;
}

struct uid_map {
	uint32_t idx;
	uint32_t uid;
};

static int uid_map_cmp(const void *p1, const void *p2)
{
	const struct uid_map *m1 = p1, *m2 = p2;

	return m1->uid < m2->uid ? -1 :
		(m1->uid > m2->uid ? 1 : 0);
}

void mail_index_transaction_sort_appends(struct mail_index_transaction *t)
{
	struct mail_index_record *recs, *sorted_recs;
	struct uid_map *new_uid_map;
	ARRAY_TYPE(seq_array) *ext_rec_arrays;
	uint32_t *old_to_new_map;
	unsigned int i, j, count, ext_rec_array_count;

	if (!t->appends_nonsorted)
		return;

	/* first make a copy of the UIDs and map them to sequences */
	recs = array_get_modifiable(&t->appends, &count);
	new_uid_map = i_new(struct uid_map, count);
	for (i = 0; i < count; i++) {
		new_uid_map[i].idx = i;
		new_uid_map[i].uid = recs[i].uid;
	}

	/* now sort the UID map */
	qsort(new_uid_map, count, sizeof(*new_uid_map), uid_map_cmp);

	old_to_new_map = i_new(uint32_t, count);
	for (i = 0; i < count; i++)
		old_to_new_map[new_uid_map[i].idx] = i;

	/* sort mail records */
	sorted_recs = i_new(struct mail_index_record, count);
	for (i = 0; i < count; i++)
		sorted_recs[i] = recs[new_uid_map[i].idx];
	buffer_write(t->appends.arr.buffer, 0, sorted_recs,
		     sizeof(*sorted_recs) * count);
	i_free(sorted_recs);

	/* fix the order in extensions */
	if (!array_is_created(&t->ext_rec_updates)) {
		ext_rec_arrays = NULL;
		ext_rec_array_count = 0;
	} else {
		ext_rec_arrays = array_get_modifiable(&t->ext_rec_updates,
						      &ext_rec_array_count);
	}
	for (j = 0; j < ext_rec_array_count; j++) {
		ARRAY_TYPE(seq_array) *old_array = &ext_rec_arrays[j];
		ARRAY_TYPE(seq_array) new_array;
		unsigned int ext_count;
		const uint32_t *ext_rec;
		uint32_t seq;

		if (!array_is_created(old_array))
			continue;

		ext_count = array_count(old_array);
		array_create(&new_array, default_pool,
			     old_array->arr.element_size, ext_count);
		for (i = 0; i < ext_count; i++) {
			ext_rec = array_idx(old_array, i);

			seq = *ext_rec < t->first_new_seq ? *ext_rec :
				(t->first_new_seq +
				 old_to_new_map[*ext_rec - t->first_new_seq]);
			mail_index_seq_array_add(&new_array, seq, ext_rec+1,
						 old_array->arr.element_size -
						 sizeof(*ext_rec), NULL);
		}
		array_free(old_array);
		ext_rec_arrays[j] = new_array;
	}

	/* FIXME: fix the order in keywords */

	i_free(new_uid_map);
	i_free(old_to_new_map);

	t->appends_nonsorted = FALSE;
}

static int _mail_index_transaction_commit(struct mail_index_transaction *t,
					  uint32_t *log_file_seq_r,
					  uoff_t *log_file_offset_r)
{
	int ret;

	if (t->cache_trans_ctx != NULL) {
		mail_cache_transaction_commit(t->cache_trans_ctx);
                t->cache_trans_ctx = NULL;
	}

	mail_index_transaction_sort_appends(t);

	if (mail_index_transaction_convert_to_uids(t) < 0)
		ret = -1;
	else {
		ret = mail_transaction_log_append(t, log_file_seq_r,
						  log_file_offset_r);
	}

	mail_index_transaction_unref(&t);
	return ret;
}

static void _mail_index_transaction_rollback(struct mail_index_transaction *t)
{
	if (t->cache_trans_ctx != NULL) {
		mail_cache_transaction_rollback(t->cache_trans_ctx);
                t->cache_trans_ctx = NULL;
	}
        mail_index_transaction_unref(&t);
}

int mail_index_transaction_commit(struct mail_index_transaction **_t,
				  uint32_t *log_file_seq_r,
				  uoff_t *log_file_offset_r)
{
	struct mail_index_transaction *t = *_t;

	if (mail_index_view_is_inconsistent(t->view)) {
		mail_index_transaction_rollback(_t);
		return -1;
	}

	*_t = NULL;
	return t->v.commit(t, log_file_seq_r, log_file_offset_r);
}

void mail_index_transaction_rollback(struct mail_index_transaction **_t)
{
	struct mail_index_transaction *t = *_t;

	*_t = NULL;
	t->v.rollback(t);
}

struct mail_index_record *
mail_index_transaction_lookup(struct mail_index_transaction *t, uint32_t seq)
{
	i_assert(seq >= t->first_new_seq && seq <= t->last_new_seq);

	return array_idx_modifiable(&t->appends, seq - t->first_new_seq);
}

void mail_index_append(struct mail_index_transaction *t, uint32_t uid,
		       uint32_t *seq_r)
{
        struct mail_index_record *rec;

	i_assert(!t->no_appends);

	t->log_updates = TRUE;

	if (!array_is_created(&t->appends))
		i_array_init(&t->appends, 32);

	/* sequence number is visible only inside given view,
	   so let it generate it */
	if (t->last_new_seq != 0)
		*seq_r = ++t->last_new_seq;
	else
		*seq_r = t->last_new_seq = t->first_new_seq;

	rec = array_append_space(&t->appends);
	if (uid != 0) {
		rec->uid = uid;
		if (!t->appends_nonsorted &&
		    t->last_new_seq != t->first_new_seq) {
			/* if previous record's UID is larger than this one,
			   we'll have to sort the appends later */
			rec = mail_index_transaction_lookup(t, *seq_r - 1);
			if (rec->uid > uid)
				t->appends_nonsorted = TRUE;
		}
	}
}

void mail_index_append_assign_uids(struct mail_index_transaction *t,
				   uint32_t first_uid, uint32_t *next_uid_r)
{
	struct mail_index_record *recs;
	unsigned int i, count;

	i_assert(first_uid != 0);

	if (!array_is_created(&t->appends))
		return;

	recs = array_get_modifiable(&t->appends, &count);

	/* find the first mail with uid = 0 */
	for (i = 0; i < count; i++) {
		if (recs[i].uid == 0)
			break;
	}

	for (; i < count; i++) {
		i_assert(recs[i].uid == 0);
		recs[i].uid = first_uid++;
	}

	*next_uid_r = first_uid;
}

void mail_index_expunge(struct mail_index_transaction *t, uint32_t seq)
{
	i_assert(seq > 0 && seq <= mail_index_view_get_messages_count(t->view));

	t->log_updates = TRUE;

	/* expunges is a sorted array of {seq1, seq2, ..}, .. */
	seq_range_array_add(&t->expunges, 128, seq);
}

static void
mail_index_insert_flag_update(struct mail_index_transaction *t,
			      struct mail_transaction_flag_update u,
			      uint32_t left_idx, uint32_t right_idx)
{
	struct mail_transaction_flag_update *updates, tmp_update;
	unsigned int count;
	uint32_t idx, move;

	updates = array_get_modifiable(&t->updates, &count);

	i_assert(left_idx <= right_idx && right_idx <= count);

	/* find the first update with either overlapping range,
	   or the update which will come after our insert */
	idx = left_idx;
	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		if (updates[idx].uid2 < u.uid1)
			left_idx = idx+1;
		else if (updates[idx].uid1 > u.uid1)
			right_idx = idx;
		else
			break;
	}
	if (idx < count && updates[idx].uid2 < u.uid1)
		idx++;

	/* overlapping ranges, split/merge them */
	i_assert(idx == 0 || updates[idx-1].uid2 < u.uid1);
	i_assert(idx == count || updates[idx].uid2 >= u.uid1);

	for (; idx < count && u.uid2 >= updates[idx].uid1; idx++) {
		if (u.uid1 != updates[idx].uid1 &&
		    (updates[idx].add_flags != u.add_flags ||
		     updates[idx].remove_flags != u.remove_flags)) {
			if (u.uid1 < updates[idx].uid1) {
				/* insert new update */
				tmp_update = u;
				tmp_update.uid2 = updates[idx].uid1 - 1;
				move = 0;
			} else {
				/* split existing update from beginning */
				tmp_update = updates[idx];
				tmp_update.uid2 = u.uid1 - 1;
				updates[idx].uid1 = u.uid1;
				move = 1;
			}

			i_assert(tmp_update.uid1 <= tmp_update.uid2);
			i_assert(updates[idx].uid1 <= updates[idx].uid2);

			array_insert(&t->updates, idx, &tmp_update, 1);
			updates = array_get_modifiable(&t->updates, &count);
			idx += move;
		} else if (u.uid1 < updates[idx].uid1) {
			updates[idx].uid1 = u.uid1;
		}

		if (u.uid2 < updates[idx].uid2 &&
		    (updates[idx].add_flags != u.add_flags ||
		     updates[idx].remove_flags != u.remove_flags)) {
			/* split existing update from end */
			tmp_update = updates[idx];
			tmp_update.uid2 = u.uid2;
			updates[idx].uid1 = u.uid2 + 1;

			i_assert(tmp_update.uid1 <= tmp_update.uid2);
			i_assert(updates[idx].uid1 <= updates[idx].uid2);

			array_insert(&t->updates, idx, &tmp_update, 1);
			updates = array_get_modifiable(&t->updates, &count);
		}

		updates[idx].add_flags =
			(updates[idx].add_flags | u.add_flags) &
			~u.remove_flags;
		updates[idx].remove_flags =
			(updates[idx].remove_flags | u.remove_flags) &
			~u.add_flags;

		u.uid1 = updates[idx].uid2 + 1;
		if (u.uid1 > u.uid2) {
			/* break here before idx++ so last_update_idx is set
			   correctly */
			break;
		}
	}
	i_assert(idx <= count);

	if (u.uid1 <= u.uid2) {
		i_assert(idx == 0 || updates[idx-1].uid2 < u.uid1);
		i_assert(idx == count || updates[idx].uid1 > u.uid2);
		array_insert(&t->updates, idx, &u, 1);
	}
	t->last_update_idx = idx;
}

static void mail_index_record_modify_flags(struct mail_index_record *rec,
					   enum modify_type modify_type,
					   enum mail_flags flags)
{
	switch (modify_type) {
	case MODIFY_REPLACE:
		rec->flags = flags;
		break;
	case MODIFY_ADD:
		rec->flags |= flags;
		break;
	case MODIFY_REMOVE:
		rec->flags &= ~flags;
		break;
	}
}

void mail_index_update_flags_range(struct mail_index_transaction *t,
				   uint32_t seq1, uint32_t seq2,
				   enum modify_type modify_type,
				   enum mail_flags flags)
{
	struct mail_index_record *rec;
	struct mail_transaction_flag_update u, *last_update;
	unsigned int count;

	t->log_updates = TRUE;

	if (seq2 >= t->first_new_seq) {
		/* updates for appended messages, modify them directly */
		uint32_t seq;

		for (seq = I_MAX(t->first_new_seq, seq1); seq <= seq2; seq++) {
			rec = mail_index_transaction_lookup(t, seq);
			mail_index_record_modify_flags(rec, modify_type, flags);
		}
		if (seq1 >= t->first_new_seq)
			return;

		/* range contains also existing messages. update them next. */
		seq2 = t->first_new_seq - 1;
	}

	i_assert(seq1 <= seq2 && seq1 > 0);
	i_assert(seq2 <= mail_index_view_get_messages_count(t->view));

	memset(&u, 0, sizeof(u));
	u.uid1 = seq1;
	u.uid2 = seq2;

	switch (modify_type) {
	case MODIFY_REPLACE:
		u.add_flags = flags;
		u.remove_flags = ~flags & MAIL_INDEX_FLAGS_MASK;
		break;
	case MODIFY_ADD:
		u.add_flags = flags;
		break;
	case MODIFY_REMOVE:
		u.remove_flags = flags;
		break;
	}

	if (!array_is_created(&t->updates)) {
		i_array_init(&t->updates, 256);
		array_append(&t->updates, &u, 1);
		return;
	}

	last_update = array_get_modifiable(&t->updates, &count);
	if (t->last_update_idx < count) {
		/* fast path - hopefully we're updating the next message,
		   or a message that is to be appended as last update */
		last_update += t->last_update_idx;
		if (seq1 - 1 == last_update->uid2) {
			if (u.add_flags == last_update->add_flags &&
			    u.remove_flags == last_update->remove_flags &&
			    (t->last_update_idx + 1 == count ||
			     last_update[1].uid1 > seq2)) {
				/* we can just update the UID range */
				last_update->uid2 = seq2;
				return;
			}
		} else if (seq1 > last_update->uid2) {
			/* hopefully we can just append it */
			t->last_update_idx++;
			last_update++;
		}
	}

	if (t->last_update_idx == count) {
		array_append(&t->updates, &u, 1);
		return;
	}

	/* slow path */
	if (seq1 > last_update->uid2) {
		/* added after this */
		mail_index_insert_flag_update(t, u, t->last_update_idx + 1,
					      count);
	} else {
		/* added before this or on top of this */
		mail_index_insert_flag_update(t, u, 0, t->last_update_idx + 1);
	}
}

void mail_index_update_flags(struct mail_index_transaction *t, uint32_t seq,
			     enum modify_type modify_type,
			     enum mail_flags flags)
{
	mail_index_update_flags_range(t, seq, seq, modify_type, flags);
}

void mail_index_update_header(struct mail_index_transaction *t,
			      size_t offset, const void *data, size_t size,
			      bool prepend)
{
	i_assert(offset < sizeof(t->pre_hdr_change));
	i_assert(size <= sizeof(t->pre_hdr_change) - offset);

	t->log_updates = TRUE;

	if (prepend) {
		t->pre_hdr_changed = TRUE;
		memcpy(t->pre_hdr_change + offset, data, size);
		for (; size > 0; size--)
			t->pre_hdr_mask[offset++] = 1;
	} else {
		t->post_hdr_changed = TRUE;
		memcpy(t->post_hdr_change + offset, data, size);
		for (; size > 0; size--)
			t->post_hdr_mask[offset++] = 1;
	}
}

void mail_index_ext_resize(struct mail_index_transaction *t, uint32_t ext_id,
			   uint32_t hdr_size, uint16_t record_size,
			   uint16_t record_align)
{
	struct mail_transaction_ext_intro intro;
	uint32_t old_record_size, old_record_align;

	memset(&intro, 0, sizeof(intro));

	/* get ext_id from transaction's map if it's there */
	if (!mail_index_map_get_ext_idx(t->view->map, ext_id, &intro.ext_id)) {
		/* have to create it */
		const struct mail_index_registered_ext *rext;

		intro.ext_id = (uint32_t)-1;
		rext = array_idx(&t->view->index->extensions, ext_id);
		old_record_size = rext->record_size;
		old_record_align = rext->record_align;
	} else {
		const struct mail_index_ext *ext;

		ext = array_idx(&t->view->map->extensions, ext_id);
		old_record_size = ext->record_size;
		old_record_align = ext->record_align;
	}

	/* allow only header size changes if extension records have already
	   been changed in transaction */
	i_assert(!array_is_created(&t->ext_rec_updates) ||
		 (old_record_size == record_size &&
		  old_record_align == record_align));

	t->log_updates = TRUE;

	if (!array_is_created(&t->ext_resizes))
		i_array_init(&t->ext_resizes, ext_id + 2);

	intro.hdr_size = hdr_size;
	intro.record_size = record_size;
	intro.record_align = record_align;
	intro.name_size = 1;
	array_idx_set(&t->ext_resizes, ext_id, &intro);
}

void mail_index_ext_reset(struct mail_index_transaction *t, uint32_t ext_id,
			  uint32_t reset_id)
{
	i_assert(reset_id != 0);

	t->log_updates = TRUE;

	if (array_is_created(&t->ext_rec_updates) &&
	    ext_id < array_count(&t->ext_rec_updates)) {
		/* if extension records have been updated, clear them */
		ARRAY_TYPE(seq_array) *array;

		array = array_idx_modifiable(&t->ext_rec_updates, ext_id);
		if (array_is_created(array))
			array_clear(array);
	}

	if (!array_is_created(&t->ext_resets))
		i_array_init(&t->ext_resets, ext_id + 2);
	array_idx_set(&t->ext_resets, ext_id, &reset_id);
}

void mail_index_update_header_ext(struct mail_index_transaction *t,
				  uint32_t ext_id, size_t offset,
				  const void *data, size_t size)
{
	// FIXME
}

void mail_index_update_ext(struct mail_index_transaction *t, uint32_t seq,
			   uint32_t ext_id, const void *data, void *old_data_r)
{
	struct mail_index *index = t->view->index;
        const struct mail_index_registered_ext *rext;
	const struct mail_transaction_ext_intro *intro;
	uint16_t record_size;
	ARRAY_TYPE(seq_array) *array;
	unsigned int count;

	i_assert(seq > 0 &&
		 (seq <= mail_index_view_get_messages_count(t->view) ||
		  seq <= t->last_new_seq));
	i_assert(ext_id < array_count(&index->extensions));

	t->log_updates = TRUE;

	if (!array_is_created(&t->ext_resizes)) {
		intro = NULL;
		count = 0;
	} else {
		intro = array_get(&t->ext_resizes, &count);
	}
	if (ext_id < count && intro[ext_id].name_size != 0) {
		/* resized record */
		record_size = intro[ext_id].record_size;
	} else {
		rext = array_idx(&index->extensions, ext_id);
		record_size = rext->record_size;
	}

	if (!array_is_created(&t->ext_rec_updates))
		i_array_init(&t->ext_rec_updates, ext_id + 2);
	array = array_idx_modifiable(&t->ext_rec_updates, ext_id);

	/* @UNSAFE */
	if (!mail_index_seq_array_add(array, seq, data, record_size,
				      old_data_r)) {
		/* not found, clear old_data if it was given */
		if (old_data_r != NULL)
			memset(old_data_r, 0, record_size);
	}
}

struct mail_keywords *
mail_index_keywords_create(struct mail_index_transaction *t,
			   const char *const keywords[])
{
	struct mail_index *index = t->view->index;
	struct mail_keywords *k;
	unsigned int i, count;

	count = strarray_length(keywords);
	if (count == 0) {
		k = i_new(struct mail_keywords, 1);
		k->index = index;
		return k;
	}

	/* @UNSAFE */
	k = i_malloc(sizeof(struct mail_keywords) +
		     (sizeof(k->idx) * (count-1)));
	k->index = index;
	k->count = count;

	/* look up the keywords from index. they're never removed from there
	   so we can permanently store indexes to them. */
	for (i = 0; i < count; i++) {
		(void)mail_index_keyword_lookup(index, keywords[i],
						TRUE, &k->idx[i]);
	}
	return k;
}

struct mail_keywords *
mail_index_keywords_create_from_indexes(struct mail_index_transaction *t,
					const ARRAY_TYPE(keyword_indexes)
						*keyword_indexes)
{
	struct mail_keywords *k;
	unsigned int count;

	count = array_count(keyword_indexes);
	if (count == 0) {
		k = i_new(struct mail_keywords, 1);
		k->index = t->view->index;
		return k;
	}

	/* @UNSAFE */
	k = i_malloc(sizeof(struct mail_keywords) +
		     (sizeof(k->idx) * (count-1)));
	k->index = t->view->index;
	k->count = count;

	memcpy(k->idx, array_idx(keyword_indexes, 0),
	       count * sizeof(k->idx[0]));
	return k;
}

void mail_index_keywords_free(struct mail_keywords **keywords)
{
	i_free(*keywords);
	*keywords = NULL;
}

void mail_index_update_keywords(struct mail_index_transaction *t, uint32_t seq,
				enum modify_type modify_type,
				struct mail_keywords *keywords)
{
	struct mail_index_transaction_keyword_update *u;
	unsigned int i, ku_count;

	i_assert(seq > 0 &&
		 (seq <= mail_index_view_get_messages_count(t->view) ||
		  seq <= t->last_new_seq));
	i_assert(keywords->count > 0 || modify_type == MODIFY_REPLACE);
	i_assert(keywords->index == t->view->index);

	if (!array_is_created(&t->keyword_updates) && keywords->count > 0) {
		uint32_t max_idx = keywords->idx[keywords->count-1];

		i_array_init(&t->keyword_updates, max_idx + 1);
	}

	/* Update add_seq and remove_seq arrays which describe the keyword
	   changes. Don't bother updating remove_seq or keyword resets for
	   newly added messages since they default to not having any
	   keywords anyway. */
	switch (modify_type) {
	case MODIFY_ADD:
		for (i = 0; i < keywords->count; i++) {
			u = array_idx_modifiable(&t->keyword_updates,
						 keywords->idx[i]);
			seq_range_array_add(&u->add_seq, 16, seq);
			if (seq < t->first_new_seq)
				seq_range_array_remove(&u->remove_seq, seq);
		}
		break;
	case MODIFY_REMOVE:
		for (i = 0; i < keywords->count; i++) {
			u = array_idx_modifiable(&t->keyword_updates,
						 keywords->idx[i]);
			seq_range_array_remove(&u->add_seq, seq);
			if (seq < t->first_new_seq)
				seq_range_array_add(&u->remove_seq, 16, seq);
		}
		break;
	case MODIFY_REPLACE:
		/* Remove sequence from all add/remove arrays */
		if (array_is_created(&t->keyword_updates)) {
			u = array_get_modifiable(&t->keyword_updates,
						 &ku_count);
			for (i = 0; i < ku_count; i++) {
				seq_range_array_remove(&u[i].add_seq, seq);
				if (seq < t->first_new_seq) {
					seq_range_array_remove(
						&u[i].remove_seq, seq);
				}
			}
		}
		/* Add the wanted keyword back */
		for (i = 0; i < keywords->count; i++) {
			u = array_idx_modifiable(&t->keyword_updates,
						 keywords->idx[i]);
			seq_range_array_add(&u->add_seq, 16, seq);
		}

		if (seq < t->first_new_seq)
			seq_range_array_add(&t->keyword_resets, 16, seq);
		break;
	}

	t->log_updates = TRUE;
}

struct mail_index_transaction_vfuncs trans_vfuncs = {
	_mail_index_transaction_commit,
	_mail_index_transaction_rollback
};

struct mail_index_transaction *
mail_index_transaction_begin(struct mail_index_view *view,
			     bool hide, bool external)
{
	struct mail_index_transaction *t;

	/* don't allow syncing view while there's ongoing transactions */
	mail_index_view_transaction_ref(view);
 	mail_index_view_ref(view);

	t = i_new(struct mail_index_transaction, 1);
	t->refcount = 1;
	t->v = trans_vfuncs;
	t->view = view;
	t->hide_transaction = hide;
	t->external = external;
	t->first_new_seq = mail_index_view_get_messages_count(t->view)+1;
	t->sync_transaction = view->index_sync_view;

	if (view->syncing) {
		/* transaction view cannot work if new records are being added
		   in two places. make sure it doesn't happen. */
		t->no_appends = TRUE;
	}

	array_create(&t->mail_index_transaction_module_contexts, default_pool,
		     sizeof(void *), I_MIN(5, mail_index_module_id));

	if (hook_mail_index_transaction_created != NULL)
		hook_mail_index_transaction_created(t);
	return t;
}
