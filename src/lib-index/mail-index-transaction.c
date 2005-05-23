/* Copyright (C) 2003-2004 Timo Sirainen */

/* Inside transaction we keep messages stored in sequences in uid fields.
   Before they're written to transaction log the sequences are changed to
   UIDs. This is because we're able to compress sequence ranges better. */

#include "lib.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-transaction-log.h"
#include "mail-cache-private.h"
#include "mail-index-transaction-private.h"

#include <stddef.h>
#include <stdlib.h>

struct mail_index_transaction *
mail_index_transaction_begin(struct mail_index_view *view,
			     int hide, int external)
{
	struct mail_index_transaction *t;

	/* don't allow syncing view while there's ongoing transactions */
	mail_index_view_transaction_ref(view);
 	mail_index_view_ref(view);

	t = i_new(struct mail_index_transaction, 1);
	t->refcount = 1;
	t->view = view;
	t->hide_transaction = hide;
	t->external = external;
	t->first_new_seq = mail_index_view_get_messages_count(t->view)+1;

	if (view->syncing) {
		/* transaction view cannot work if new records are being added
		   in two places. make sure it doesn't happen. */
		t->no_appends = TRUE;
	}

	return t;
}

static void mail_index_transaction_free(struct mail_index_transaction *t)
{
	array_t *recs;
	unsigned i, count;

	if (array_is_created(&t->ext_rec_updates)) {
		recs = array_get_modifyable(&t->ext_rec_updates, &count);

		for (i = 0; i < count; i++) {
			if (array_is_created(&recs[i]))
				array_free(&recs[i]);
		}
		array_free(&t->ext_rec_updates);
	}

	if (array_is_created(&t->keyword_updates)) {
		struct mail_index_transaction_keyword_update *u;

		u = array_get_modifyable(&t->keyword_updates, &count);

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

	mail_index_view_transaction_unref(t->view);
	mail_index_view_close(t->view);
	i_free(t);
}

void mail_index_transaction_ref(struct mail_index_transaction *t)
{
	t->refcount++;
}

void mail_index_transaction_unref(struct mail_index_transaction *t)
{
	if (--t->refcount == 0)
		mail_index_transaction_free(t);
}

static void
mail_index_buffer_convert_to_uids(struct mail_index_transaction *t,
				  array_t *array, int range)
{
        ARRAY_SET_TYPE(array, uint32_t);
        struct mail_index_view *view = t->view;
	const struct mail_index_record *rec;
	uint32_t *seq;
	unsigned int i, count;
	int j;

	if (!array_is_created(array))
		return;

	count = array_count(array);
	for (i = 0; i < count; i++) {
		seq = array_modifyable_idx(array, i);

		for (j = 0; j <= range; j++, seq++) {
			if (*seq >= t->first_new_seq) {
				rec = mail_index_transaction_lookup(t, *seq);
				*seq = rec->uid;
			} else {
				i_assert(*seq <= view->map->records_count);
				*seq = MAIL_INDEX_MAP_IDX(view->map,
							  *seq - 1)->uid;
			}
			i_assert(*seq != 0);
		}
	}
}

static void arrays_convert_to_uids(struct mail_index_transaction *t,
				   array_t *array, int range)
{
	ARRAY_SET_TYPE(array, array_t);
	array_t *updates;
	unsigned int i, count;

	if (!array_is_created(array))
		return;

	updates = array_get_modifyable(array, &count);
	for (i = 0; i < count; i++) {
		if (array_is_created(&updates[i])) {
			mail_index_buffer_convert_to_uids(t, &updates[i],
							  range);
		}
	}
}

static int
mail_index_transaction_convert_to_uids(struct mail_index_transaction *t)
{
	if (mail_index_view_lock(t->view) < 0)
		return -1;

	arrays_convert_to_uids(t, &t->ext_rec_updates, FALSE);
	arrays_convert_to_uids(t, &t->keyword_updates, TRUE);

	mail_index_buffer_convert_to_uids(t, &t->expunges, TRUE);
	mail_index_buffer_convert_to_uids(t, &t->updates, TRUE);
	mail_index_buffer_convert_to_uids(t, &t->keyword_resets, TRUE);
	return 0;
}

int mail_index_transaction_commit(struct mail_index_transaction *t,
				  uint32_t *log_file_seq_r,
				  uoff_t *log_file_offset_r)
{
	int ret;

	if (mail_index_view_is_inconsistent(t->view)) {
		mail_index_transaction_rollback(t);
		return -1;
	}

	if (t->cache_trans_ctx != NULL) {
		mail_cache_transaction_commit(t->cache_trans_ctx);
                t->cache_trans_ctx = NULL;
	}

	if (mail_index_transaction_convert_to_uids(t) < 0)
		ret = -1;
	else {
		ret = mail_transaction_log_append(t, log_file_seq_r,
						  log_file_offset_r);
	}

	mail_index_transaction_unref(t);
	return ret;
}

void mail_index_transaction_rollback(struct mail_index_transaction *t)
{
	if (t->cache_trans_ctx != NULL) {
		mail_cache_transaction_rollback(t->cache_trans_ctx);
                t->cache_trans_ctx = NULL;
	}
        mail_index_transaction_unref(t);
}

struct mail_index_record *
mail_index_transaction_lookup(struct mail_index_transaction *t, uint32_t seq)
{
	i_assert(seq >= t->first_new_seq && seq <= t->last_new_seq);

	return array_modifyable_idx(&t->appends, seq - t->first_new_seq);
}

void mail_index_append(struct mail_index_transaction *t, uint32_t uid,
		       uint32_t *seq_r)
{
        struct mail_index_record *rec;

	i_assert(!t->no_appends);

	t->log_updates = TRUE;

	if (!array_is_created(&t->appends)) {
		ARRAY_CREATE(&t->appends, default_pool,
			     struct mail_index_record, 32);
	}

	/* sequence number is visible only inside given view,
	   so let it generate it */
	if (t->last_new_seq != 0)
		*seq_r = ++t->last_new_seq;
	else
		*seq_r = t->last_new_seq = t->first_new_seq;

	rec = array_modifyable_append(&t->appends);
	rec->uid = uid;
}

void mail_index_append_assign_uids(struct mail_index_transaction *t,
				   uint32_t first_uid, uint32_t *next_uid_r)
{
	struct mail_index_record *recs;
	unsigned int i, count;

	if (!array_is_created(&t->appends))
		return;

	recs = array_get_modifyable(&t->appends, &count);

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

struct seq_range {
	uint32_t seq1, seq2;
};

static void
mail_index_seq_range_array_add(array_t *array, unsigned int init_count,
			       uint32_t seq)
{
        ARRAY_SET_TYPE(array, struct seq_range);
	struct seq_range *data, value;
	unsigned int idx, left_idx, right_idx, count;

	value.seq1 = value.seq2 = seq;

	if (!array_is_created(array)) {
		array_create(array, default_pool,
			     sizeof(struct seq_range), init_count);
		array_append(array, &value, 1);
		return;
	}

	data = array_get_modifyable(array, &count);
	i_assert(count > 0);

	/* quick checks */
	if (data[count-1].seq2 == seq-1) {
		/* grow last range */
		data[count-1].seq2 = seq;
		return;
	}
	if (data[count-1].seq2 < seq) {
		array_append(array, &value, 1);
		return;
	}
	if (data[0].seq1 == seq+1) {
		/* grow down first range */
		data[0].seq1 = seq;
		return;
	}
	if (data[0].seq1 > seq) {
		array_insert(array, 0, &value, 1);
		return;
	}

	/* somewhere in the middle, array is sorted so find it with
	   binary search */
	idx = 0; left_idx = 0; right_idx = count;
	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		if (data[idx].seq1 <= seq) {
			if (data[idx].seq2 >= seq) {
				/* it's already in the range */
				return;
			}
			left_idx = idx+1;
		} else {
			right_idx = idx;
		}
	}

	if (data[idx].seq2 < seq)
		idx++;

        /* idx == count couldn't happen because we already handle it above */
	i_assert(idx < count && data[idx].seq1 >= seq);
	i_assert(data[idx].seq1 > seq || data[idx].seq2 < seq);

	if (data[idx].seq1 == seq+1) {
		data[idx].seq1 = seq;
		if (idx > 0 && data[idx-1].seq2 == seq-1) {
			/* merge */
			data[idx-1].seq2 = data[idx].seq2;
			array_delete(array, idx, 1);
		}
	} else if (data[idx].seq2 == seq-1) {
		i_assert(idx+1 < count); /* already handled above */
		data[idx].seq2 = seq;
		if (data[idx+1].seq1 == seq+1) {
			/* merge */
			data[idx+1].seq1 = data[idx].seq1;
			array_delete(array, idx, 1);
		}
	} else {
		array_insert(array, idx, &value, 1);
	}
}

static void mail_index_seq_range_array_remove(array_t *array, uint32_t seq)
{
        ARRAY_SET_TYPE(array, struct seq_range);
	struct seq_range *data, value;
	unsigned int idx, left_idx, right_idx, count;

	if (!array_is_created(array))
		return;

	data = array_get_modifyable(array, &count);
	i_assert(count > 0);

	/* quick checks */
	if (seq > data[count-1].seq2 || seq < data[0].seq1) {
		/* outside the range */
		return;
	}
	if (data[count-1].seq2 == seq) {
		/* shrink last range */
		data[count-1].seq2--;
		return;
	}
	if (data[0].seq1 == seq) {
		/* shrink up first range */
		data[0].seq1++;
		return;
	}

	/* somewhere in the middle, array is sorted so find it with
	   binary search */
	idx = 0; left_idx = 0; right_idx = count;
	while (left_idx < right_idx) {
		idx = (left_idx + right_idx) / 2;

		if (data[idx].seq1 > seq)
			right_idx = idx;
		else if (data[idx].seq2 < seq)
			left_idx = idx+1;
		else {
			/* found it */
			if (data[idx].seq1 == seq) {
				if (data[idx].seq1 == data[idx].seq2) {
					/* a single sequence range.
					   remove it entirely */
					array_delete(array, idx, 1);
				} else {
					/* shrink the range */
					data[idx].seq1++;
				}
			} else if (data[idx].seq2 == seq) {
				/* shrink the range */
				data[idx].seq2--;
			} else {
				/* split the sequence range */
				value.seq1 = seq + 1;
				value.seq2 = data[idx].seq2;
				data[idx].seq2 = seq - 1;

				array_insert(array, idx, &value, 1);
			}
			break;
		}
	}
}

void mail_index_expunge(struct mail_index_transaction *t, uint32_t seq)
{
	i_assert(seq > 0 && seq <= mail_index_view_get_messages_count(t->view));

	t->log_updates = TRUE;

	/* expunges is a sorted array of {seq1, seq2, ..}, .. */
	mail_index_seq_range_array_add(&t->expunges, 128, seq);
}

static void
mail_index_insert_flag_update(struct mail_index_transaction *t,
			      struct mail_transaction_flag_update u,
			      uint32_t left_idx, uint32_t right_idx)
{
	struct mail_transaction_flag_update *updates, tmp_update;
	unsigned int count;
	uint32_t idx, move;

	updates = array_get_modifyable(&t->updates, &count);

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
			updates = array_get_modifyable(&t->updates, &count);
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
			updates = array_get_modifyable(&t->updates, &count);
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
		ARRAY_CREATE(&t->updates, default_pool,
			     struct mail_transaction_flag_update, 256);
		array_append(&t->updates, &u, 1);
		return;
	}

	last_update = array_get_modifyable(&t->updates, &count);
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

int mail_index_seq_array_lookup(const array_t *array, uint32_t seq,
				unsigned int *idx_r)
{
        ARRAY_SET_TYPE(array, uint32_t);
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

static int mail_index_seq_array_add(array_t *array, uint32_t seq,
				    const void *record, size_t record_size,
				    void *old_record)
{
        ARRAY_SET_TYPE(array, void *);
	void *p;
	unsigned int idx;

	if (!array_is_created(array)) {
		array_create(array, default_pool,
			     sizeof(seq) + record_size,
			     1024 / (sizeof(seq) + record_size));
	}
	i_assert(array->element_size == sizeof(seq) + record_size);

	if (mail_index_seq_array_lookup(array, seq, &idx)) {
		/* already there, update */
		p = array_modifyable_idx(array, idx);
		if (old_record != NULL) {
			memcpy(old_record, PTR_OFFSET(p, sizeof(seq)),
			       record_size);
		}
		memcpy(PTR_OFFSET(p, sizeof(seq)), record, record_size);
		return TRUE;
	} else {
		/* insert */
                p = array_modifyable_insert(array, idx);
		memcpy(p, &seq, sizeof(seq));
		memcpy(PTR_OFFSET(p, sizeof(seq)), record, record_size);
		return FALSE;
	}
}

void mail_index_update_header(struct mail_index_transaction *t,
			      size_t offset, const void *data, size_t size,
			      int prepend)
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
	const struct mail_index_ext *ext;

	memset(&intro, 0, sizeof(intro));

	if (!mail_index_map_get_ext_idx(t->view->map, ext_id, &intro.ext_id)) {
		intro.ext_id = (uint32_t)-1;
		ext = array_idx(&t->view->index->extensions, ext_id);
	} else {
		ext = array_idx(&t->view->map->extensions, ext_id);
	}

	/* allow only header size changes if extension records have already
	   been changed in transaction */
	i_assert(!array_is_created(&t->ext_rec_updates) ||
		 (ext->record_size == record_size &&
		  ext->record_align == record_align));

	t->log_updates = TRUE;

	if (!array_is_created(&t->ext_resizes)) {
		ARRAY_CREATE(&t->ext_resizes, default_pool,
			     struct mail_transaction_ext_intro, ext_id + 2);
	}

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
		array_t *array;

		array = array_modifyable_idx(&t->ext_rec_updates, ext_id);
		if (array_is_created(array))
			array_clear(array);
	}

	if (!array_is_created(&t->ext_resets)) {
		ARRAY_CREATE(&t->ext_resets, default_pool,
			     uint32_t, ext_id + 2);
	}
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
        const struct mail_index_ext *ext;
	const struct mail_transaction_ext_intro *intro;
	uint16_t record_size;
	array_t *array;
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
		ext = array_idx(&index->extensions, ext_id);
		record_size = ext->record_size;
	}

	if (!array_is_created(&t->ext_rec_updates)) {
		ARRAY_CREATE(&t->ext_rec_updates, default_pool,
			     array_t, ext_id + 2);
	}
	array = array_modifyable_idx(&t->ext_rec_updates, ext_id);

	/* @UNSAFE */
	if (!mail_index_seq_array_add(array, seq, data, record_size,
				      old_data_r)) {
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

	if (keywords == NULL) {
		k = i_new(struct mail_keywords, 1);
		k->index = index;
		return k;
	}
	count = strarray_length(keywords);

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
					const array_t *keyword_indexes)
{
	ARRAY_SET_TYPE(keyword_indexes, unsigned int);
	struct mail_keywords *k;
	unsigned int count;

	count = array_count(keyword_indexes);

	/* @UNSAFE */
	k = i_malloc(sizeof(struct mail_keywords) +
		     (sizeof(k->idx) * (count-1)));
	k->index = t->view->index;
	k->count = count;

	memcpy(k->idx, array_get(keyword_indexes, NULL),
	       count * sizeof(k->idx[0]));
	return k;
}

void mail_index_keywords_free(struct mail_keywords *keywords)
{
	i_free(keywords);
}

void mail_index_update_keywords(struct mail_index_transaction *t, uint32_t seq,
				enum modify_type modify_type,
				struct mail_keywords *keywords)
{
	struct mail_index_transaction_keyword_update *u;
	unsigned int i;

	i_assert(seq > 0 &&
		 (seq <= mail_index_view_get_messages_count(t->view) ||
		  seq <= t->last_new_seq));
	i_assert(keywords->count > 0 || modify_type == MODIFY_REPLACE);
	i_assert(keywords->index == t->view->index);

	if (!array_is_created(&t->keyword_updates)) {
		uint32_t max_idx = keywords->idx[keywords->count-1];

		ARRAY_CREATE(&t->keyword_updates, default_pool,
			     struct mail_index_transaction_keyword_update,
			     max_idx);
	}

	switch (modify_type) {
	case MODIFY_ADD:
		for (i = 0; i < keywords->count; i++) {
			u = array_modifyable_idx(&t->keyword_updates,
						 keywords->idx[i]);
			mail_index_seq_range_array_add(&u->add_seq, 16, seq);
			mail_index_seq_range_array_remove(&u->remove_seq, seq);
		}
		break;
	case MODIFY_REMOVE:
		for (i = 0; i < keywords->count; i++) {
			u = array_modifyable_idx(&t->keyword_updates,
						 keywords->idx[i]);
			mail_index_seq_range_array_remove(&u->add_seq, seq);
			mail_index_seq_range_array_add(&u->remove_seq, 16, seq);
		}
		break;
	case MODIFY_REPLACE:
		for (i = 0; i < keywords->count; i++) {
			u = array_modifyable_idx(&t->keyword_updates,
						 keywords->idx[i]);
			mail_index_seq_range_array_add(&u->add_seq, 16, seq);
		}

		/* If t->keyword_resets is set for a sequence, there's no
		   need to update remove_seq as it will remove all keywords. */
		mail_index_seq_range_array_add(&t->keyword_resets, 16, seq);
		break;
	}

	t->log_updates = TRUE;
}
