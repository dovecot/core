/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "seq-range-array.h"
#include "mail-index-private.h"
#include "mail-index-view-private.h"
#include "mail-index-transaction-private.h"

struct mail_index_view_transaction {
	struct mail_index_view view;
	struct mail_index_view_vfuncs *super;
	struct mail_index_transaction *t;

	struct mail_index_map *lookup_map;
	struct mail_index_header hdr;

	buffer_t *lookup_return_data;
	uint32_t lookup_prev_seq;

	unsigned int record_size;
	unsigned int recs_count;
	void *recs;
	ARRAY_DEFINE(all_recs, void *);
};

static void tview_close(struct mail_index_view *view)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;
	struct mail_index_transaction *t = tview->t;
	void **recs;
	unsigned int i, count;

	if (tview->lookup_map != NULL)
		mail_index_unmap(&tview->lookup_map);
	if (tview->lookup_return_data != NULL)
		buffer_free(&tview->lookup_return_data);

	if (array_is_created(&tview->all_recs)) {
		recs = array_get_modifiable(&tview->all_recs, &count);
		for (i = 0; i < count; i++)
			i_free(recs[i]);
		array_free(&tview->all_recs);
	}

	tview->super->close(view);
	mail_index_transaction_unref(&t);
}

static uint32_t tview_get_message_count(struct mail_index_view *view)
{
	struct mail_index_view_transaction *tview =
                (struct mail_index_view_transaction *)view;

	return view->map->hdr.messages_count +
		(tview->t->last_new_seq == 0 ? 0 :
		 tview->t->last_new_seq - tview->t->first_new_seq + 1);
}

static const struct mail_index_header *
tview_get_header(struct mail_index_view *view)
{
	struct mail_index_view_transaction *tview =
                (struct mail_index_view_transaction *)view;
	const struct mail_index_header *hdr;
	uint32_t next_uid;

	/* FIXME: header counters may not be correct */
	hdr = tview->super->get_header(view);

	next_uid = mail_index_transaction_get_next_uid(tview->t);
	if (next_uid != hdr->next_uid) {
		tview->hdr = *hdr;
		tview->hdr.next_uid = next_uid;
		hdr = &tview->hdr;
	}
	return hdr;
}

static const struct mail_index_record *
tview_apply_flag_updates(struct mail_index_view_transaction *tview,
			 struct mail_index_map *map,
			 const struct mail_index_record *rec, uint32_t seq)
{
	struct mail_index_transaction *t = tview->t;
	const struct mail_transaction_flag_update *updates;
	struct mail_index_record *trec;
	unsigned int idx, count;

	/* see if there are any flag updates */
	if (seq < t->min_flagupdate_seq || seq > t->max_flagupdate_seq ||
	    !array_is_created(&t->updates))
		return rec;

	updates = array_get(&t->updates, &count);
	idx = mail_index_transaction_get_flag_update_pos(t, 0, count, seq);
	if (seq < updates[idx].uid1 || seq > updates[idx].uid2)
		return rec;

	/* yes, we have flag updates. since we can't modify rec directly and
	   we want to be able to handle multiple mail_index_lookup() calls
	   without the second one overriding the first one's data, we'll
	   create a records array and return data from there.

	   it's also possible that the record size increases, so we potentially
	   have to create multiple arrays. they all get eventually freed when
	   the view gets freed. */
	if (map->hdr.record_size > tview->record_size) {
		if (!array_is_created(&tview->all_recs))
			i_array_init(&tview->all_recs, 4);
		tview->recs_count = t->first_new_seq;
		tview->record_size = I_MAX(map->hdr.record_size,
					   tview->view.map->hdr.record_size);
		tview->recs = i_malloc(tview->record_size *
				       tview->recs_count);
		array_append(&tview->all_recs, &tview->recs, 1);
	}
	i_assert(tview->recs_count == t->first_new_seq);
	i_assert(seq > 0 && seq <= tview->recs_count);

	trec = PTR_OFFSET(tview->recs, (seq-1) * tview->record_size);
	memcpy(trec, rec, map->hdr.record_size);
	trec->flags |= updates[idx].add_flags;
	trec->flags &= ~updates[idx].remove_flags;
	return trec;
}

static const struct mail_index_record *
tview_lookup_full(struct mail_index_view *view, uint32_t seq,
		  struct mail_index_map **map_r, bool *expunged_r)
{
	struct mail_index_view_transaction *tview =
                (struct mail_index_view_transaction *)view;
	const struct mail_index_record *rec;

	if (seq >= tview->t->first_new_seq) {
		/* FIXME: is this right to return index map..?
		   it's not there yet. */
		*map_r = view->index->map;
		*expunged_r = FALSE;
		return mail_index_transaction_lookup(tview->t, seq);
	}

	rec = tview->super->lookup_full(view, seq, map_r, expunged_r);
	rec = tview_apply_flag_updates(tview, *map_r, rec, seq);

	if (mail_index_transaction_is_expunged(tview->t, seq))
		*expunged_r = TRUE;
	return rec;
}

static void
tview_lookup_uid(struct mail_index_view *view, uint32_t seq, uint32_t *uid_r)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;

	if (seq >= tview->t->first_new_seq)
		*uid_r = mail_index_transaction_lookup(tview->t, seq)->uid;
	else
		tview->super->lookup_uid(view, seq, uid_r);
}

static void tview_lookup_seq_range(struct mail_index_view *view,
				   uint32_t first_uid, uint32_t last_uid,
				   uint32_t *first_seq_r, uint32_t *last_seq_r)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;
	const struct mail_index_record *rec;
	uint32_t seq;

	if (!tview->t->reset) {
		tview->super->lookup_seq_range(view, first_uid, last_uid,
					       first_seq_r, last_seq_r);
	} else {
		/* index is being reset. we never want to return old
		   sequences. */
		*first_seq_r = *last_seq_r = 0;
	}
	if (tview->t->last_new_seq == 0) {
		/* no new messages, the results are final. */
		return;
	}

	rec = mail_index_transaction_lookup(tview->t, tview->t->first_new_seq);
	if (rec->uid == 0) {
		/* new messages don't have UIDs */
		return;
	}
	if (last_uid < rec->uid) {
		/* all wanted messages were existing */
		return;
	}

	/* at least some of the wanted messages are newly created */
	if (*first_seq_r == 0) {
		seq = tview->t->first_new_seq;
		for (; seq <= tview->t->last_new_seq; seq++) {
			rec = mail_index_transaction_lookup(tview->t, seq);
			if (first_uid <= rec->uid)
				break;
		}
		if (seq > tview->t->last_new_seq) {
			/* no messages in range */
			return;
		}
		*first_seq_r = seq;
	}

	seq = tview->t->last_new_seq;
	for (; seq >= tview->t->first_new_seq; seq--) {
		rec = mail_index_transaction_lookup(tview->t, seq);
		if (rec->uid <= last_uid) {
			*last_seq_r = seq;
			break;
		}
	}
	i_assert(seq >= tview->t->first_new_seq);
}

static void tview_lookup_first(struct mail_index_view *view,
			       enum mail_flags flags, uint8_t flags_mask,
			       uint32_t *seq_r)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;
	const struct mail_index_record *rec;
	unsigned int append_count;
	uint32_t seq, message_count;

	if (!tview->t->reset) {
		tview->super->lookup_first(view, flags, flags_mask, seq_r);
		if (*seq_r != 0)
			return;
	} else {
		*seq_r = 0;
	}

	rec = array_get(&tview->t->appends, &append_count);
	seq = tview->t->first_new_seq;
	message_count = tview->t->last_new_seq;
	i_assert(append_count == message_count - seq + 1);

	for (; seq <= message_count; seq++, rec++) {
		if ((rec->flags & flags_mask) == (uint8_t)flags) {
			*seq_r = seq;
			break;
		}
	}
}

static void keyword_index_add(ARRAY_TYPE(keyword_indexes) *keywords,
			      unsigned int idx)
{
	const unsigned int *indexes;
	unsigned int i, count;

	indexes = array_get(keywords, &count);
	for (i = 0; i < count; i++) {
		if (indexes[i] == idx)
			return;
	}
	array_append(keywords, &idx, 1);
}

static void keyword_index_remove(ARRAY_TYPE(keyword_indexes) *keywords,
				 unsigned int idx)
{
	const unsigned int *indexes;
	unsigned int i, count;

	indexes = array_get(keywords, &count);
	for (i = 0; i < count; i++) {
		if (indexes[i] == idx) {
			array_delete(keywords, i, 1);
			break;
		}
	}
}

static void tview_lookup_keywords(struct mail_index_view *view, uint32_t seq,
				  ARRAY_TYPE(keyword_indexes) *keyword_idx)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;
	struct mail_index_transaction *t = tview->t;
	const struct mail_index_transaction_keyword_update *updates;
	unsigned int i, count;

	tview->super->lookup_keywords(view, seq, keyword_idx);

	if (seq < t->min_flagupdate_seq || seq > t->max_flagupdate_seq) {
		/* no keyword updates for this sequence */
		return;
	}

	/* apply any keyword updates in this transaction */
	if (array_is_created(&t->keyword_resets)) {
		if (seq_range_exists(&t->keyword_resets, seq))
			array_clear(keyword_idx);
	}

	if (array_is_created(&t->keyword_updates))
		updates = array_get(&t->keyword_updates, &count);
	else {
		updates = NULL;
		count = 0;
	}
	for (i = 0; i < count; i++) {
		if (array_is_created(&updates[i].add_seq) &&
		    seq_range_exists(&updates[i].add_seq, seq))
			keyword_index_add(keyword_idx, i);
		else if (array_is_created(&updates[i].remove_seq) &&
			 seq_range_exists(&updates[i].remove_seq, seq))
			keyword_index_remove(keyword_idx, i);
	}
}

static struct mail_index_map *
tview_get_lookup_map(struct mail_index_view_transaction *tview)
{
	if (tview->lookup_map == NULL) {
		tview->lookup_map =
			mail_index_map_clone(tview->view.index->map);
	}
	return tview->lookup_map;
}

static const void *
tview_return_updated_ext(struct mail_index_view_transaction *tview,
			 uint32_t seq, const void *data, uint32_t ext_id)
{
	const struct mail_index_ext *ext;
	const struct mail_index_registered_ext *rext;
	const struct mail_transaction_ext_intro *intro;
	unsigned int record_align, record_size;
	uint32_t ext_idx;
	size_t pos;

	/* data begins with a 32bit sequence, followed by the actual
	   extension data */
	data = CONST_PTR_OFFSET(data, sizeof(uint32_t));

	if (!mail_index_map_get_ext_idx(tview->lookup_map, ext_id, &ext_idx)) {
		/* we're adding the extension now. */
		rext = array_idx(&tview->view.index->extensions, ext_id);
		record_align = rext->record_align;
		record_size = rext->record_size;
	} else {
		ext = array_idx(&tview->lookup_map->extensions, ext_idx);
		record_align = ext->record_align;
		record_size = ext->record_size;
	}

	/* see if the extension has been resized within this transaction */
	if (array_is_created(&tview->t->ext_resizes) &&
	    ext_id < array_count(&tview->t->ext_resizes)) {
		intro = array_idx(&tview->t->ext_resizes, ext_id);
		if (intro[ext_id].name_size != 0) {
			record_align = intro->record_align;
			record_size = intro->record_size;
		}
	}

	if (record_align <= sizeof(uint32_t)) {
		/* data is 32bit aligned already */
		return data;
	} else {
		/* assume we want 64bit alignment - copy the data to
		   temporary buffer and return it */
		if (tview->lookup_return_data == NULL) {
			tview->lookup_return_data =
				buffer_create_dynamic(default_pool,
						      record_size + 64);
		} else if (seq != tview->lookup_prev_seq) {
			/* clear the buffer between lookups for different
			   messages */
			buffer_set_used_size(tview->lookup_return_data, 0);
		}
		tview->lookup_prev_seq = seq;
		pos = tview->lookup_return_data->used;
		buffer_append(tview->lookup_return_data, data, record_size);
		return CONST_PTR_OFFSET(tview->lookup_return_data->data, pos);
	}
}

static void
tview_lookup_ext_full(struct mail_index_view *view, uint32_t seq,
		      uint32_t ext_id, struct mail_index_map **map_r,
		      const void **data_r, bool *expunged_r)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;
	const ARRAY_TYPE(seq_array) *ext_buf;
	const void *data;
	unsigned int idx;

	i_assert(ext_id < array_count(&view->index->extensions));

	*expunged_r = FALSE;

	if (array_is_created(&tview->t->ext_rec_updates) &&
	    ext_id < array_count(&tview->t->ext_rec_updates)) {
		/* there are some ext updates in transaction.
		   see if there's any for this sequence. */
		ext_buf = array_idx(&tview->t->ext_rec_updates, ext_id);
		if (array_is_created(ext_buf) &&
		    mail_index_seq_array_lookup(ext_buf, seq, &idx)) {
			data = array_idx(ext_buf, idx);
			*map_r = tview_get_lookup_map(tview);
			*data_r = tview_return_updated_ext(tview, seq, data,
							   ext_id);
			return;
		}
	}

	/* not updated, return the existing value */
	if (seq < tview->t->first_new_seq) {
		tview->super->lookup_ext_full(view, seq, ext_id,
					      map_r, data_r, expunged_r);
	} else {
		*map_r = view->index->map;
		*data_r = NULL;
	}
}

static void tview_get_header_ext(struct mail_index_view *view,
				 struct mail_index_map *map, uint32_t ext_id,
				 const void **data_r, size_t *data_size_r)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;

	/* FIXME: check updates */
	tview->super->get_header_ext(view, map, ext_id, data_r, data_size_r);
}

static bool tview_ext_get_reset_id(struct mail_index_view *view,
				   struct mail_index_map *map,
				   uint32_t ext_id, uint32_t *reset_id_r)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;
	const uint32_t *reset_id_p;

	if (array_is_created(&tview->t->ext_reset_ids) &&
	    ext_id < array_count(&tview->t->ext_reset_ids) &&
	    map == tview->lookup_map) {
		reset_id_p = array_idx(&tview->t->ext_reset_ids, ext_id);
		*reset_id_r = *reset_id_p;
		return TRUE;
	}

	return tview->super->ext_get_reset_id(view, map, ext_id, reset_id_r);
}

static struct mail_index_view_vfuncs trans_view_vfuncs = {
	tview_close,
        tview_get_message_count,
	tview_get_header,
	tview_lookup_full,
	tview_lookup_uid,
	tview_lookup_seq_range,
	tview_lookup_first,
	tview_lookup_keywords,
	tview_lookup_ext_full,
	tview_get_header_ext,
	tview_ext_get_reset_id
};

struct mail_index_view *
mail_index_transaction_open_updated_view(struct mail_index_transaction *t)
{
	struct mail_index_view_transaction *tview;

	if (t->view->syncing) {
		/* transaction view is being synced. while it's done, it's not
		   possible to add new messages, but the view itself might
		   change. so we can't make a copy of the view. */
		mail_index_view_ref(t->view);
		return t->view;
	}

	tview = i_new(struct mail_index_view_transaction, 1);
	mail_index_view_clone(&tview->view, t->view);
	tview->view.v = trans_view_vfuncs;
	tview->super = &t->view->v;
	tview->t = t;

	mail_index_transaction_ref(t);
	return &tview->view;
}
