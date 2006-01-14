/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "mail-index-private.h"
#include "mail-index-view-private.h"
#include "mail-index-transaction-private.h"

struct mail_index_view_transaction {
	struct mail_index_view view;
	struct mail_index_view_methods *parent;
	struct mail_index_transaction *t;
};

static void _tview_close(struct mail_index_view *view)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;

	mail_index_transaction_unref(&tview->t);
	tview->parent->close(view);
}

static uint32_t _tview_get_message_count(struct mail_index_view *view)
{
	struct mail_index_view_transaction *tview =
                (struct mail_index_view_transaction *)view;

	return view->hdr.messages_count +
		(tview->t->last_new_seq == 0 ? 0 :
		 tview->t->last_new_seq - tview->t->first_new_seq);
}

static const struct mail_index_header *
_tview_get_header(struct mail_index_view *view)
{
	struct mail_index_view_transaction *tview =
                (struct mail_index_view_transaction *)view;

	/* FIXME: header counters may not be correct */
	return tview->parent->get_header(view);
}

static int _tview_lookup_full(struct mail_index_view *view, uint32_t seq,
			      struct mail_index_map **map_r,
			      const struct mail_index_record **rec_r)
{
	struct mail_index_view_transaction *tview =
                (struct mail_index_view_transaction *)view;

	if (seq >= tview->t->first_new_seq) {
		/* FIXME: is this right to return index map..?
		   it's not there yet. */
		*map_r = view->index->map;
		*rec_r = mail_index_transaction_lookup(tview->t, seq);
		return 1;
	} else {
		return tview->parent->lookup_full(view, seq, map_r, rec_r);
	}
}

static int _tview_lookup_uid(struct mail_index_view *view, uint32_t seq,
			     uint32_t *uid_r)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;

	if (seq >= tview->t->first_new_seq) {
		*uid_r = mail_index_transaction_lookup(tview->t, seq)->uid;
		return 0;
	} else {
		return tview->parent->lookup_uid(view, seq, uid_r);
	}
}

static int _tview_lookup_uid_range(struct mail_index_view *view,
				   uint32_t first_uid, uint32_t last_uid,
				   uint32_t *first_seq_r, uint32_t *last_seq_r)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;

	if (tview->parent->lookup_uid_range(view, first_uid, last_uid,
					    first_seq_r, last_seq_r) < 0)
		return -1;

	/* FIXME: we don't need this function yet.. new UIDs might be 0 as
	   well.. */

	if (*first_seq_r == 0) {
		/* nothing found, either doesn't exist or it's completely
		   newly appended. */
	} else if (*last_seq_r + 1 == tview->t->first_new_seq) {
		/* last_seq_r may be growed from transactions */
	}

	return 0;
}

static int _tview_lookup_first(struct mail_index_view *view,
			       enum mail_flags flags, uint8_t flags_mask,
			       uint32_t *seq_r)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;
	const struct mail_index_record *rec;
	unsigned int append_count;
	uint32_t seq, message_count;

	if (tview->parent->lookup_first(view, flags, flags_mask, seq_r) < 0)
		return -1;

	if (*seq_r != 0)
		return 0;

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

	return 0;
}

static int
_tview_lookup_ext_full(struct mail_index_view *view, uint32_t seq,
		       uint32_t ext_id, struct mail_index_map **map_r,
		       const void **data_r)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;
	const array_t *ext_buf;
	ARRAY_SET_TYPE(ext_buf, void *);
	const void *data;
	unsigned int idx;

	i_assert(ext_id < array_count(&view->index->extensions));

	*map_r = view->index->map;

	if (array_is_created(&tview->t->ext_rec_updates) &&
	    ext_id < array_count(&tview->t->ext_rec_updates)) {
		/* there are some ext updates in transaction.
		   see if there's any for this sequence. */
		ext_buf = array_idx(&tview->t->ext_rec_updates, ext_id);
		if (array_is_created(ext_buf) &&
		    mail_index_seq_array_lookup(ext_buf, seq, &idx)) {
			data = array_idx(ext_buf, idx);
			*data_r = CONST_PTR_OFFSET(data, sizeof(uint32_t));
			return 1;
		}
	}

	/* not updated, return the existing value */
	if (seq < tview->t->first_new_seq) {
		return tview->parent->lookup_ext_full(view, seq, ext_id,
						      map_r, data_r);
	}

	*data_r = NULL;
	return 1;
}

static int _tview_get_header_ext(struct mail_index_view *view,
				 struct mail_index_map *map, uint32_t ext_id,
				 const void **data_r, size_t *data_size_r)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;

	/* FIXME: check updates */
	return tview->parent->get_header_ext(view, map, ext_id,
					     data_r, data_size_r);
}

static struct mail_index_view_methods view_methods = {
	_tview_close,
        _tview_get_message_count,
	_tview_get_header,
	_tview_lookup_full,
	_tview_lookup_uid,
	_tview_lookup_uid_range,
	_tview_lookup_first,
	_tview_lookup_ext_full,
	_tview_get_header_ext
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
	tview->view.methods = view_methods;
	tview->parent = &t->view->methods;
	tview->t = t;

	mail_index_transaction_ref(t);
	return &tview->view;
}
