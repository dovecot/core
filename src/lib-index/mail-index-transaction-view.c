/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
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

	mail_index_transaction_unref(tview->t);
	return tview->parent->close(view);
}

static uint32_t _tview_get_message_count(struct mail_index_view *view)
{
	struct mail_index_view_transaction *tview =
                (struct mail_index_view_transaction *)view;

	return view->messages_count +
		(tview->t->last_new_seq == 0 ? 0 :
		 tview->t->last_new_seq - tview->t->first_new_seq);
}

static int _tview_get_header(struct mail_index_view *view,
			     const struct mail_index_header **hdr_r)
{
	struct mail_index_view_transaction *tview =
                (struct mail_index_view_transaction *)view;

	if (tview->parent->get_header(view, hdr_r) < 0)
		return -1;

	if ((*hdr_r)->messages_count != view->messages_count) {
		/* messages_count differs, use a modified copy.
		   FIXME: same problems as with _view_get_header().. */
		view->tmp_hdr_copy = **hdr_r;
		view->tmp_hdr_copy.messages_count = view->messages_count;
		*hdr_r = &view->tmp_hdr_copy;
	}
	return 0;
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
	uint32_t seq, message_count;

	if (tview->parent->lookup_first(view, flags, flags_mask, seq_r) < 0)
		return -1;

	if (*seq_r != 0)
		return 0;

	rec = buffer_get_data(tview->t->appends, NULL);
	seq = tview->t->first_new_seq;
	message_count = tview->t->last_new_seq;
	for (; seq <= message_count; seq++, rec++) {
		if ((rec->flags & flags_mask) == (uint8_t)flags) {
			*seq_r = seq;
			break;
		}
	}

	return 0;
}

static int _tview_lookup_extra(struct mail_index_view *view, uint32_t seq,
			       uint32_t data_id, const void **data_r)
{
	struct mail_index_view_transaction *tview =
		(struct mail_index_view_transaction *)view;
        const struct mail_index_extra_record_info *einfo;
	buffer_t *const *extra_bufs;
	size_t size, pos;

	if (seq < tview->t->first_new_seq)
		return tview->parent->lookup_extra(view, seq, data_id, data_r);

	i_assert(seq <= tview->t->last_new_seq);
	i_assert(data_id < view->index->extra_infos->used / sizeof(*einfo));

	einfo = view->index->extra_infos->data;
	einfo += data_id;

	extra_bufs = buffer_get_data(tview->t->extra_rec_updates, &size);
	size /= sizeof(*extra_bufs);

	if (size <= data_id || extra_bufs[data_id] == NULL ||
	    !mail_index_seq_buffer_lookup(extra_bufs[data_id], seq,
					  einfo->record_size, &pos)) {
		*data_r = NULL;
		return 1;
	}

	*data_r = CONST_PTR_OFFSET(extra_bufs[data_id]->data, pos);
	return 1;
}

static struct mail_index_view_methods view_methods = {
	_tview_close,
        _tview_get_message_count,
	_tview_get_header,
	_tview_lookup_full,
	_tview_lookup_uid,
	_tview_lookup_uid_range,
	_tview_lookup_first,
	_tview_lookup_extra
};

struct mail_index_view *
mail_index_transaction_open_updated_view(struct mail_index_transaction *t)
{
	struct mail_index_view_transaction *tview;

	tview = i_new(struct mail_index_view_transaction, 1);
	mail_index_view_clone(&tview->view, t->view);
	tview->view.methods = view_methods;
	tview->parent = &t->view->methods;
	tview->t = t;

	mail_index_transaction_ref(t);
	return &tview->view;
}
