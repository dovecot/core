/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "mail-index-private.h"
#include "mail-transaction-log-private.h"
#include "mail-transaction-util.h"

struct mail_transaction_log_view {
	struct mail_transaction_log *log;
        struct mail_transaction_log_view *next;

	uint32_t min_file_seq, max_file_seq;
	uoff_t min_file_offset, max_file_offset;

	enum mail_transaction_type type_mask;
	struct mail_transaction_header tmp_hdr;

        struct mail_transaction_log_file *cur, *head, *tail;
	uoff_t cur_offset;

	uint32_t prev_file_seq;
	uoff_t prev_file_offset;

	unsigned int broken:1;
};

struct mail_transaction_log_view *
mail_transaction_log_view_open(struct mail_transaction_log *log)
{
	struct mail_transaction_log_view *view;

	view = i_new(struct mail_transaction_log_view, 1);
	view->log = log;
	view->broken = TRUE;

	view->head = view->tail = view->log->head;
	view->head->refcount++;

	view->next = log->views;
	log->views = view;
	return view;
}

void mail_transaction_log_view_close(struct mail_transaction_log_view *view)
{
	struct mail_transaction_log_view **p;
	struct mail_transaction_log_file *file;

	for (p = &view->log->views; *p != NULL; p = &(*p)->next) {
		if (*p == view) {
			*p = view->next;
			break;
		}
	}

	for (file = view->tail; file != view->head; file = file->next)
		file->refcount--;
	view->head->refcount--;

	mail_transaction_logs_clean(view->log);
	i_free(view);
}

void mail_transaction_log_views_close(struct mail_transaction_log *log)
{
	struct mail_transaction_log_view *view;

	for (view = log->views; view != NULL; view = view->next)
		view->log = NULL;
}

int
mail_transaction_log_view_set(struct mail_transaction_log_view *view,
			      uint32_t min_file_seq, uoff_t min_file_offset,
			      uint32_t max_file_seq, uoff_t max_file_offset,
			      enum mail_transaction_type type_mask)
{
	/* FIXME: error handling for "not found" case is bad.. should the
	   caller after all check it and handle as it sees best..? */
	struct mail_transaction_log_file *file, *first;
	uint32_t seq;
	uoff_t end_offset;
	int ret;

	i_assert(min_file_seq <= max_file_seq);

	if (view->log == NULL)
		return -1;

	if (min_file_seq == view->log->tail->hdr.prev_file_seq &&
	    min_file_offset == view->log->tail->hdr.prev_file_offset) {
		/* we can skip this */
		min_file_seq = view->log->tail->hdr.file_seq;
		min_file_offset = sizeof(struct mail_transaction_log_header);

		if (min_file_seq > max_file_seq) {
			/* empty view */
			max_file_seq = min_file_seq;
			max_file_offset = min_file_offset;
		}
	}

	ret = mail_transaction_log_file_find(view->log, min_file_seq, &file);
	if (ret <= 0) {
		if (ret == 0) {
			mail_index_set_error(view->log->index,
				"Lost transaction log file %s seq %u",
				view->log->tail->filepath, min_file_seq);
		}
		return -1;
	}

	/* check these later than others as index file may have corrupted
	   log_file_offset. we should have recreated the log file and
	   skipped min_file_seq file above.. max_file_offset can be broken
	   only if min_file_seq = max_file_seq. */
	i_assert(min_file_offset >= sizeof(struct mail_transaction_log_header));
	i_assert(max_file_offset >= sizeof(struct mail_transaction_log_header));

	i_assert(min_file_seq != max_file_seq ||
		 min_file_offset <= max_file_offset);

	end_offset = min_file_seq == max_file_seq ?
		max_file_offset : (uoff_t)-1;
	ret = mail_transaction_log_file_map(file, min_file_offset, end_offset);
	if (ret <= 0) {
		if (ret == 0) {
			mail_index_set_error(view->log->index,
				"Lost transaction log file %s seq %u",
				file->filepath, file->hdr.file_seq);
		}
		return -1;
	}
	first = file;

	for (seq = min_file_seq+1; seq <= max_file_seq; seq++) {
		file = file->next;
		if (file == NULL || file->hdr.file_seq != seq)  {
			mail_index_set_error(view->log->index,
				"Lost transaction log file %s seq %u",
				view->log->tail->filepath, seq);
			return -1;
		}

		end_offset = file->hdr.file_seq == max_file_seq ?
			max_file_offset : (uoff_t)-1;
		ret = mail_transaction_log_file_map(file,
			sizeof(struct mail_transaction_log_header),
			end_offset);
		if (ret == 0) {
			mail_index_set_error(view->log->index,
				"Lost transaction log file %s seq %u",
				file->filepath, file->hdr.file_seq);
		}
		if (ret <= 0)
			return -1;
	}

	i_assert(max_file_offset <= file->hdr.used_size);

	/* we have all of them. update refcounts. */
	if (view->tail->hdr.file_seq < first->hdr.file_seq) {
		/* unref old files */
		for (file = view->tail; file != first; file = file->next)
			file->refcount--;
		view->tail = first;
	} else {
		/* going backwards, reference them */
		for (file = first; file != view->tail; file = file->next)
			file->refcount++;
	}

	/* reference all new files */
	for (file = view->head->next; file != NULL; file = file->next)
		file->refcount++;
	view->head = view->log->head;

	view->prev_file_seq = 0;
	view->prev_file_offset = 0;

	view->cur = first;
	view->cur_offset = min_file_offset;

	view->min_file_seq = min_file_seq;
	view->min_file_offset = min_file_offset;
	view->max_file_seq = max_file_seq;
	view->max_file_offset = max_file_offset;
	view->type_mask = type_mask;
	view->broken = FALSE;
	return 0;
}

void
mail_transaction_log_view_get_prev_pos(struct mail_transaction_log_view *view,
				       uint32_t *file_seq_r,
				       uoff_t *file_offset_r)
{
	*file_seq_r = view->prev_file_seq;
	*file_offset_r = view->prev_file_offset;
}

void
mail_transaction_log_view_set_corrupted(struct mail_transaction_log_view *view,
					const char *fmt, ...)
{
	va_list va;

	view->broken = TRUE;

	va_start(va, fmt);
	t_push();
	mail_transaction_log_file_set_corrupted(view->log->head, "%s",
						t_strdup_vprintf(fmt, va));
	t_pop();
	va_end(va);
}

int
mail_transaction_log_view_is_corrupted(struct mail_transaction_log_view *view)
{
	return view->broken;
}

static int log_view_get_next(struct mail_transaction_log_view *view,
			     const struct mail_transaction_header **hdr_r,
			     const void **data_r)
{
	const struct mail_transaction_header *hdr;
	struct mail_transaction_log_file *file;
	const struct mail_transaction_type_map *type_rec;
	const void *data;
	unsigned int record_size;
	size_t file_size;

	for (;;) {
		file = view->cur;

		view->prev_file_seq = file->hdr.file_seq;
		view->prev_file_offset = view->cur_offset;

		if (view->cur_offset != file->hdr.used_size)
			break;

		view->cur = file->next;
		view->cur_offset = sizeof(struct mail_transaction_log_header);

		if (view->cur == NULL)
			return 0;
	}

	data = buffer_get_data(file->buffer, &file_size);
	file_size += file->buffer_offset;

	if (view->cur_offset + sizeof(*hdr) > file_size) {
		mail_transaction_log_file_set_corrupted(file,
			"offset points outside file "
			"(%"PRIuUOFF_T" + %"PRIuSIZE_T" > %"PRIuSIZE_T")",
			view->cur_offset, sizeof(*hdr), file_size);
		return -1;
	}

	hdr = CONST_PTR_OFFSET(data, view->cur_offset - file->buffer_offset);
	view->cur_offset += sizeof(*hdr);

	if (file_size - view->cur_offset < hdr->size) {
		mail_transaction_log_file_set_corrupted(file,
			"record size too large (type=0x%x, offset=%"PRIuUOFF_T
			", size=%u, end=%"PRIuSIZE_T")",
			hdr->type & MAIL_TRANSACTION_TYPE_MASK,
			view->cur_offset, hdr->size, file_size);
                view->cur_offset = file_size;
		return -1;
	}

	type_rec = mail_transaction_type_lookup(hdr->type);
	if (type_rec != NULL)
		record_size = type_rec->record_size;
	else {
		mail_transaction_log_file_set_corrupted(file,
			"unknown record type 0x%x",
			hdr->type & MAIL_TRANSACTION_TYPE_MASK);
                view->cur_offset = file->hdr.used_size;
		return -1;
	}

	if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0) {
		if ((hdr->type & MAIL_TRANSACTION_TYPE_MASK) !=
		    (MAIL_TRANSACTION_EXPUNGE|MAIL_TRANSACTION_EXPUNGE_PROT)) {
			mail_transaction_log_file_set_corrupted(file,
				"found expunge without protection mask");
			return -1;
		}
	} else if ((hdr->type & MAIL_TRANSACTION_TYPE_MASK) != type_rec->type) {
		mail_transaction_log_file_set_corrupted(file,
			"extra bits in header type: 0x%x",
			hdr->type & MAIL_TRANSACTION_TYPE_MASK);
		return -1;
	}

	if (hdr->size % record_size != 0) {
		mail_transaction_log_file_set_corrupted(file,
			"record size wrong (type 0x%x, %u %% %u != 0)",
			hdr->type & MAIL_TRANSACTION_TYPE_MASK,
			hdr->size, record_size);
                view->cur_offset = file->hdr.used_size;
		return -1;
	}

	*hdr_r = hdr;
	*data_r = CONST_PTR_OFFSET(data, view->cur_offset -
				   file->buffer_offset);
	view->cur_offset += hdr->size;
	return 1;
}

int mail_transaction_log_view_next(struct mail_transaction_log_view *view,
				   const struct mail_transaction_header **hdr_r,
				   const void **data_r, int *skipped_r)
{
	const struct mail_transaction_header *hdr;
	const void *data;
	int ret = 0;

	if (skipped_r != NULL)
		*skipped_r = FALSE;
	if (view->broken)
		return -1;

	while ((ret = log_view_get_next(view, &hdr, &data)) > 0) {
		if ((view->type_mask & hdr->type) != 0)
			break;

		/* we don't want this record */
		if (skipped_r != NULL)
			*skipped_r = TRUE;

		/* FIXME: hide flag/cache updates for appends if
		   append isn't in mask */
	}

	if (ret <= 0)
		return ret;

	*hdr_r = hdr;
	*data_r = data;

	if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0) {
		/* hide expunge protection */
		if (*hdr_r != &view->tmp_hdr) {
			view->tmp_hdr = *hdr;
			*hdr_r = &view->tmp_hdr;
		}
		view->tmp_hdr.type &= ~MAIL_TRANSACTION_EXPUNGE_PROT;
	}

	return 1;
}
