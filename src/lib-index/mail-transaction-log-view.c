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
	buffer_t *expunges_buf, *data_buf;
        struct mail_transaction_expunge_traverse_ctx *exp_ctx;
	struct mail_transaction_header tmp_hdr;

        struct mail_transaction_log_file *file;
	uoff_t file_offset;

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
	view->expunges_buf =
		buffer_create_dynamic(default_pool, 512, (size_t)-1);

	view->next = log->views;
	log->views = view;
	return view;
}

static void
mail_transaction_log_view_close_files(struct mail_transaction_log_view *view)
{
	struct mail_transaction_log_file *file;

	for (file = view->log->tail; file != NULL; file = file->next) {
		if (file->hdr.file_seq > view->max_file_seq)
			break;
		if (file->hdr.file_seq >= view->min_file_seq)
			file->refcount--;
	}

	mail_transaction_logs_clean(view->log);
}

void mail_transaction_log_view_close(struct mail_transaction_log_view *view)
{
	mail_transaction_log_view_close_files(view);
	if (view->data_buf != NULL)
		buffer_free(view->data_buf);
	buffer_free(view->expunges_buf);
	i_free(view);
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
	i_assert(min_file_offset >= sizeof(struct mail_transaction_log_header));
	i_assert(max_file_offset >= sizeof(struct mail_transaction_log_header));

	view->broken = TRUE;

        mail_transaction_log_view_close_files(view);

	ret = mail_transaction_log_file_find(view->log, min_file_seq, &file);
	if (ret <= 0)
		return -1;
	end_offset = min_file_seq == max_file_seq ?
		max_file_offset : (uoff_t)-1;
	ret = mail_transaction_log_file_map(file, min_file_offset, end_offset);
	if (ret <= 0)
		return -1;
	first = file;

	for (seq = min_file_seq+1; seq <= max_file_seq; seq++) {
		file = file->next;
		if (file == NULL || file->hdr.file_seq != seq) 
			return -1;

		end_offset = file->hdr.file_seq == max_file_seq ?
			max_file_offset : (uoff_t)-1;
		ret = mail_transaction_log_file_map(file,
			sizeof(struct mail_transaction_log_header),
			end_offset);
		if (ret <= 0)
			return -1;
	}

	i_assert(max_file_offset <= file->hdr.used_size);

	/* we have it all, refcount the files */
	for (file = first, seq = min_file_seq; seq <= max_file_seq; seq++) {
		file->refcount++;
		file = file->next;
	}

	buffer_set_used_size(view->expunges_buf, 0);

	view->prev_file_seq = 0;
	view->prev_file_offset = 0;

	view->file = first;
	view->file_offset = min_file_offset;

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
	struct mail_transaction_log_file *file = view->file;
	const struct mail_transaction_type_map *type_rec;
	const void *data;
	unsigned int record_size;
	size_t file_size;

	view->prev_file_seq = file->hdr.file_seq;
	view->prev_file_offset = view->file_offset;

	if (view->file_offset == file->hdr.used_size) {
		view->file = file->next;
		view->file_offset = sizeof(struct mail_transaction_log_header);
		return 0;
	}

	data = buffer_get_data(file->buffer, &file_size);
	file_size += file->buffer_offset;

	if (view->file_offset + sizeof(*hdr) > file_size) {
		mail_transaction_log_file_set_corrupted(file,
			"offset points outside file "
			"(%"PRIuUOFF_T" + %"PRIuSIZE_T" > %"PRIuSIZE_T")",
			view->file_offset, sizeof(*hdr), file_size);
		return -1;
	}

	hdr = CONST_PTR_OFFSET(data, view->file_offset - file->buffer_offset);
	view->file_offset += sizeof(*hdr);

	if (file_size - view->file_offset < hdr->size) {
		mail_transaction_log_file_set_corrupted(file,
			"record size too large (type=0x%x, offset=%"PRIuUOFF_T
			", size=%u, end=%"PRIuSIZE_T")",
			hdr->type & MAIL_TRANSACTION_TYPE_MASK,
			view->file_offset, hdr->size, file_size);
                view->file_offset = file_size;
		return -1;
	}

	type_rec = mail_transaction_type_lookup(hdr->type);
	if (type_rec != NULL)
		record_size = type_rec->record_size;
	else {
		mail_transaction_log_file_set_corrupted(file,
			"unknown record type 0x%x",
			hdr->type & MAIL_TRANSACTION_TYPE_MASK);
                view->file_offset = file->hdr.used_size;
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
                view->file_offset = file->hdr.used_size;
		return -1;
	}

	*hdr_r = hdr;
	*data_r = CONST_PTR_OFFSET(data, view->file_offset -
				   file->buffer_offset);
	view->file_offset += hdr->size;
	return 1;
}

static int seqfix_expunge(const struct mail_transaction_expunge *e,
			  void *context)
{
	struct mail_transaction_log_view *view = context;
	struct mail_transaction_expunge new_e;
	uint32_t expunges_before;

	expunges_before = mail_transaction_expunge_traverse_to(view->exp_ctx,
							       e->seq2);
	if (expunges_before == 0) {
		buffer_append(view->data_buf, e, sizeof(*e));
		return 1;
	}

	/* FIXME: if there's expunges in the middle of the
	   range, we'd have to split this to multiple records */

	new_e = *e;
	new_e.seq2 += expunges_before;
	new_e.seq1 += mail_transaction_expunge_traverse_to(view->exp_ctx,
							   new_e.seq1);
	buffer_append(view->data_buf, &new_e, sizeof(new_e));
	return 1;
}

static int seqfix_flag_update(const struct mail_transaction_flag_update *u,
			      void *context)
{
	struct mail_transaction_log_view *view = context;
	struct mail_transaction_flag_update new_u;
	uint32_t expunges_before;

	expunges_before = mail_transaction_expunge_traverse_to(view->exp_ctx,
							       u->seq2);
	if (expunges_before == 0) {
		buffer_append(view->data_buf, u, sizeof(*u));
		return 1;
	}

	/* FIXME: if there's expunges in the middle of the
	   range, we'd have to split this to multiple records */

	new_u = *u;
	new_u.seq2 += expunges_before;
	new_u.seq1 += mail_transaction_expunge_traverse_to(view->exp_ctx,
							   new_u.seq1);
	buffer_append(view->data_buf, &new_u, sizeof(new_u));
	return 1;
}

static int seqfix_cache_update(const struct mail_transaction_cache_update *u,
			       void *context)
{
	struct mail_transaction_log_view *view = context;
	struct mail_transaction_cache_update new_u;
	uint32_t expunges_before;

	expunges_before = mail_transaction_expunge_traverse_to(view->exp_ctx,
							       u->seq);
	if (expunges_before != 0) {
		new_u = *u;
		new_u.seq += expunges_before;
		u = &new_u;
	}

	buffer_append(view->data_buf, u, sizeof(*u));
	return 1;
}

int mail_transaction_log_view_next(struct mail_transaction_log_view *view,
				   const struct mail_transaction_header **hdr_r,
				   const void **data_r, int *skipped_r)
{
	struct mail_transaction_map_functions seqfix_funcs = {
		seqfix_expunge, NULL, seqfix_flag_update, seqfix_cache_update
	};
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

		if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0) {
			mail_transaction_log_sort_expunges(view->expunges_buf,
							   data, hdr->size);
		}

		/* FIXME: hide flag/cache updates for appends if
		   append isn't in mask */
	}

	if (ret <= 0)
		return ret;

	*hdr_r = hdr;
	*data_r = data;

	if (buffer_get_used_size(view->expunges_buf) > 0) {
		/* we have to fix sequences in the data */
		if (view->data_buf == NULL) {
			view->data_buf =
				buffer_create_dynamic(default_pool,
						      hdr->size, (size_t)-1);
		} else {
			buffer_set_used_size(view->data_buf, 0);
		}

		view->exp_ctx = mail_transaction_expunge_traverse_init(
					view->expunges_buf);
		ret = mail_transaction_map(hdr, data, &seqfix_funcs, view);
		mail_transaction_expunge_traverse_deinit(view->exp_ctx);

		if (ret > 0) {
			/* modified */
			i_assert(buffer_get_used_size(view->data_buf) ==
				 hdr->size);
			*data_r = buffer_get_data(view->data_buf, NULL);
		} else {
			i_assert(buffer_get_used_size(view->data_buf) == 0);
		}
	}

	if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0) {
		mail_transaction_log_sort_expunges(view->expunges_buf,
						   data, hdr->size);

		/* hide expunge protection */
		view->tmp_hdr = *hdr;
		view->tmp_hdr.type &= ~MAIL_TRANSACTION_EXPUNGE_PROT;
		*hdr_r = &view->tmp_hdr;
	}

	return 1;
}

buffer_t *
mail_transaction_log_view_get_expunges(struct mail_transaction_log_view *view)
{
	return view->expunges_buf;
}
