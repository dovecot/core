/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "mail-index-private.h"
#include "mail-transaction-log-private.h"

struct mail_transaction_log_view {
	struct mail_transaction_log *log;
        struct mail_transaction_log_view *next;

	uint32_t min_file_seq, max_file_seq;
	uoff_t min_file_offset, max_file_offset;

	struct mail_transaction_header tmp_hdr;

	/* a list of log files we've referenced. we have to keep this list
	   explicitly because more files may be added into the linked list
	   at any time. */
	ARRAY_DEFINE(file_refs, struct mail_transaction_log_file *);
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
	i_array_init(&view->file_refs, 8);
	array_append(&view->file_refs, &view->head, 1);

	view->next = log->views;
	log->views = view;
	return view;
}

static void
mail_transaction_log_view_unref_all(struct mail_transaction_log_view *view)
{
	struct mail_transaction_log_file *const *files;
	unsigned int i, count;

	files = array_get(&view->file_refs, &count);
	for (i = 0; i < count; i++)
		files[i]->refcount--;

	array_clear(&view->file_refs);
}

void mail_transaction_log_view_close(struct mail_transaction_log_view **_view)
{
        struct mail_transaction_log_view *view = *_view;
	struct mail_transaction_log_view **p;

	*_view = NULL;

	for (p = &view->log->views; *p != NULL; p = &(*p)->next) {
		if (*p == view) {
			*p = view->next;
			break;
		}
	}

	mail_transaction_log_view_unref_all(view);
	mail_transaction_logs_clean(view->log);

	array_free(&view->file_refs);
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
			      uint32_t max_file_seq, uoff_t max_file_offset)
{
	struct mail_transaction_log_file *file, *first;
	uint32_t seq;
	uoff_t end_offset;
	int ret;

	i_assert(view->log != NULL);
	i_assert(min_file_seq <= max_file_seq);

	if (view->log == NULL) {
		/* transaction log is closed already. this log view shouldn't
		   be used anymore. */
		return -1;
	}

	if (min_file_seq == 0) {
		/* index file doesn't exist yet. this transaction log should
		   start from the beginning */
		if (view->log->files->hdr.prev_file_seq != 0) {
			/* but it doesn't */
			return 0;
		}

		min_file_seq = view->log->files->hdr.file_seq;
		min_file_offset = 0;

		if (max_file_seq == 0) {
			max_file_seq = min_file_seq;
			max_file_offset = min_file_offset;
		}
	} 

	if (min_file_seq == view->log->files->hdr.prev_file_seq &&
	    min_file_offset == view->log->files->hdr.prev_file_offset) {
		/* we can skip this */
		min_file_seq = view->log->files->hdr.file_seq;
		min_file_offset = 0;

		if (min_file_seq > max_file_seq) {
			/* empty view */
			max_file_seq = min_file_seq;
			max_file_offset = min_file_offset;
		}
	}

	/* find the oldest log file first. */
	ret = mail_transaction_log_find_file(view->log, min_file_seq, &file);
	if (ret <= 0)
		return ret;

	if (min_file_offset == 0) {
		/* this could happen if internal transactions haven't yet been
		   committed but external are. just assume we're at the
		   beginning. */
		min_file_offset = file->hdr.hdr_size;
		if (max_file_offset == 0 && min_file_seq == max_file_seq)
			max_file_offset = min_file_offset;
	}
	i_assert(min_file_offset >= file->hdr.hdr_size);

	if (min_file_seq == max_file_seq && min_file_offset > max_file_offset) {
		/* log file offset is probably corrupted in the index file. */
		mail_transaction_log_view_set_corrupted(view,
			"file_seq=%u, min_file_offset (%"PRIuUOFF_T
			") > max_file_offset (%"PRIuUOFF_T")",
			min_file_seq, min_file_offset, max_file_offset);
		return -1;
	}

	end_offset = min_file_seq == max_file_seq ?
		max_file_offset : (uoff_t)-1;
	ret = mail_transaction_log_file_map(file, min_file_offset, end_offset);
	if (ret <= 0)
		return ret;
	first = file;

	for (seq = min_file_seq+1; seq <= max_file_seq; seq++) {
		file = file->next;
		if (file == NULL || file->hdr.file_seq != seq) {
			/* see if we could find the missing file */
			ret = mail_transaction_log_find_file(view->log,
							     seq, &file);
			if (ret <= 0) {
				if (ret < 0)
					return -1;

				/* not found / corrupted */
				file = NULL;
			}
		}

		if (file == NULL || file->hdr.file_seq != seq) {
			if (file == NULL && max_file_seq == (uint32_t)-1) {
				/* we just wanted to sync everything */
				i_assert(max_file_offset == (uoff_t)-1);
				max_file_seq = seq-1;
				break;
			}

			/* missing files in the middle */
			return 0;
		}

		end_offset = file->hdr.file_seq == max_file_seq ?
			max_file_offset : (uoff_t)-1;
		ret = mail_transaction_log_file_map(file, file->hdr.hdr_size,
						    end_offset);
		if (ret <= 0)
			return ret;
	}

	i_assert(max_file_offset == (uoff_t)-1 ||
		 max_file_offset <= file->sync_offset);

	/* we have all of them. update refcounts. */
	mail_transaction_log_view_unref_all(view);

	view->tail = first;
	view->head = view->log->head;

	/* reference all used files */
	for (file = view->tail; file != NULL; file = file->next) {
		array_append(&view->file_refs, &file, 1);
		file->refcount++;
	}

	view->prev_file_seq = 0;
	view->prev_file_offset = 0;

	view->cur = first;
	view->cur_offset = min_file_offset;

	view->min_file_seq = min_file_seq;
	view->min_file_offset = min_file_offset;
	view->max_file_seq = max_file_seq;
	view->max_file_offset = max_file_offset;
	view->broken = FALSE;

	i_assert(view->cur_offset <= view->cur->sync_offset);
	i_assert(view->cur->hdr.file_seq == min_file_seq);
	return 1;
}

void
mail_transaction_log_view_get_prev_pos(struct mail_transaction_log_view *view,
				       uint32_t *file_seq_r,
				       uoff_t *file_offset_r)
{
	*file_seq_r = view->prev_file_seq;
	*file_offset_r = view->prev_file_offset;
}

static bool
mail_transaction_log_view_get_last(struct mail_transaction_log_view *view,
				   struct mail_transaction_log_file **last_r,
				   uoff_t *last_offset_r)
{
	struct mail_transaction_log_file *cur = view->cur;
	uoff_t cur_offset = view->cur_offset;
	bool last = FALSE;

	if (cur == NULL) {
		*last_r = NULL;
		return TRUE;
	}

	for (;;) {
		if (cur->hdr.file_seq == view->max_file_seq) {
			/* last file */
			if (cur_offset == view->max_file_offset ||
			    cur_offset == cur->sync_offset) {
				/* we're all finished */
				last = TRUE;
			}
		} else if (cur_offset == cur->sync_offset) {
			/* end of file, go to next one */
			if (cur->next == NULL) {
				last = TRUE;
			} else {
				cur = cur->next;
				cur_offset = cur->hdr.hdr_size;
				continue;
			}
		} 

		/* not EOF */
		break;
	}

	*last_r = cur;
	*last_offset_r = cur_offset;
	return last;
}

bool mail_transaction_log_view_is_last(struct mail_transaction_log_view *view)
{
	struct mail_transaction_log_file *cur;
	uoff_t cur_offset;

	return mail_transaction_log_view_get_last(view, &cur, &cur_offset);
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

bool
mail_transaction_log_view_is_corrupted(struct mail_transaction_log_view *view)
{
	return view->broken;
}

static bool
log_view_is_record_valid(struct mail_transaction_log_file *file,
			 const struct mail_transaction_header *hdr,
			 const void *data)
{
	enum mail_transaction_type rec_type;
	ARRAY_TYPE(seq_range) uids = ARRAY_INIT;
	buffer_t *uid_buf = NULL;
	uint32_t rec_size;
	bool ret = TRUE;

	rec_type = hdr->type & MAIL_TRANSACTION_TYPE_MASK;
	rec_size = mail_index_offset_to_uint32(hdr->size) - sizeof(*hdr);

	/* we want to be extra careful with expunges */
	if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0) {
		if (rec_type != (MAIL_TRANSACTION_EXPUNGE |
				 MAIL_TRANSACTION_EXPUNGE_PROT)) {
			mail_transaction_log_file_set_corrupted(file,
				"expunge record missing protection mask");
			return FALSE;
		}
	}

	if (rec_size == 0) {
		mail_transaction_log_file_set_corrupted(file,
			"Empty record contents (type=0x%x)", rec_type);
		return FALSE;
	}

	/* records that are exported by syncing and view syncing will be
	   checked here so that we don't have to implement the same validation
	   multiple times. other records are checked internally by
	   mail_index_sync_record(). */
	t_push();
	switch (rec_type) {
	case MAIL_TRANSACTION_APPEND:
		if ((rec_size % sizeof(struct mail_index_record)) != 0) {
			mail_transaction_log_file_set_corrupted(file,
				"Invalid append record size");
			ret = FALSE;
		}
		break;
	case MAIL_TRANSACTION_EXPUNGE:
		uid_buf = buffer_create_const_data(pool_datastack_create(),
						   data, rec_size);
		array_create_from_buffer(&uids, uid_buf,
			sizeof(struct mail_transaction_expunge));
		break;
	case MAIL_TRANSACTION_FLAG_UPDATE:
		uid_buf = buffer_create_const_data(pool_datastack_create(),
						   data, rec_size);
		array_create_from_buffer(&uids, uid_buf,
			sizeof(struct mail_transaction_flag_update));
		break;
	case MAIL_TRANSACTION_KEYWORD_UPDATE: {
		const struct mail_transaction_keyword_update *rec = data;
		unsigned int seqset_offset;

		seqset_offset = sizeof(*rec) + rec->name_size;
		if ((seqset_offset % 4) != 0)
			seqset_offset += 4 - (seqset_offset % 4);

		if (seqset_offset > rec_size) {
			mail_transaction_log_file_set_corrupted(file,
				"Invalid keyword update record size");
			ret = FALSE;
			break;
		}

		uid_buf = buffer_create_const_data(pool_datastack_create(),
					CONST_PTR_OFFSET(data, seqset_offset),
					rec_size - seqset_offset);
		array_create_from_buffer(&uids, uid_buf, sizeof(uint32_t)*2);
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_RESET:
		uid_buf = buffer_create_const_data(pool_datastack_create(),
						   data, rec_size);
		array_create_from_buffer(&uids, uid_buf,
			sizeof(struct mail_transaction_keyword_reset));
		break;
	default:
		break;
	}

	if (array_is_created(&uids)) {
		const struct seq_range *rec, *prev = NULL;
		unsigned int i, count = array_count(&uids);

		if ((uid_buf->used % uids.arr.element_size) != 0) {
			mail_transaction_log_file_set_corrupted(file,
				"Invalid record size (type=0x%x)", rec_type);
			ret = FALSE;
			count = 0;
		} else if (count == 0) {
			mail_transaction_log_file_set_corrupted(file,
				"No UID ranges (type=0x%x)", rec_type);
			ret = FALSE;
		}

		for (i = 0; i < count; i++, prev = rec) {
			rec = array_idx(&uids, i);
			if (rec->seq1 > rec->seq2 || rec->seq1 == 0) {
				mail_transaction_log_file_set_corrupted(file,
					"Invalid UID range "
					"(%u .. %u, type=0x%x)",
					rec->seq1, rec->seq2, rec_type);
				ret = FALSE;
				break;
			}
			if (prev != NULL && rec->seq1 <= prev->seq2) {
				mail_transaction_log_file_set_corrupted(file,
					"Non-sorted UID ranges (type=0x%x)",
					rec_type);
				ret = FALSE;
				break;
			}
		}
	}
	t_pop();
	return ret;
}

static int
log_view_get_next(struct mail_transaction_log_view *view,
		  const struct mail_transaction_header **hdr_r,
		  const void **data_r)
{
	const struct mail_transaction_header *hdr;
	struct mail_transaction_log_file *file;
	const void *data;
	enum mail_transaction_type rec_type;
	uint32_t full_size;
	size_t file_size;

	if (view->cur == NULL)
		return 0;

	/* prev_file_offset should point to beginning of previous log record.
	   when we reach EOF, it should be left there, not to beginning of the
	   next file that's not included inside the view. */
	if (mail_transaction_log_view_get_last(view, &view->cur,
					       &view->cur_offset)) {
		/* if the last file was the beginning of a file, we want to
		   move prev pointers there */
		view->prev_file_seq = view->cur->hdr.file_seq;
		view->prev_file_offset = view->cur_offset;
		view->cur = NULL;
		return 0;
	}

	view->prev_file_seq = view->cur->hdr.file_seq;
	view->prev_file_offset = view->cur_offset;

	file = view->cur;

	data = buffer_get_data(file->buffer, &file_size);
	file_size += file->buffer_offset;

	if (view->cur_offset + sizeof(*hdr) > file_size) {
		mail_transaction_log_file_set_corrupted(file,
			"offset points outside file "
			"(%"PRIuUOFF_T" + %"PRIuSIZE_T" > %"PRIuSIZE_T")",
			view->cur_offset, sizeof(*hdr), file_size);
		return -1;
	}

	i_assert(view->cur_offset >= file->buffer_offset);
	hdr = CONST_PTR_OFFSET(data, view->cur_offset - file->buffer_offset);
	data = CONST_PTR_OFFSET(hdr, sizeof(*hdr));

	rec_type = hdr->type & MAIL_TRANSACTION_TYPE_MASK;
	full_size = mail_index_offset_to_uint32(hdr->size);
	if (full_size < sizeof(*hdr)) {
		mail_transaction_log_file_set_corrupted(file,
			"record size too small (type=0x%x, "
			"offset=%"PRIuUOFF_T", size=%u)",
			rec_type, view->cur_offset, full_size);
		return -1;
	}

	if (file_size - view->cur_offset < full_size) {
		mail_transaction_log_file_set_corrupted(file,
			"record size too large (type=0x%x, "
			"offset=%"PRIuUOFF_T", size=%u, end=%"PRIuSIZE_T")",
			rec_type, view->cur_offset, full_size, file_size);
		return -1;
	}

	if (!log_view_is_record_valid(file, hdr, data))
		return -1;

	*hdr_r = hdr;
	*data_r = data;
	view->cur_offset += full_size;
	return 1;
}

int mail_transaction_log_view_next(struct mail_transaction_log_view *view,
				   const struct mail_transaction_header **hdr_r,
				   const void **data_r)
{
	const struct mail_transaction_header *hdr;
	const void *data;
	int ret = 0;

	if (view->broken)
		return -1;

	ret = log_view_get_next(view, &hdr, &data);
	if (ret <= 0) {
		if (ret < 0)
			view->cur_offset = view->cur->sync_offset;
		return ret;
	}

	/* drop expunge protection */
	if ((hdr->type & MAIL_TRANSACTION_TYPE_MASK) ==
	    (MAIL_TRANSACTION_EXPUNGE | MAIL_TRANSACTION_EXPUNGE_PROT))
		view->tmp_hdr.type = hdr->type & ~MAIL_TRANSACTION_EXPUNGE_PROT;
	else
		view->tmp_hdr.type = hdr->type;

	/* return record's size */
	view->tmp_hdr.size = mail_index_offset_to_uint32(hdr->size);
	i_assert(view->tmp_hdr.size > sizeof(*hdr));
	view->tmp_hdr.size -= sizeof(*hdr);

	*hdr_r = &view->tmp_hdr;
	*data_r = data;
	return 1;
}

void mail_transaction_log_view_seek(struct mail_transaction_log_view *view,
				    uint32_t seq, uoff_t offset)
{
	struct mail_transaction_log_file *file;

	i_assert(seq >= view->min_file_seq && seq <= view->max_file_seq);
	i_assert(seq != view->min_file_seq || offset >= view->min_file_offset);
	i_assert(seq != view->max_file_seq || offset < view->max_file_offset);

	if (view->cur == NULL || seq != view->cur->hdr.file_seq) {
		for (file = view->tail; file != NULL; file = file->next) {
			if (file->hdr.file_seq == seq)
				break;
		}
		i_assert(file != NULL);

		view->cur = file;
	}

	view->cur_offset = offset;
}
