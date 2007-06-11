/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
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
			      uint32_t max_file_seq, uoff_t max_file_offset,
			      enum mail_transaction_type type_mask)
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
	view->type_mask = type_mask;
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

static int
log_view_get_next(struct mail_transaction_log_view *view,
		  const struct mail_transaction_header **hdr_r,
		  const void **data_r)
{
	const struct mail_transaction_header *hdr;
	struct mail_transaction_log_file *file;
	const struct mail_transaction_type_map *type_rec;
	const void *data;
	unsigned int record_size;
	enum mail_transaction_type hdr_type;
	uint32_t hdr_size;
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

	hdr_type = hdr->type & MAIL_TRANSACTION_TYPE_MASK;
	hdr_size = mail_index_offset_to_uint32(hdr->size);
	if (hdr_size < sizeof(*hdr)) {
		type_rec = NULL;
		record_size = 0;
	} else {
		type_rec = mail_transaction_type_lookup(hdr->type);
		if (type_rec != NULL)
			record_size = type_rec->record_size;
		else {
			mail_transaction_log_file_set_corrupted(file,
				"unknown record type 0x%x", hdr_type);
			return -1;
		}
	}

	if (hdr_size < sizeof(*hdr) + record_size) {
		mail_transaction_log_file_set_corrupted(file,
			"record size too small (type=0x%x, "
			"offset=%"PRIuUOFF_T", size=%u)",
			hdr_type, view->cur_offset, hdr_size);
		return -1;
	}

	if (record_size != 0 &&
	    (hdr_size - sizeof(*hdr)) % record_size != 0) {
		mail_transaction_log_file_set_corrupted(file,
			"record size wrong (type 0x%x, "
			"offset=%"PRIuUOFF_T", size=%"PRIuSIZE_T" %% %u != 0)",
			hdr_type, view->cur_offset, (hdr_size - sizeof(*hdr)),
			record_size);
		return -1;
	}

	if (file_size - view->cur_offset < hdr_size) {
		mail_transaction_log_file_set_corrupted(file,
			"record size too large (type=0x%x, "
			"offset=%"PRIuUOFF_T", size=%u, end=%"PRIuSIZE_T")",
			hdr_type, view->cur_offset, hdr_size, file_size);
		return -1;
	}

	if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0) {
		if (hdr_type != (MAIL_TRANSACTION_EXPUNGE |
				 MAIL_TRANSACTION_EXPUNGE_PROT)) {
			mail_transaction_log_file_set_corrupted(file,
				"found expunge without protection mask");
			return -1;
		}
	} else if (hdr_type != type_rec->type) {
		mail_transaction_log_file_set_corrupted(file,
			"extra bits in header type: 0x%x", hdr_type);
		return -1;
	} else if (hdr_type == MAIL_TRANSACTION_EXT_INTRO) {
		const struct mail_transaction_ext_intro *intro;
		uint32_t i;

		for (i = 0; i < hdr_size; ) {
			if (i + sizeof(*intro) > hdr_size) {
				/* should be just extra padding */
				break;
			}

			intro = CONST_PTR_OFFSET(data, i);
			if (intro->name_size >
			    hdr_size - sizeof(*hdr) - sizeof(*intro)) {
				mail_transaction_log_file_set_corrupted(file,
					"extension intro: name_size too large");
				return -1;
			}

			i += sizeof(*intro) + intro->name_size;
		}
	}

	*hdr_r = hdr;
	*data_r = data;
	view->cur_offset += hdr_size;
	return 1;
}

int mail_transaction_log_view_next(struct mail_transaction_log_view *view,
				   const struct mail_transaction_header **hdr_r,
				   const void **data_r, bool *skipped_r)
{
	const struct mail_transaction_header *hdr;
	const void *data;
	int ret = 0;

	if (skipped_r != NULL)
		*skipped_r = FALSE;
	if (view->broken)
		return -1;

	while ((ret = log_view_get_next(view, &hdr, &data)) > 0) {
		if ((view->type_mask & hdr->type) != 0) {
			/* looks like this is within our mask, but expunge
			   protection may mess up the check. */
			if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) == 0 ||
			    (view->type_mask & MAIL_TRANSACTION_EXPUNGE) != 0)
				break;
		}

		/* we don't want this record */
		if (skipped_r != NULL)
			*skipped_r = TRUE;

		/* FIXME: hide flag/cache updates for appends if
		   append isn't in mask */
	}

	if (ret < 0) {
		view->cur_offset = view->cur->sync_offset;
		return -1;
	}
	if (ret == 0)
		return 0;

	view->tmp_hdr = *hdr;
	view->tmp_hdr.size =
		mail_index_offset_to_uint32(view->tmp_hdr.size) - sizeof(*hdr);
	i_assert(view->tmp_hdr.size != 0);

	if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0) {
		/* hide expunge protection */
		view->tmp_hdr.type &= ~MAIL_TRANSACTION_EXPUNGE_PROT;
	}

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
