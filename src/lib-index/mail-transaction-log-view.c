/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "mail-index-private.h"
#include "mail-transaction-log-view-private.h"

struct mail_transaction_log_view *
mail_transaction_log_view_open(struct mail_transaction_log *log)
{
	struct mail_transaction_log_view *view;

	view = i_new(struct mail_transaction_log_view, 1);
	view->log = log;
	view->broken = TRUE;

	i_assert(view->log->head != NULL);

	view->head = view->tail = view->log->head;
	view->head->refcount++;
	i_array_init(&view->file_refs, 8);
	array_push_back(&view->file_refs, &view->head);

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

static const char *
mail_transaction_log_get_file_seqs(struct mail_transaction_log *log)
{
	struct mail_transaction_log_file *file;
	string_t *str = t_str_new(32);

	if (log->files == NULL)
		return "";

	for (file = log->files; file != NULL; file = file->next)
		str_printfa(str, ",%u", file->hdr.file_seq);
	return str_c(str) + 1;
}

int mail_transaction_log_view_set(struct mail_transaction_log_view *view,
				  uint32_t min_file_seq, uoff_t min_file_offset,
				  uint32_t max_file_seq, uoff_t max_file_offset,
				  bool *reset_r, const char **reason_r)
{
	struct mail_transaction_log_file *file, *const *files;
	uoff_t start_offset, end_offset;
	unsigned int i;
	uint32_t seq;
	int ret;

	*reset_r = FALSE;
	*reason_r = NULL;

	if (view->log == NULL) {
		/* transaction log is closed already. this log view shouldn't
		   be used anymore. */
		*reason_r = "Log already closed";
		return -1;
	}

	if (min_file_seq == 0) {
		/* index file doesn't exist yet. this transaction log should
		   start from the beginning */
		if (view->log->files->hdr.prev_file_seq != 0) {
			/* but it doesn't */
			*reason_r = t_strdup_printf(
				"Wanted log beginning, but found prev_file_seq=%u",
				view->log->files->hdr.prev_file_seq);
			return 0;
		}

		min_file_seq = view->log->files->hdr.file_seq;
		min_file_offset = 0;

		if (max_file_seq == 0) {
			max_file_seq = min_file_seq;
			max_file_offset = min_file_offset;
		}
	}

	for (file = view->log->files; file != NULL; file = file->next) {
		if (file->hdr.prev_file_seq == min_file_seq)
			break;
	}

	if (file != NULL && min_file_offset == file->hdr.prev_file_offset) {
		/* we can (and sometimes must) skip to the next file */
		min_file_seq = file->hdr.file_seq;
		min_file_offset = file->hdr.hdr_size;
	}

	for (file = view->log->files; file != NULL; file = file->next) {
		if (file->hdr.prev_file_seq == max_file_seq)
			break;
	}
	if (file != NULL && max_file_offset == file->hdr.prev_file_offset) {
		/* we can skip to the next file. we've delayed checking for
		   min_file_seq <= max_file_seq until now, because it's not
		   really an error to specify the same position twice (even if
		   in "wrong" order) */
		i_assert(min_file_seq <= max_file_seq ||
			 min_file_seq <= file->hdr.file_seq);
		max_file_seq = file->hdr.file_seq;
		max_file_offset = file->hdr.hdr_size;
	} else {
		i_assert(min_file_seq <= max_file_seq);
	}

	if (min_file_seq == max_file_seq && min_file_offset > max_file_offset) {
		/* log file offset is probably corrupted in the index file. */
		*reason_r = t_strdup_printf(
			"Invalid offset: file_seq=%u, min_file_offset (%"PRIuUOFF_T
			") > max_file_offset (%"PRIuUOFF_T")",
			min_file_seq, min_file_offset, max_file_offset);
		mail_transaction_log_view_set_corrupted(view, "%s", *reason_r);
		return -1;
	}

	view->tail = view->head = file = NULL;
	for (seq = min_file_seq; seq <= max_file_seq; seq++) {
		const char *reason = NULL;

		if (file == NULL || file->hdr.file_seq != seq) {
			/* see if we could find the missing file. if we know
			   the max. file sequence or we don't have the the min.
			   file, make sure NFS attribute cache gets flushed if
			   necessary. */
			bool nfs_flush = seq == min_file_seq ||
				max_file_seq != (uint32_t)-1;

			ret = mail_transaction_log_find_file(view->log, seq,
				nfs_flush, &file, &reason);
			if (ret <= 0) {
				if (ret < 0) {
					*reason_r = t_strdup_printf(
						"Failed to find file seq=%u: %s",
						seq, reason);
					return -1;
				}

				/* not found / corrupted */
				file = NULL;
			}
		}

		if (file == NULL || file->hdr.file_seq != seq) {
			i_assert(reason != NULL);
			if (file == NULL && max_file_seq == (uint32_t)-1 &&
			    view->head == view->log->head) {
				/* we just wanted to sync everything */
				i_assert(max_file_offset == (uoff_t)-1);
				max_file_seq = seq-1;
				break;
			}
			/* if any of the found files reset the index,
			   ignore any missing files up to it */
			file = view->tail != NULL ? view->tail :
				view->log->files;
			for (;; file = file->next) {
				if (file == NULL ||
				    file->hdr.file_seq > max_file_seq) {
					/* missing files in the middle */
					*reason_r = t_strdup_printf(
						"Missing middle file seq=%u (between %u..%u, we have seqs %s): %s",
						seq, min_file_seq, max_file_seq,
						mail_transaction_log_get_file_seqs(view->log), reason);
					return 0;
				}

				if (file->hdr.file_seq >= seq &&
				    file->hdr.prev_file_seq == 0) {
					/* we can ignore the missing file */
					break;
				}
			}
			seq = file->hdr.file_seq;
			view->tail = NULL;
		} 

		if (view->tail == NULL)
			view->tail = file;
		view->head = file;
		file = file->next;
	}
	i_assert(view->tail != NULL);

	if (min_file_offset == 0) {
		/* beginning of the file */
		min_file_offset = view->tail->hdr.hdr_size;
		if (min_file_offset > max_file_offset &&
		    min_file_seq == max_file_seq) {
			/* we don't actually want to show anything */
			max_file_offset = min_file_offset;
		}
	}

	if (min_file_offset < view->tail->hdr.hdr_size) {
		/* log file offset is probably corrupted in the index file. */
		*reason_r = t_strdup_printf(
			"Invalid min_file_offset: file_seq=%u, min_file_offset (%"PRIuUOFF_T
			") < hdr_size (%u)",
			min_file_seq, min_file_offset, view->tail->hdr.hdr_size);
		mail_transaction_log_view_set_corrupted(view, "%s", *reason_r);
		return -1;
	}
	if (max_file_offset < view->head->hdr.hdr_size) {
		/* log file offset is probably corrupted in the index file. */
		*reason_r = t_strdup_printf(
			"Invalid max_file_offset: file_seq=%u, min_file_offset (%"PRIuUOFF_T
			") < hdr_size (%u)",
			max_file_seq, max_file_offset, view->head->hdr.hdr_size);
		mail_transaction_log_view_set_corrupted(view, "%s", *reason_r);
		return -1;
	}

	/* we have all of them. update refcounts. */
	mail_transaction_log_view_unref_all(view);

	/* Reference all used files. */
	for (file = view->tail;; file = file->next) {
		array_push_back(&view->file_refs, &file);
		file->refcount++;

		if (file == view->head)
			break;
	}

	view->cur = view->tail;
	view->cur_offset = view->cur->hdr.file_seq == min_file_seq ?
		min_file_offset : view->cur->hdr.hdr_size;

	/* Map the files only after we've found them all. Otherwise if we map
	   one file and then another file just happens to get rotated, we could
	   include both files in the view but skip the last transactions from
	   the first file.

	   We're mapping the files in reverse order so that _log_file_map()
	   can verify that prev_file_offset matches how far it actually managed
	   to sync the file. */
	files = array_front(&view->file_refs);
	for (i = array_count(&view->file_refs); i > 0; i--) {
		file = files[i-1];
		start_offset = file->hdr.file_seq == min_file_seq ?
			min_file_offset : file->hdr.hdr_size;
		end_offset = file->hdr.file_seq == max_file_seq ?
			max_file_offset : (uoff_t)-1;
		ret = mail_transaction_log_file_map(file, start_offset,
						    end_offset, reason_r);
		if (ret <= 0) {
			*reason_r = t_strdup_printf(
				"Failed to map file seq=%u "
				"offset=%"PRIuUOFF_T"..%"PRIuUOFF_T" (ret=%d): %s",
				file->hdr.file_seq, start_offset, end_offset, ret, *reason_r);
			return ret;
		}

		if (file->hdr.prev_file_seq == 0) {
			/* this file resets the index.
			   don't bother reading the others. */
			if (view->cur != file ||
			    view->cur_offset == file->hdr.hdr_size) {
				view->cur = file;
				view->cur_offset = file->hdr.hdr_size;
				*reset_r = TRUE;
				break;
			}
			i_assert(i == 1);
		}
	}

	if (min_file_seq == view->head->hdr.file_seq &&
	    min_file_offset > view->head->sync_offset) {
		/* log file offset is probably corrupted in the index file. */
		*reason_r = t_strdup_printf(
			"Invalid offset: file_seq=%u, min_file_offset (%"PRIuUOFF_T
			") > sync_offset (%"PRIuUOFF_T")", min_file_seq,
			min_file_offset, view->head->sync_offset);
		mail_transaction_log_view_set_corrupted(view, "%s", *reason_r);
		return -1;
	}

	i_assert(max_file_seq == (uint32_t)-1 ||
		 max_file_seq == view->head->hdr.file_seq);
	i_assert(max_file_offset == (uoff_t)-1 ||
		 max_file_offset <= view->head->sync_offset);
	i_assert(min_file_seq != max_file_seq ||
		 max_file_seq != view->head->hdr.file_seq ||
		 max_file_offset != (uoff_t)-1 ||
		 min_file_offset <= view->head->sync_offset);

	view->prev_file_seq = view->cur->hdr.file_seq;
	view->prev_file_offset = view->cur_offset;

	view->min_file_seq = min_file_seq;
	view->min_file_offset = min_file_offset;
	view->max_file_seq = max_file_seq;
	view->max_file_offset = I_MIN(max_file_offset, view->head->sync_offset);
	view->broken = FALSE;

	if (mail_transaction_log_file_get_highest_modseq_at(view->cur,
				view->cur_offset, &view->prev_modseq, reason_r) < 0)
		return -1;

	i_assert(view->cur_offset <= view->cur->sync_offset);
	return 1;
}

int mail_transaction_log_view_set_all(struct mail_transaction_log_view *view)
{
	struct mail_transaction_log_file *file, *first;
	const char *reason = NULL;
	int ret;

	/* make sure .log.2 file is opened */
	(void)mail_transaction_log_find_file(view->log, 1, FALSE, &file, &reason);

	first = view->log->files;
	i_assert(first != NULL);

	for (file = view->log->files; file != NULL; file = file->next) {
		ret = mail_transaction_log_file_map(file, file->hdr.hdr_size,
						    (uoff_t)-1, &reason);
		if (ret < 0) {
			first = NULL;
			break;
		}
		if (ret == 0) {
			/* corrupted */
			first = NULL;
		} else if (file->hdr.prev_file_seq == 0) {
			/* this file resets the index. skip the old ones. */
			first = file;
		}
	}
	if (first == NULL) {
		/* index wasn't reset after corruption was found */
		i_assert(reason != NULL);
		mail_index_set_error(view->log->index,
			"Failed to map transaction log %s for all-view: %s",
			view->log->filepath, reason);
		return -1;
	}

	mail_transaction_log_view_unref_all(view);
	for (file = first; file != NULL; file = file->next) {
		array_push_back(&view->file_refs, &file);
		file->refcount++;
	}

	view->tail = first;
	view->cur = view->tail;
	view->cur_offset = view->tail->hdr.hdr_size;

	view->prev_file_seq = view->cur->hdr.file_seq;
	view->prev_file_offset = view->cur_offset;

	view->min_file_seq = view->cur->hdr.file_seq;
	view->min_file_offset = view->cur_offset;
	view->max_file_seq = view->head->hdr.file_seq;
	view->max_file_offset = view->head->sync_offset;
	view->broken = FALSE;

	if (mail_transaction_log_file_get_highest_modseq_at(view->cur,
			view->cur_offset, &view->prev_modseq, &reason) < 0) {
		mail_index_set_error(view->log->index,
			"Failed to get modseq in %s for all-view: %s",
			view->log->filepath, reason);
		return -1;
	}
	return 0;
}

void mail_transaction_log_view_clear(struct mail_transaction_log_view *view,
				     uint32_t oldest_file_seq)
{
	struct mail_transaction_log_file *file;
	const char *reason;

	mail_transaction_log_view_unref_all(view);
	if (oldest_file_seq != 0 &&
	    mail_transaction_log_find_file(view->log, oldest_file_seq, FALSE,
					   &file, &reason) > 0) {
		for (; file != NULL; file = file->next) {
			array_push_back(&view->file_refs, &file);
			file->refcount++;
		}
	}

	view->cur = view->head = view->tail = NULL;

	view->mark_file = NULL;
	view->mark_offset = 0;
	view->mark_modseq = 0;

	view->min_file_seq = view->max_file_seq = 0;
	view->min_file_offset = view->max_file_offset = 0;
	view->cur_offset = 0;

	view->prev_file_seq = 0;
	view->prev_file_offset = 0;
	view->prev_modseq = 0;
}

void
mail_transaction_log_view_get_prev_pos(struct mail_transaction_log_view *view,
				       uint32_t *file_seq_r,
				       uoff_t *file_offset_r)
{
	*file_seq_r = view->prev_file_seq;
	*file_offset_r = view->prev_file_offset;
}

uint64_t
mail_transaction_log_view_get_prev_modseq(struct mail_transaction_log_view *view)
{
	return view->prev_modseq;
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
	T_BEGIN {
		mail_transaction_log_file_set_corrupted(view->log->head, "%s",
			t_strdup_vprintf(fmt, va));
	} T_END;
	va_end(va);
}

bool
mail_transaction_log_view_is_corrupted(struct mail_transaction_log_view *view)
{
	return view->broken;
}

static bool
log_view_is_uid_range_valid(struct mail_transaction_log_file *file,
			    enum mail_transaction_type rec_type,
			    const ARRAY_TYPE(seq_range) *uids)
{
	const struct seq_range *rec, *prev = NULL;
	unsigned int i, count = array_count(uids);

	if ((uids->arr.buffer->used % uids->arr.element_size) != 0) {
		mail_transaction_log_file_set_corrupted(file,
			"Invalid record size (type=0x%x)", rec_type);
		return FALSE;
	} else if (count == 0) {
		mail_transaction_log_file_set_corrupted(file,
			"No UID ranges (type=0x%x)", rec_type);
		return FALSE;
	}

	for (i = 0; i < count; i++, prev = rec) {
		rec = array_idx(uids, i);
		if (rec->seq1 > rec->seq2 || rec->seq1 == 0) {
			mail_transaction_log_file_set_corrupted(file,
				"Invalid UID range (%u .. %u, type=0x%x)",
				rec->seq1, rec->seq2, rec_type);
			return FALSE;
		}
		if (prev != NULL && rec->seq1 <= prev->seq2) {
			mail_transaction_log_file_set_corrupted(file,
				"Non-sorted UID ranges (type=0x%x)", rec_type);
			return FALSE;
		}
	}
	return TRUE;
}

static bool
log_view_is_record_valid(struct mail_transaction_log_file *file,
			 const struct mail_transaction_header *hdr,
			 const void *data)
{
	enum mail_transaction_type rec_type;
	ARRAY_TYPE(seq_range) uids = ARRAY_INIT;
	buffer_t uid_buf;
	uint32_t rec_size;

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
		rec_type &= ~MAIL_TRANSACTION_EXPUNGE_PROT;
	}
	if ((hdr->type & MAIL_TRANSACTION_EXPUNGE_GUID) != 0) {
		if (rec_type != (MAIL_TRANSACTION_EXPUNGE_GUID |
				 MAIL_TRANSACTION_EXPUNGE_PROT)) {
			mail_transaction_log_file_set_corrupted(file,
				"expunge guid record missing protection mask");
			return FALSE;
		}
		rec_type &= ~MAIL_TRANSACTION_EXPUNGE_PROT;
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
	switch (rec_type) {
	case MAIL_TRANSACTION_APPEND:
		if ((rec_size % sizeof(struct mail_index_record)) != 0) {
			mail_transaction_log_file_set_corrupted(file,
				"Invalid append record size");
			return FALSE;
		}
		break;
	case MAIL_TRANSACTION_EXPUNGE:
		buffer_create_from_const_data(&uid_buf, data, rec_size);
		array_create_from_buffer(&uids, &uid_buf,
			sizeof(struct mail_transaction_expunge));
		break;
	case MAIL_TRANSACTION_EXPUNGE_GUID: {
		const struct mail_transaction_expunge_guid *recs = data;
		unsigned int i, count;

		if ((rec_size % sizeof(*recs)) != 0) {
			mail_transaction_log_file_set_corrupted(file,
				"Invalid expunge guid record size");
			return FALSE;
		}
		count = rec_size / sizeof(*recs);
		for (i = 0; i < count; i++) {
			if (recs[i].uid == 0) {
				mail_transaction_log_file_set_corrupted(file,
					"Expunge guid record with uid=0");
				return FALSE;
			}
		}
		break;
	}
	case MAIL_TRANSACTION_FLAG_UPDATE:
		buffer_create_from_const_data(&uid_buf, data, rec_size);
		array_create_from_buffer(&uids, &uid_buf,
			sizeof(struct mail_transaction_flag_update));
		break;
	case MAIL_TRANSACTION_KEYWORD_UPDATE: {
		const struct mail_transaction_keyword_update *rec = data;
		unsigned int seqset_offset;

		seqset_offset = sizeof(*rec) + rec->name_size;
		if ((seqset_offset % 4) != 0)
			seqset_offset += 4 - (seqset_offset % 4);

		if (rec->name_size == 0) {
			mail_transaction_log_file_set_corrupted(file,
				"Trying to use empty keyword");
			return FALSE;
		}
		if (seqset_offset > rec_size) {
			mail_transaction_log_file_set_corrupted(file,
				"Invalid keyword update record size");
			return FALSE;
		}

		buffer_create_from_const_data(&uid_buf,
					 CONST_PTR_OFFSET(data, seqset_offset),
					 rec_size - seqset_offset);
		array_create_from_buffer(&uids, &uid_buf,
					 sizeof(uint32_t)*2);
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_RESET:
		buffer_create_from_const_data(&uid_buf, data, rec_size);
		array_create_from_buffer(&uids, &uid_buf,
			sizeof(struct mail_transaction_keyword_reset));
		break;
	case MAIL_TRANSACTION_EXT_INTRO: {
		const struct mail_transaction_ext_intro *rec;
		unsigned int i;

		for (i = 0; i < rec_size; ) {
			if (i + sizeof(*rec) > rec_size) {
				/* should be just extra padding */
				break;
			}

			rec = CONST_PTR_OFFSET(data, i);
			if (i + sizeof(*rec) + rec->name_size > rec_size) {
				mail_transaction_log_file_set_corrupted(file,
					"ext intro: name_size too large");
				return FALSE;
			}
			i += sizeof(*rec) + rec->name_size;
			if ((i % 4) != 0)
				i += 4 - (i % 4);
		}
		break;
	}
	case MAIL_TRANSACTION_ATTRIBUTE_UPDATE: {
		const char *attr_changes = data;
		unsigned int i;

		for (i = 0; i+2 < rec_size && attr_changes[i] != '\0'; ) {
			if (attr_changes[i] != '+' && attr_changes[i] != '-') {
				mail_transaction_log_file_set_corrupted(file,
					"attribute update: Invalid prefix 0x%02x",
					attr_changes[i]);
				return FALSE;
			}
			i++;
			if (attr_changes[i] != 'p' && attr_changes[i] != 's') {
				mail_transaction_log_file_set_corrupted(file,
					"attribute update: Invalid type 0x%02x",
					attr_changes[i]);
				return FALSE;
			}
			i++;
			if (attr_changes[i] == '\0') {
				mail_transaction_log_file_set_corrupted(file,
					"attribute update: Empty key");
				return FALSE;
			}
			i += strlen(attr_changes+i) + 1;
		}
		if (i == 0 || (i < rec_size && attr_changes[i] != '\0')) {
			mail_transaction_log_file_set_corrupted(file,
				"attribute update doesn't end with NUL");
			return FALSE;
		}
		break;
	}
	default:
		break;
	}

	if (array_is_created(&uids)) {
		if (!log_view_is_uid_range_valid(file, rec_type, &uids))
			return FALSE;
	}
	return TRUE;
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
	int ret;

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

	data = file->buffer->data;
	file_size = file->buffer->used + file->buffer_offset;

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

	T_BEGIN {
		ret = log_view_is_record_valid(file, hdr, data) ? 1 : -1;
	} T_END;
	if (ret > 0) {
		mail_transaction_update_modseq(hdr, data, &view->prev_modseq,
			MAIL_TRANSACTION_LOG_HDR_VERSION(&file->hdr));
		*hdr_r = hdr;
		*data_r = data;
		view->cur_offset += full_size;
	}
	return ret;
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
	    (MAIL_TRANSACTION_EXPUNGE | MAIL_TRANSACTION_EXPUNGE_PROT) ||
	    (hdr->type & MAIL_TRANSACTION_TYPE_MASK) ==
	    (MAIL_TRANSACTION_EXPUNGE_GUID | MAIL_TRANSACTION_EXPUNGE_PROT))
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

void mail_transaction_log_view_mark(struct mail_transaction_log_view *view)
{
	i_assert(view->cur->hdr.file_seq == view->prev_file_seq);

	view->mark_file = view->cur;
	view->mark_offset = view->prev_file_offset;
	view->mark_next_offset = view->cur_offset;
	view->mark_modseq = view->prev_modseq;
}

void mail_transaction_log_view_rewind(struct mail_transaction_log_view *view)
{
	i_assert(view->mark_file != NULL);

	view->cur = view->mark_file;
	view->cur_offset = view->mark_next_offset;
	view->prev_file_seq = view->cur->hdr.file_seq;
	view->prev_file_offset = view->mark_offset;
	view->prev_modseq = view->mark_modseq;
}
