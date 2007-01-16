/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "buffer.h"
#include "write-full.h"
#include "mail-index-private.h"
#include "mail-index-view-private.h"
#include "mail-index-transaction-private.h"
#include "mail-transaction-log-private.h"

static int log_append_buffer(struct mail_transaction_log_file *file,
			     const buffer_t *buf, const buffer_t *hdr_buf,
			     enum mail_transaction_type type, int external)
{
	struct mail_transaction_header hdr;
	const void *data, *hdr_data;
	size_t size, hdr_data_size;
	uoff_t offset;
	uint32_t hdr_size;

	i_assert((type & MAIL_TRANSACTION_TYPE_MASK) != 0);

	data = buffer_get_data(buf, &size);
	if (size == 0)
		return 0;

	i_assert((size % 4) == 0);

	if (hdr_buf != NULL) {
		hdr_data = buffer_get_data(hdr_buf, &hdr_data_size);
		i_assert((hdr_data_size % 4) == 0);
	} else {
		hdr_data = NULL;
		hdr_data_size = 0;
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.type = type;
	if (type == MAIL_TRANSACTION_EXPUNGE)
		hdr.type |= MAIL_TRANSACTION_EXPUNGE_PROT;
	if (external)
		hdr.type |= MAIL_TRANSACTION_EXTERNAL;

	hdr_size = mail_index_uint32_to_offset(sizeof(hdr) + size +
					       hdr_data_size);
	if (!MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file)) {
		do {
			offset = file->sync_offset;
			if (file->first_append_size == 0) {
				/* size will be written later once everything
				   is in disk */
				file->first_append_size = hdr_size;
			} else {
				hdr.size = hdr_size;
			}
			if (pwrite_full(file->fd, &hdr, sizeof(hdr),
					offset) < 0)
				break;
			offset += sizeof(hdr);

			if (hdr_data_size > 0) {
				if (pwrite_full(file->fd, hdr_data,
						hdr_data_size, offset) < 0)
					break;
				offset += hdr_data_size;
			}

			if (pwrite_full(file->fd, data, size, offset) < 0)
				break;

			file->sync_offset = offset + size;
			return 0;
		} while (0);

		/* write failure. */
		if (!ENOSPACE(errno)) {
			mail_index_file_set_syscall_error(file->log->index,
							  file->filepath,
							  "pwrite_full()");
			return -1;
		}

		/* not enough space. fallback to in-memory indexes. */
		if (mail_index_move_to_memory(file->log->index) < 0)
			return -1;
		i_assert(MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file));
	}

	hdr.size = hdr_size;

	i_assert(file->buffer_offset + file->buffer->used ==
		 file->sync_offset);
	buffer_append(file->buffer, &hdr, sizeof(hdr));
	buffer_append(file->buffer, hdr_data, hdr_data_size);
	buffer_append(file->buffer, data, size);
	file->sync_offset = file->buffer_offset + file->buffer->used;
	return 0;
}

static const buffer_t *
log_get_hdr_update_buffer(struct mail_index_transaction *t, bool prepend)
{
	buffer_t *buf;
	const unsigned char *data, *mask;
	struct mail_transaction_header_update u;
	uint16_t offset;
	int state = 0;

	memset(&u, 0, sizeof(u));

	data = prepend ? t->pre_hdr_change : t->post_hdr_change;
	mask = prepend ? t->pre_hdr_mask : t->post_hdr_mask;

	buf = buffer_create_dynamic(pool_datastack_create(), 256);
	for (offset = 0; offset <= sizeof(t->pre_hdr_change); offset++) {
		if (offset < sizeof(t->pre_hdr_change) && mask[offset]) {
			if (state == 0) {
				u.offset = offset;
				state++;
			}
		} else {
			if (state > 0) {
				u.size = offset - u.offset;
				buffer_append(buf, &u, sizeof(u));
				buffer_append(buf, data + u.offset, u.size);
				state = 0;
			}
		}
	}
	return buf;
}

static int log_append_ext_intro(struct mail_transaction_log_file *file,
				struct mail_index_transaction *t,
				uint32_t ext_id, uint32_t reset_id)
{
	const struct mail_index_registered_ext *rext;
        struct mail_transaction_ext_intro *intro;
	buffer_t *buf;
	uint32_t idx;
	unsigned int count;

	if (!mail_index_map_get_ext_idx(t->view->map, ext_id, &idx)) {
		/* new extension */
		idx = (uint32_t)-1;
	}

	rext = array_idx(&t->view->index->extensions, ext_id);
	if (!array_is_created(&t->ext_resizes)) {
		intro = NULL;
		count = 0;
	} else {
		intro = array_get_modifiable(&t->ext_resizes, &count);
	}

	buf = buffer_create_dynamic(pool_datastack_create(), 128);
	if (ext_id < count && intro[ext_id].name_size != 0) {
		/* we're resizing it */
		intro += ext_id;

		i_assert(intro->ext_id == idx);
		intro->name_size = idx != (uint32_t)-1 ? 0 :
			strlen(rext->name);
		buffer_append(buf, intro, sizeof(*intro));
	} else {
		/* generate a new intro structure */
		intro = buffer_append_space_unsafe(buf, sizeof(*intro));
		intro->ext_id = idx;
		intro->hdr_size = rext->hdr_size;
		intro->record_size = rext->record_size;
		intro->record_align = rext->record_align;
		intro->name_size = idx != (uint32_t)-1 ? 0 :
			strlen(rext->name);
	}
	if (reset_id != 0) {
		/* we're going to reset this extension in this transaction */
		intro->reset_id = reset_id;
	} else if (idx != (uint32_t)-1) {
		/* use the existing reset_id */
		const struct mail_index_ext *map_ext =
			array_idx(&t->view->map->extensions, idx);
		intro->reset_id = map_ext->reset_id;
	} else {
		/* new extension, reset_id defaults to 0 */
	}
	buffer_append(buf, rext->name, intro->name_size);

	if ((buf->used % 4) != 0)
		buffer_append_zero(buf, 4 - (buf->used % 4));

	return log_append_buffer(file, buf, NULL, MAIL_TRANSACTION_EXT_INTRO,
				 t->external);
}

static int
mail_transaction_log_append_ext_intros(struct mail_transaction_log_file *file,
				       struct mail_index_transaction *t)
{
        const struct mail_transaction_ext_intro *resize;
	struct mail_transaction_ext_reset ext_reset;
	unsigned int update_count, resize_count, reset_count, ext_count;
	uint32_t ext_id;
	const uint32_t *reset;
	const ARRAY_TYPE(seq_array) *update;
	buffer_t *buf;

	if (!array_is_created(&t->ext_rec_updates)) {
		update = NULL;
		update_count = 0;
	} else {
		update = array_get(&t->ext_rec_updates, &update_count);
	}

	if (!array_is_created(&t->ext_resizes)) {
		resize = NULL;
		resize_count = 0;
	} else {
		resize = array_get(&t->ext_resizes, &resize_count);
	}

	if (!array_is_created(&t->ext_resets)) {
		reset = NULL;
		reset_count = 0;
	} else {
		reset = array_get(&t->ext_resets, &reset_count);
	}

	memset(&ext_reset, 0, sizeof(ext_reset));

	buf = buffer_create_data(pool_datastack_create(),
				 &ext_reset, sizeof(ext_reset));
	buffer_set_used_size(buf, sizeof(ext_reset));
	ext_count = I_MAX(I_MAX(update_count, resize_count), reset_count);

	for (ext_id = 0; ext_id < ext_count; ext_id++) {
		ext_reset.new_reset_id =
			ext_id < reset_count && reset[ext_id] != 0 ?
			reset[ext_id] : 0;
		if ((ext_id < resize_count && resize[ext_id].name_size) ||
		    (ext_id < update_count &&
		     array_is_created(&update[ext_id])) ||
		    ext_reset.new_reset_id != 0) {
			if (log_append_ext_intro(file, t, ext_id, 0) < 0)
				return -1;
		}
		if (ext_reset.new_reset_id != 0) {
			if (log_append_buffer(file, buf, NULL,
					      MAIL_TRANSACTION_EXT_RESET,
					      t->external) < 0)
				return -1;
		}
	}

	return 0;
}

static int log_append_ext_rec_updates(struct mail_transaction_log_file *file,
				      struct mail_index_transaction *t)
{
	ARRAY_TYPE(seq_array) *updates;
	const uint32_t *reset;
	unsigned int ext_id, count, reset_count;
	uint32_t reset_id;

	if (!array_is_created(&t->ext_rec_updates)) {
		updates = NULL;
		count = 0;
	} else {
		updates = array_get_modifiable(&t->ext_rec_updates, &count);
	}

	if (!array_is_created(&t->ext_resets)) {
		reset = NULL;
		reset_count = 0;
	} else {
		reset = array_get_modifiable(&t->ext_resets, &reset_count);
	}

	for (ext_id = 0; ext_id < count; ext_id++) {
		if (!array_is_created(&updates[ext_id]))
			continue;

		reset_id = ext_id < reset_count && reset[ext_id] != 0 ?
			reset[ext_id] : 0;
		if (log_append_ext_intro(file, t, ext_id, reset_id) < 0)
			return -1;

		if (log_append_buffer(file, updates[ext_id].arr.buffer, NULL,
				      MAIL_TRANSACTION_EXT_REC_UPDATE,
				      t->external) < 0)
			return -1;
	}
	return 0;
}

static int
log_append_keyword_update(struct mail_transaction_log_file *file,
			  struct mail_index_transaction *t,
			  buffer_t *hdr_buf, enum modify_type modify_type,
			  const char *keyword, const buffer_t *buffer)
{
	struct mail_transaction_keyword_update kt_hdr;

	memset(&kt_hdr, 0, sizeof(kt_hdr));
	kt_hdr.modify_type = modify_type;
	kt_hdr.name_size = strlen(keyword);

	buffer_set_used_size(hdr_buf, 0);
	buffer_append(hdr_buf, &kt_hdr, sizeof(kt_hdr));
	buffer_append(hdr_buf, keyword, kt_hdr.name_size);
	if ((hdr_buf->used % 4) != 0)
		buffer_append_zero(hdr_buf, 4 - (hdr_buf->used % 4));

	if (t->hide_transaction) {
		mail_index_view_add_hidden_transaction(t->view,
			file->hdr.file_seq, file->sync_offset);
	}

	return log_append_buffer(file, buffer, hdr_buf,
				 MAIL_TRANSACTION_KEYWORD_UPDATE, t->external);
}

static int log_append_keyword_updates(struct mail_transaction_log_file *file,
				      struct mail_index_transaction *t)
{
        const struct mail_index_transaction_keyword_update *updates;
	const char *const *keywords;
	buffer_t *hdr_buf;
	unsigned int i, count, keywords_count;

	hdr_buf = buffer_create_dynamic(pool_datastack_create(), 64);

	keywords = array_get_modifiable(&t->view->index->keywords,
					&keywords_count);
	updates = array_get_modifiable(&t->keyword_updates, &count);
	i_assert(count <= keywords_count);

	for (i = 0; i < count; i++) {
		if (array_is_created(&updates[i].add_seq)) {
			if (log_append_keyword_update(file, t, hdr_buf,
					MODIFY_ADD, keywords[i],
					updates[i].add_seq.arr.buffer) < 0)
				return -1;
		}
		if (array_is_created(&updates[i].remove_seq)) {
			if (log_append_keyword_update(file, t, hdr_buf,
					MODIFY_REMOVE, keywords[i],
					updates[i].remove_seq.arr.buffer) < 0)
				return -1;
		}
	}

	return 0;
}

#define ARE_ALL_TRANSACTIONS_IN_INDEX(log, idx_hdr) \
	((log)->head->hdr.file_seq == (idx_hdr)->log_file_seq && \
	 (log)->head->sync_offset == (idx_hdr)->log_file_int_offset && \
	 (log)->head->sync_offset == (idx_hdr)->log_file_ext_offset)

static int
mail_transaction_log_append_locked(struct mail_index_transaction *t,
				   uint32_t *log_file_seq_r,
				   uoff_t *log_file_offset_r)
{
	struct mail_index_view *view = t->view;
	struct mail_index *index;
	struct mail_transaction_log *log;
	struct mail_transaction_log_file *file;
	struct mail_index_header idx_hdr;
	uoff_t append_offset;
	unsigned int old_hidden_syncs_count;
	unsigned int lock_id;
	int ret;

	index = mail_index_view_get_index(view);
	log = index->log;

	if (!index->log_locked) {
		/* update sync_offset */
		if (mail_transaction_log_file_map(log->head,
						  log->head->sync_offset,
						  (uoff_t)-1) < 0)
			return -1;
	}

	if (log->head->sync_offset > MAIL_TRANSACTION_LOG_ROTATE_SIZE &&
	    (time_t)log->head->hdr.create_stamp <
	    ioloop_time - MAIL_TRANSACTION_LOG_ROTATE_TIME &&
	    ARE_ALL_TRANSACTIONS_IN_INDEX(log, index->hdr)) {
		/* we might want to rotate, but check first that everything is
		   synced in index. */
		if (mail_index_lock_shared(index, TRUE, &lock_id) < 0)
			return -1;

		/* we need the latest log_file_*_offsets. It's important to
		   use this function instead of mail_index_map() as it may
		   have generated them by reading log files. */
		if (mail_index_get_latest_header(index, &idx_hdr) <= 0) {
			mail_index_unlock(index, lock_id);
			return -1;
		}
		mail_index_unlock(index, lock_id);

		if (ARE_ALL_TRANSACTIONS_IN_INDEX(log, &idx_hdr)) {
			if (mail_transaction_log_rotate(log, TRUE) < 0)
				return -1;
		}
	}

	file = log->head;
	file->first_append_size = 0;
	append_offset = file->sync_offset;

	old_hidden_syncs_count = !array_is_created(&view->syncs_hidden) ? 0 :
		array_count(&view->syncs_hidden);

	ret = 0;

	/* send all extension introductions and resizes before appends
	   to avoid resize overhead as much as possible */
        ret = mail_transaction_log_append_ext_intros(file, t);

	if (t->pre_hdr_changed && ret == 0) {
		ret = log_append_buffer(file,
					log_get_hdr_update_buffer(t, TRUE),
					NULL, MAIL_TRANSACTION_HEADER_UPDATE,
					t->external);
	}
	if (array_is_created(&t->appends) && ret == 0) {
		if (t->hide_transaction) {
			mail_index_view_add_hidden_transaction(view,
				file->hdr.file_seq, file->sync_offset);
		}
		ret = log_append_buffer(file, t->appends.arr.buffer, NULL,
					MAIL_TRANSACTION_APPEND, t->external);
	}
	if (array_is_created(&t->updates) && ret == 0) {
		if (t->hide_transaction) {
			mail_index_view_add_hidden_transaction(view,
				file->hdr.file_seq, file->sync_offset);
		}
		ret = log_append_buffer(file, t->updates.arr.buffer, NULL,
					MAIL_TRANSACTION_FLAG_UPDATE,
					t->external);
	}

	if (array_is_created(&t->ext_rec_updates) && ret == 0)
		ret = log_append_ext_rec_updates(file, t);

	/* keyword resets before updates */
	if (array_is_created(&t->keyword_resets) && ret == 0) {
		if (t->hide_transaction) {
			mail_index_view_add_hidden_transaction(view,
				file->hdr.file_seq, file->sync_offset);
		}
		ret = log_append_buffer(file, t->keyword_resets.arr.buffer,
					NULL, MAIL_TRANSACTION_KEYWORD_RESET,
					t->external);
	}
	if (array_is_created(&t->keyword_updates) && ret == 0)
		ret = log_append_keyword_updates(file, t);

	if (array_is_created(&t->expunges) && ret == 0) {
		/* Expunges cannot be hidden */
		ret = log_append_buffer(file, t->expunges.arr.buffer, NULL,
					MAIL_TRANSACTION_EXPUNGE, t->external);
	}

	if (t->post_hdr_changed && ret == 0) {
		ret = log_append_buffer(file,
					log_get_hdr_update_buffer(t, FALSE),
					NULL, MAIL_TRANSACTION_HEADER_UPDATE,
					t->external);
	}

	if (ret == 0 && file->first_append_size != 0) {
		if (!MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file)) {
			/* synced - rewrite first record's header */
			ret = pwrite_full(file->fd, &file->first_append_size,
					  sizeof(uint32_t), append_offset);
			if (ret < 0) {
				mail_index_file_set_syscall_error(index,
					file->filepath, "pwrite()");
			}
		} else {
			/* changed into in-memory buffer in the middle */
			buffer_write(file->buffer,
				     append_offset - file->buffer_offset,
				     &file->first_append_size,
				     sizeof(file->first_append_size));
		}
	}

	if (ret < 0) {
		if (array_is_created(&view->syncs_hidden)) {
			/* revert changes to log_syncs */
			array_delete(&view->syncs_hidden,
				     old_hidden_syncs_count,
				     array_count(&view->syncs_hidden) -
				     old_hidden_syncs_count);
		}
		file->sync_offset = append_offset;
	}

	*log_file_seq_r = file->hdr.file_seq;
	*log_file_offset_r = file->sync_offset;
	return ret;
}

int mail_transaction_log_append(struct mail_index_transaction *t,
				uint32_t *log_file_seq_r,
				uoff_t *log_file_offset_r)
{
	struct mail_index *index;
	int ret;

	if (!t->log_updates) {
		/* nothing to append */
		*log_file_seq_r = 0;
		*log_file_offset_r = 0;
		return 0;
	}

	index = mail_index_view_get_index(t->view);

	if (index->log_locked) {
		i_assert(t->external);
	} else {
		if (mail_transaction_log_lock_head(index->log) < 0)
			return -1;
	}

	ret = mail_transaction_log_append_locked(t, log_file_seq_r,
						 log_file_offset_r);

	if (!index->log_locked)
		mail_transaction_log_file_unlock(index->log->head);
	return ret;
}
