/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
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

	hdr_size =
		mail_index_uint32_to_offset(sizeof(hdr) + size + hdr_data_size);
	if (file->first_append_size == 0) {
		/* size will be written later once everything is in disk */
		file->first_append_size = hdr_size;
	} else {
		hdr.size = hdr_size;
	}

	if (pwrite_full(file->fd, &hdr, sizeof(hdr), file->sync_offset) < 0)
		return -1;
	file->sync_offset += sizeof(hdr);

	if (hdr_data_size > 0) {
		if (pwrite_full(file->fd, hdr_data, hdr_data_size,
				file->sync_offset) < 0)
			return -1;
		file->sync_offset += hdr_data_size;
	}

	if (pwrite_full(file->fd, data, size, file->sync_offset) < 0)
		return -1;
	file->sync_offset += size;
	return 0;
}

static const buffer_t *
log_get_hdr_update_buffer(struct mail_index_transaction *t)
{
	buffer_t *buf;
	struct mail_transaction_header_update u;
	uint16_t offset;
	int state = 0;

	memset(&u, 0, sizeof(u));

	buf = buffer_create_dynamic(pool_datastack_create(), 256);
	for (offset = 0; offset <= sizeof(t->hdr_change); offset++) {
		if (offset < sizeof(t->hdr_change) && t->hdr_mask[offset]) {
			if (state == 0) {
				u.offset = offset;
				state++;
			}
		} else {
			if (state > 0) {
				u.size = offset - u.offset;
				buffer_append(buf, &u, sizeof(uint16_t)*2);
				buffer_append(buf, t->hdr_change + u.offset,
					      u.size);
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
	const struct mail_index_ext *ext;
        struct mail_transaction_ext_intro *intro;
	buffer_t *buf;
	uint32_t idx;
	unsigned int count;

	if (!mail_index_map_get_ext_idx(t->view->map, ext_id, &idx)) {
		/* new extension */
		idx = (uint32_t)-1;
	}

	ext = array_idx(&t->view->index->extensions, ext_id);
	if (!array_is_created(&t->ext_resizes)) {
		intro = NULL;
		count = 0;
	} else {
		intro = array_get_modifyable(&t->ext_resizes, &count);
	}

	buf = buffer_create_dynamic(pool_datastack_create(), 128);
	if (ext_id < count && intro[ext_id].name_size != 0) {
		/* we're resizing it */
		intro += ext_id;

		i_assert(intro->ext_id == idx);
		intro->name_size = idx != (uint32_t)-1 ? 0 :
			strlen(ext->name);
		buffer_append(buf, intro, sizeof(*intro));
	} else {
		/* generate a new intro structure */
		intro = buffer_append_space_unsafe(buf, sizeof(*intro));
		intro->ext_id = idx;
		intro->hdr_size = ext->hdr_size;
		intro->record_size = ext->record_size;
		intro->record_align = ext->record_align;
		intro->name_size = idx != (uint32_t)-1 ? 0 :
			strlen(ext->name);
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
	buffer_append(buf, ext->name, intro->name_size);

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
	const array_t *update;
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
	array_t *updates;
	const uint32_t *reset;
	unsigned int ext_id, count, reset_count;
	uint32_t reset_id;

	if (!array_is_created(&t->ext_rec_updates)) {
		updates = NULL;
		count = 0;
	} else {
		updates = array_get_modifyable(&t->ext_rec_updates, &count);
	}

	if (!array_is_created(&t->ext_resets)) {
		reset = NULL;
		reset_count = 0;
	} else {
		reset = array_get_modifyable(&t->ext_resets, &reset_count);
	}

	for (ext_id = 0; ext_id < count; ext_id++) {
		if (!array_is_created(&updates[ext_id]))
			continue;

		reset_id = ext_id < reset_count && reset[ext_id] != 0 ?
			reset[ext_id] : 0;
		if (log_append_ext_intro(file, t, ext_id, reset_id) < 0)
			return -1;

		if (log_append_buffer(file, updates[ext_id].buffer, NULL,
				      MAIL_TRANSACTION_EXT_REC_UPDATE,
				      t->external) < 0)
			return -1;
	}
	return 0;
}

static int log_append_keyword_updates(struct mail_transaction_log_file *file,
				      struct mail_index_transaction *t)
{
	struct mail_index *index = t->view->index;
	struct mail_transaction_keyword_update kt_hdr;
	buffer_t *hdr_buf;
	array_t *updates;
	unsigned int i, count;

	hdr_buf = buffer_create_dynamic(pool_datastack_create(), 64);

	updates = array_get_modifyable(&t->keyword_updates, &count);
	for (i = 0; i < count; i++) {
		if (!array_is_created(&updates[i]))
			continue;

		buffer_set_used_size(hdr_buf, 0);

		memset(&kt_hdr, 0, sizeof(kt_hdr));
		kt_hdr.modify_type = (i & 1) == 0 ? MODIFY_ADD : MODIFY_REMOVE;
		kt_hdr.name_size = strlen(index->keywords[i / 2]);
		buffer_append(hdr_buf, &kt_hdr, sizeof(kt_hdr));
		buffer_append(hdr_buf, index->keywords[i / 2],
			      kt_hdr.name_size);
		if ((hdr_buf->used % 4) != 0)
			buffer_append_zero(hdr_buf, 4 - (hdr_buf->used % 4));

		if (log_append_buffer(file, updates[i].buffer, hdr_buf,
				      MAIL_TRANSACTION_KEYWORD_UPDATE,
				      t->external) < 0)
			return -1;
	}

	return 0;
}

int mail_transaction_log_append(struct mail_index_transaction *t,
				uint32_t *log_file_seq_r,
				uoff_t *log_file_offset_r)
{
	struct mail_index_view *view = t->view;
	struct mail_index *index;
	struct mail_transaction_log *log;
	struct mail_transaction_log_file *file;
	struct mail_index_header idx_hdr;
	uoff_t append_offset;
	unsigned int lock_id;
	int ret, visibility_changes = FALSE;

	index = mail_index_view_get_index(view);
	log = index->log;

	if (!t->log_updates) {
		/* nothing to append */
		*log_file_seq_r = 0;
		*log_file_offset_r = 0;
		return 0;
	}

	if (log->index->log_locked) {
		i_assert(t->external);
	} else {
		if (mail_transaction_log_lock_head(log) < 0)
			return -1;

		/* update sync_offset */
		if (mail_transaction_log_file_map(log->head,
						  log->head->sync_offset,
						  (uoff_t)-1) < 0) {
			mail_transaction_log_file_unlock(log->head);
			return -1;
		}
	}

	if (log->head->sync_offset > MAIL_TRANSACTION_LOG_ROTATE_SIZE &&
	    (time_t)log->head->hdr.create_stamp <
	    ioloop_time - MAIL_TRANSACTION_LOG_ROTATE_TIME) {
		/* we might want to rotate, but check first that everything is
		   synced in index. */
		if (mail_index_lock_shared(log->index, TRUE, &lock_id) < 0) {
			if (!log->index->log_locked)
				mail_transaction_log_file_unlock(log->head);
			return -1;
		}
		if (mail_index_map(index, FALSE) <= 0) {
			mail_index_unlock(index, lock_id);
			if (!log->index->log_locked)
				mail_transaction_log_file_unlock(log->head);
			return -1;
		}

		idx_hdr = *log->index->hdr;
		mail_index_unlock(log->index, lock_id);

		if (log->head->hdr.file_seq == idx_hdr.log_file_seq &&
		    log->head->sync_offset == idx_hdr.log_file_int_offset &&
		    log->head->sync_offset == idx_hdr.log_file_ext_offset) {
			if (mail_transaction_log_rotate(log, TRUE) < 0) {
				/* that didn't work. well, try to continue
				   anyway */
			}
		}
	}

	file = log->head;
	file->first_append_size = 0;
	append_offset = file->sync_offset;

	ret = 0;

	/* send all extension introductions and resizes before appends
	   to avoid resize overhead as much as possible */
        ret = mail_transaction_log_append_ext_intros(file, t);

	if (array_is_created(&t->appends) && ret == 0) {
                visibility_changes = TRUE;
		ret = log_append_buffer(file, t->appends.buffer, NULL,
					MAIL_TRANSACTION_APPEND, t->external);
	}
	if (array_is_created(&t->updates) && ret == 0) {
                visibility_changes = TRUE;
		ret = log_append_buffer(file, t->updates.buffer, NULL,
					MAIL_TRANSACTION_FLAG_UPDATE,
					t->external);
	}

	if (array_is_created(&t->ext_rec_updates) && ret == 0)
		ret = log_append_ext_rec_updates(file, t);

	/* keyword resets before updates */
	if (array_is_created(&t->keyword_resets) && ret == 0) {
                visibility_changes = TRUE;
		ret = log_append_buffer(file, t->keyword_resets.buffer, NULL,
					MAIL_TRANSACTION_KEYWORD_RESET,
					t->external);
	}
	if (array_is_created(&t->keyword_updates) && ret == 0) {
                visibility_changes = TRUE;
		ret = log_append_keyword_updates(file, t);
	}

	if (array_is_created(&t->expunges) && ret == 0) {
		ret = log_append_buffer(file, t->expunges.buffer, NULL,
					MAIL_TRANSACTION_EXPUNGE, t->external);
	}
	if (t->hdr_changed && ret == 0) {
		ret = log_append_buffer(file, log_get_hdr_update_buffer(t),
					NULL, MAIL_TRANSACTION_HEADER_UPDATE,
					t->external);
	}

	if (ret < 0) {
		mail_index_file_set_syscall_error(log->index, file->filepath,
						  "pwrite()");
	}

	if (ret == 0 && visibility_changes && t->hide_transaction) {
		mail_index_view_add_synced_transaction(view, file->hdr.file_seq,
						       append_offset);
	}

	if (ret == 0 && fsync(file->fd) < 0) {
		/* we don't know how much of it got written,
		   it may be corrupted now.. */
		mail_index_file_set_syscall_error(log->index, file->filepath,
						  "fsync()");
		ret = -1;
	}

	if (ret == 0 && file->first_append_size != 0) {
		/* synced - rewrite first record's header */
		ret = pwrite_full(file->fd, &file->first_append_size,
				  sizeof(uint32_t), append_offset);
		if (ret < 0) {
			mail_index_file_set_syscall_error(log->index,
							  file->filepath,
							  "pwrite()");
		}
	}

	if (ret < 0)
		file->sync_offset = append_offset;

	*log_file_seq_r = file->hdr.file_seq;
	*log_file_offset_r = file->sync_offset;

	if (!log->index->log_locked)
		mail_transaction_log_file_unlock(file);
	return ret;
}

