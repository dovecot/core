/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "write-full.h"
#include "mail-index-private.h"
#include "mail-index-view-private.h"
#include "mail-index-transaction-private.h"
#include "mail-transaction-log-private.h"

struct log_append_context {
	struct mail_transaction_log_file *file;
	struct mail_index_transaction *trans;
	buffer_t *output;

	uint32_t first_append_size;
	bool sync_includes_this;
};

static void log_append_buffer(struct log_append_context *ctx,
			      const buffer_t *buf, const buffer_t *hdr_buf,
			      enum mail_transaction_type type)
{
	struct mail_transaction_header hdr;
	uint32_t hdr_size;

	i_assert((type & MAIL_TRANSACTION_TYPE_MASK) != 0);
	i_assert((buf->used % 4) == 0);
	i_assert(hdr_buf == NULL || (hdr_buf->used % 4) == 0);

	if (buf->used == 0)
		return;

	memset(&hdr, 0, sizeof(hdr));
	hdr.type = type;
	if (type == MAIL_TRANSACTION_EXPUNGE)
		hdr.type |= MAIL_TRANSACTION_EXPUNGE_PROT;
	if (ctx->trans->external)
		hdr.type |= MAIL_TRANSACTION_EXTERNAL;

	hdr_size = mail_index_uint32_to_offset(sizeof(hdr) + buf->used +
					       (hdr_buf == NULL ? 0 :
						hdr_buf->used));
	if (!MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(ctx->file) &&
	    ctx->first_append_size == 0) {
		/* size will be written later once everything
		   is in disk */
		ctx->first_append_size = hdr_size;
	} else {
		hdr.size = hdr_size;
	}

	buffer_append(ctx->output, &hdr, sizeof(hdr));
	if (hdr_buf != NULL)
		buffer_append(ctx->output, hdr_buf->data, hdr_buf->used);
	buffer_append(ctx->output, buf->data, buf->used);
}

static int log_buffer_move_to_memory(struct log_append_context *ctx)
{
	struct mail_transaction_log_file *file = ctx->file;

	/* first we need to truncate this latest write so that log syncing
	   doesn't break */
	if (ftruncate(file->fd, file->sync_offset) < 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath,
						  "ftruncate()");
	}

	if (mail_index_move_to_memory(file->log->index) < 0)
		return -1;
	i_assert(MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file));

	i_assert(file->buffer_offset + file->buffer->used ==
		 file->sync_offset);
	buffer_append_buf(file->buffer, ctx->output, 0, (size_t)-1);
	file->sync_offset = file->buffer_offset + file->buffer->used;
	return 0;
}

static int log_buffer_write(struct log_append_context *ctx)
{
	struct mail_transaction_log_file *file = ctx->file;

	if (MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file)) {
		buffer_append_buf(file->buffer, ctx->output, 0, (size_t)-1);
		file->sync_offset = file->buffer_offset + file->buffer->used;
		return 0;
	}

	i_assert(ctx->first_append_size != 0);
	if (pwrite_full(file->fd, ctx->output->data, ctx->output->used,
			file->sync_offset) < 0) {
		/* write failure, fallback to in-memory indexes. */
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath,
						  "pwrite_full()");
		return log_buffer_move_to_memory(ctx);
	}

	i_assert(!ctx->sync_includes_this ||
		 file->sync_offset + ctx->output->used ==
		 file->max_tail_offset);

	if (!file->log->index->fsync_disable && fdatasync(file->fd) < 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath,
						  "fsync()");
		return log_buffer_move_to_memory(ctx);
	}

	/* now that the whole transaction has been written, rewrite the first
	   record's size so the transaction becomes visible */
	if (pwrite_full(file->fd, &ctx->first_append_size,
			sizeof(uint32_t), file->sync_offset) < 0) {
		mail_index_file_set_syscall_error(file->log->index,
						  file->filepath,
						  "pwrite_full()");
		return log_buffer_move_to_memory(ctx);
	}

	/* FIXME: when we're relying on O_APPEND and someone else wrote a
	   transaction, we'll need to wait for it to commit its transaction.
	   if it crashes before doing that, we'll need to overwrite it with
	   a dummy record */

	file->sync_offset += ctx->output->used;
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

static void log_append_ext_intro(struct log_append_context *ctx,
				 uint32_t ext_id, uint32_t reset_id)
{
	struct mail_index_transaction *t = ctx->trans;
	const struct mail_index_registered_ext *rext;
        struct mail_transaction_ext_intro *intro;
	buffer_t *buf;
	uint32_t idx;
	unsigned int count;

	i_assert(ext_id != (uint32_t)-1);

	if (t->reset ||
	    !mail_index_map_get_ext_idx(t->view->map, ext_id, &idx)) {
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

	log_append_buffer(ctx, buf, NULL, MAIL_TRANSACTION_EXT_INTRO);
}

static void
log_append_ext_hdr_update(struct log_append_context *ctx,
			  struct mail_index_transaction_ext_hdr_update *hdr)
{
	struct mail_transaction_ext_hdr_update *trans_hdr;
	buffer_t *buf;
	unsigned int hdr_size;

	t_push();
	hdr_size = sizeof(*trans_hdr) + hdr->size;
	buf = buffer_create_static_hard(pool_datastack_create(), hdr_size);
	trans_hdr = buffer_append_space_unsafe(buf, sizeof(*trans_hdr));
	trans_hdr->offset = hdr->offset;
	trans_hdr->size = hdr->size;
	buffer_append(buf, hdr + 1, hdr->size);
	log_append_buffer(ctx, buf, NULL, MAIL_TRANSACTION_EXT_HDR_UPDATE);
	t_pop();
}

static void
mail_transaction_log_append_ext_intros(struct log_append_context *ctx)
{
	struct mail_index_transaction *t = ctx->trans;
        const struct mail_transaction_ext_intro *resize;
	struct mail_index_transaction_ext_hdr_update *const *hdrs;
	struct mail_transaction_ext_reset ext_reset;
	unsigned int update_count, resize_count, ext_count = 0;
	unsigned int hdrs_count, reset_id_count, reset_count;
	uint32_t ext_id, reset_id;
	const uint32_t *reset_ids, *reset;
	const ARRAY_TYPE(seq_array) *update;
	buffer_t *buf;

	if (!array_is_created(&t->ext_rec_updates)) {
		update = NULL;
		update_count = 0;
	} else {
		update = array_get(&t->ext_rec_updates, &update_count);
		ext_count = update_count;
	}

	if (!array_is_created(&t->ext_resizes)) {
		resize = NULL;
		resize_count = 0;
	} else {
		resize = array_get(&t->ext_resizes, &resize_count);
		if (ext_count < resize_count)
			ext_count = resize_count;
	}

	if (!array_is_created(&t->ext_reset_ids)) {
		reset_ids = NULL;
		reset_id_count = 0;
	} else {
		reset_ids = array_get(&t->ext_reset_ids, &reset_id_count);
	}

	if (!array_is_created(&t->ext_resets)) {
		reset = NULL;
		reset_count = 0;
	} else {
		reset = array_get(&t->ext_resets, &reset_count);
		if (ext_count < reset_count)
			ext_count = reset_count;
	}

	if (!array_is_created(&t->ext_hdr_updates)) {
		hdrs = NULL;
		hdrs_count = 0;
	} else {
		hdrs = array_get(&t->ext_hdr_updates, &hdrs_count);
		if (ext_count < hdrs_count)
			ext_count = hdrs_count;
	}

	memset(&ext_reset, 0, sizeof(ext_reset));

	buf = buffer_create_data(pool_datastack_create(),
				 &ext_reset, sizeof(ext_reset));
	buffer_set_used_size(buf, sizeof(ext_reset));

	for (ext_id = 0; ext_id < ext_count; ext_id++) {
		ext_reset.new_reset_id =
			ext_id < reset_count && reset[ext_id] != 0 ?
			reset[ext_id] : 0;
		if ((ext_id < resize_count && resize[ext_id].name_size) ||
		    (ext_id < update_count &&
		     array_is_created(&update[ext_id])) ||
		    ext_reset.new_reset_id != 0 ||
		    (ext_id < hdrs_count && hdrs[ext_id] != NULL)) {
			reset_id = ext_id < reset_id_count &&
				ext_reset.new_reset_id == 0 ?
				reset_ids[ext_id] : 0;
			log_append_ext_intro(ctx, ext_id, reset_id);
		}
		if (ext_reset.new_reset_id != 0) {
			i_assert(ext_id < reset_id_count &&
				 ext_reset.new_reset_id == reset_ids[ext_id]);
			log_append_buffer(ctx, buf, NULL,
					  MAIL_TRANSACTION_EXT_RESET);
		}
		if (ext_id < hdrs_count && hdrs[ext_id] != NULL)
			log_append_ext_hdr_update(ctx, hdrs[ext_id]);
	}
}

static void log_append_ext_rec_updates(struct log_append_context *ctx)
{
	struct mail_index_transaction *t = ctx->trans;
	ARRAY_TYPE(seq_array) *updates;
	const uint32_t *reset_ids;
	unsigned int ext_id, count, reset_id_count;
	uint32_t reset_id;

	if (!array_is_created(&t->ext_rec_updates)) {
		updates = NULL;
		count = 0;
	} else {
		updates = array_get_modifiable(&t->ext_rec_updates, &count);
	}

	if (!array_is_created(&t->ext_reset_ids)) {
		reset_ids = NULL;
		reset_id_count = 0;
	} else {
		reset_ids = array_get_modifiable(&t->ext_reset_ids,
						 &reset_id_count);
	}

	for (ext_id = 0; ext_id < count; ext_id++) {
		if (!array_is_created(&updates[ext_id]))
			continue;

		reset_id = ext_id < reset_id_count ? reset_ids[ext_id] : 0;
		log_append_ext_intro(ctx, ext_id, reset_id);

		log_append_buffer(ctx, updates[ext_id].arr.buffer, NULL,
				  MAIL_TRANSACTION_EXT_REC_UPDATE);
	}
}

static void
log_append_keyword_update(struct log_append_context *ctx,
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

	log_append_buffer(ctx, buffer, hdr_buf,
			  MAIL_TRANSACTION_KEYWORD_UPDATE);
}

static void log_append_keyword_updates(struct log_append_context *ctx)
{
        const struct mail_index_transaction_keyword_update *updates;
	const char *const *keywords;
	buffer_t *hdr_buf;
	unsigned int i, count, keywords_count;

	hdr_buf = buffer_create_dynamic(pool_datastack_create(), 64);

	keywords = array_get_modifiable(&ctx->trans->view->index->keywords,
					&keywords_count);
	updates = array_get_modifiable(&ctx->trans->keyword_updates, &count);
	i_assert(count <= keywords_count);

	for (i = 0; i < count; i++) {
		if (array_is_created(&updates[i].add_seq)) {
			log_append_keyword_update(ctx, hdr_buf,
					MODIFY_ADD, keywords[i],
					updates[i].add_seq.arr.buffer);
		}
		if (array_is_created(&updates[i].remove_seq)) {
			log_append_keyword_update(ctx, hdr_buf,
					MODIFY_REMOVE, keywords[i],
					updates[i].remove_seq.arr.buffer);
		}
	}
}

static void log_append_sync_offset_if_needed(struct log_append_context *ctx)
{
	struct mail_transaction_header_update *u;
	buffer_t *buf;
	uint32_t offset;

	if (ctx->file->max_tail_offset == ctx->file->sync_offset) {
		/* FIXME: when we remove exclusive log locking, we
		   can't rely on this. then write non-changed offset + check
		   real offset + rewrite the new offset if other transactions
		   weren't written in the middle */
		ctx->file->max_tail_offset += ctx->output->used +
			sizeof(struct mail_transaction_header) +
			sizeof(*u) + sizeof(offset);
		ctx->sync_includes_this = TRUE;
	}
	offset = ctx->file->max_tail_offset;

	if (ctx->file->saved_tail_offset == offset)
		return;

	buf = buffer_create_static_hard(pool_datastack_create(),
					sizeof(*u) + sizeof(offset));
	u = buffer_append_space_unsafe(buf, sizeof(*u));
	u->offset = offsetof(struct mail_index_header, log_file_tail_offset);
	u->size = sizeof(offset);
	buffer_append(buf, &offset, sizeof(offset));

	log_append_buffer(ctx, buf, NULL, MAIL_TRANSACTION_HEADER_UPDATE);
}

static int
mail_transaction_log_append_locked(struct mail_index_transaction *t,
				   uint32_t *log_file_seq_r,
				   uoff_t *log_file_offset_r)
{
	struct mail_index_view *view = t->view;
	struct mail_index *index;
	struct mail_transaction_log *log;
	struct mail_transaction_log_file *file;
	struct log_append_context ctx;
	uoff_t append_offset;

	index = mail_index_view_get_index(view);
	log = index->log;

	if (t->reset) {
		/* Reset the whole index, preserving only indexid. Begin by
		   rotating the log. We don't care if we skip some non-synced
		   transactions. */
		if (mail_transaction_log_rotate(log, TRUE) < 0)
			return -1;

		if (!t->log_updates && !t->log_ext_updates) {
			/* we only wanted to reset */
			return 0;
		}
	}

	if (!index->log_locked) {
		/* update sync_offset */
		if (mail_transaction_log_file_map(log->head,
						  log->head->sync_offset,
						  (uoff_t)-1) <= 0)
			return -1;
	}

	file = log->head;

	if (file->sync_offset < file->buffer_offset)
		file->sync_offset = file->buffer_offset;

	memset(&ctx, 0, sizeof(ctx));
	ctx.file = file;
	ctx.trans = t;
	ctx.output = buffer_create_dynamic(default_pool, 1024);

	/* send all extension introductions and resizes before appends
	   to avoid resize overhead as much as possible */
        mail_transaction_log_append_ext_intros(&ctx);

	if (t->pre_hdr_changed) {
		log_append_buffer(&ctx,
				  log_get_hdr_update_buffer(t, TRUE),
				  NULL, MAIL_TRANSACTION_HEADER_UPDATE);
	}
	if (array_is_created(&t->appends)) {
		log_append_buffer(&ctx, t->appends.arr.buffer, NULL,
				  MAIL_TRANSACTION_APPEND);
	}
	if (array_is_created(&t->updates)) {
		log_append_buffer(&ctx, t->updates.arr.buffer, NULL,
				  MAIL_TRANSACTION_FLAG_UPDATE);
	}

	if (array_is_created(&t->ext_rec_updates))
		log_append_ext_rec_updates(&ctx);

	/* keyword resets before updates */
	if (array_is_created(&t->keyword_resets)) {
		log_append_buffer(&ctx, t->keyword_resets.arr.buffer,
				  NULL, MAIL_TRANSACTION_KEYWORD_RESET);
	}
	if (array_is_created(&t->keyword_updates))
		log_append_keyword_updates(&ctx);

	if (array_is_created(&t->expunges)) {
		log_append_buffer(&ctx, t->expunges.arr.buffer, NULL,
				  MAIL_TRANSACTION_EXPUNGE);
	}

	if (t->post_hdr_changed) {
		log_append_buffer(&ctx, log_get_hdr_update_buffer(t, FALSE),
				  NULL, MAIL_TRANSACTION_HEADER_UPDATE);
	}

	/* NOTE: mailbox sync offset update must be the last change.
	   it may update the sync offset to include this transaction, so it
	   needs to know this transaction's size */
	if (t->external)
		log_append_sync_offset_if_needed(&ctx);

	if (file->sync_offset < file->last_size) {
		/* there is some garbage at the end of the transaction log
		   (eg. previous write failed). remove it so reader doesn't
		   break because of it. */
		buffer_set_used_size(file->buffer,
				     file->sync_offset - file->buffer_offset);
		if (!MAIL_TRANSACTION_LOG_FILE_IN_MEMORY(file)) {
			if (ftruncate(file->fd, file->sync_offset) < 0) {
				mail_index_file_set_syscall_error(index,
					file->filepath, "ftruncate()");
			}
		}
	}

	append_offset = file->sync_offset;
	if (log_buffer_write(&ctx) < 0) {
		buffer_free(ctx.output);
		return -1;
	}
	buffer_free(ctx.output);

	if (t->hide_transaction) {
		/* mark the area covered by this transaction hidden */
		mail_index_view_add_hidden_transaction(view, file->hdr.file_seq,
			append_offset, file->sync_offset - append_offset);
	}

	*log_file_seq_r = file->hdr.file_seq;
	*log_file_offset_r = file->sync_offset;
	return 0;
}

int mail_transaction_log_append(struct mail_index_transaction *t,
				uint32_t *log_file_seq_r,
				uoff_t *log_file_offset_r)
{
	struct mail_index *index;
	int ret;

	*log_file_seq_r = 0;
	*log_file_offset_r = 0;

	if (!t->log_updates && !t->log_ext_updates && !t->reset) {
		/* nothing to append */
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
