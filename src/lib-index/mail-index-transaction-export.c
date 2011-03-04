/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-index-private.h"
#include "mail-index-modseq.h"
#include "mail-transaction-log-private.h"
#include "mail-index-transaction-private.h"

struct mail_index_export_context {
	struct mail_index_transaction *trans;
	struct mail_transaction_log_append_ctx *append_ctx;
};

static void
log_append_buffer(struct mail_index_export_context *ctx,
		  const buffer_t *buf, enum mail_transaction_type type)
{
	mail_transaction_log_append_add(ctx->append_ctx, type,
					buf->data, buf->used);
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

static void log_append_ext_intro(struct mail_index_export_context *ctx,
				 uint32_t ext_id, uint32_t reset_id)
{
	struct mail_index_transaction *t = ctx->trans;
	const struct mail_index_registered_ext *rext;
        struct mail_transaction_ext_intro *intro, *resizes;
	buffer_t *buf;
	uint32_t idx;
	unsigned int count;

	i_assert(ext_id != (uint32_t)-1);

	if (t->reset ||
	    !mail_index_map_get_ext_idx(t->view->index->map, ext_id, &idx)) {
		/* new extension */
		idx = (uint32_t)-1;
	}

	rext = array_idx(&t->view->index->extensions, ext_id);
	if (!array_is_created(&t->ext_resizes)) {
		resizes = NULL;
		count = 0;
	} else {
		resizes = array_get_modifiable(&t->ext_resizes, &count);
	}

	buf = buffer_create_dynamic(pool_datastack_create(), 128);
	if (ext_id < count && resizes[ext_id].name_size != 0) {
		/* we're resizing the extension. use the resize struct. */
		intro = &resizes[ext_id];

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
		intro->flags = MAIL_TRANSACTION_EXT_INTRO_FLAG_NO_SHRINK;
		intro->name_size = idx != (uint32_t)-1 ? 0 :
			strlen(rext->name);
	}
	if (reset_id != 0) {
		/* we're going to reset this extension in this transaction */
		intro->reset_id = reset_id;
	} else if (idx != (uint32_t)-1) {
		/* use the existing reset_id */
		const struct mail_index_ext *map_ext =
			array_idx(&t->view->index->map->extensions, idx);
		intro->reset_id = map_ext->reset_id;
	} else {
		/* new extension, reset_id defaults to 0 */
	}
	buffer_append(buf, rext->name, intro->name_size);
	if ((buf->used % 4) != 0)
		buffer_append_zero(buf, 4 - (buf->used % 4));

	if (ctx->append_ctx->new_highest_modseq == 0 &&
	    strcmp(rext->name, MAIL_INDEX_MODSEQ_EXT_NAME) == 0) {
		/* modseq tracking started */
		ctx->append_ctx->new_highest_modseq = 1;
	}

	log_append_buffer(ctx, buf, MAIL_TRANSACTION_EXT_INTRO);
}

static void
log_append_ext_hdr_update(struct mail_index_export_context *ctx,
			const struct mail_index_transaction_ext_hdr_update *hdr)
{
	buffer_t *buf;
	const unsigned char *data, *mask;
	struct mail_transaction_ext_hdr_update u;
	struct mail_transaction_ext_hdr_update32 u32;
	size_t offset;
	bool started = FALSE, use_32 = hdr->alloc_size >= 65536;

	memset(&u, 0, sizeof(u));
	memset(&u32, 0, sizeof(u32));

	data = hdr->data;
	mask = hdr->mask;

	buf = buffer_create_dynamic(pool_datastack_create(), 256);
	for (offset = 0; offset <= hdr->alloc_size; offset++) {
		if (offset < hdr->alloc_size && mask[offset] != 0) {
			if (!started) {
				u32.offset = offset;
				started = TRUE;
			}
		} else {
			if (started) {
				u32.size = offset - u32.offset;
				if (use_32)
					buffer_append(buf, &u32, sizeof(u32));
				else {
					u.offset = u32.offset;
					u.size = u32.size;
					buffer_append(buf, &u, sizeof(u));
				}
				buffer_append(buf, data + u32.offset, u32.size);
				started = FALSE;
			}
		}
	}
	if (buf->used % 4 != 0)
		buffer_append_zero(buf, 4 - buf->used % 4);
	log_append_buffer(ctx, buf, use_32 ? MAIL_TRANSACTION_EXT_HDR_UPDATE32 :
			  MAIL_TRANSACTION_EXT_HDR_UPDATE);
}

static void
mail_transaction_log_append_ext_intros(struct mail_index_export_context *ctx)
{
	struct mail_index_transaction *t = ctx->trans;
        const struct mail_transaction_ext_intro *resize;
	const struct mail_index_transaction_ext_hdr_update *hdrs;
	struct mail_transaction_ext_reset ext_reset;
	unsigned int resize_count, ext_count = 0;
	unsigned int hdrs_count, reset_id_count, reset_count;
	uint32_t ext_id, reset_id;
	const struct mail_transaction_ext_reset *reset;
	const uint32_t *reset_ids;
	buffer_t reset_buf;

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
	buffer_create_data(&reset_buf, &ext_reset, sizeof(ext_reset));
	buffer_set_used_size(&reset_buf, sizeof(ext_reset));

	for (ext_id = 0; ext_id < ext_count; ext_id++) {
		if (ext_id < reset_count)
			ext_reset = reset[ext_id];
		else
			ext_reset.new_reset_id = 0;
		if ((ext_id < resize_count && resize[ext_id].name_size) ||
		    ext_reset.new_reset_id != 0 ||
		    (ext_id < hdrs_count && hdrs[ext_id].alloc_size > 0)) {
			if (ext_reset.new_reset_id != 0) {
				/* we're going to reset this extension
				   immediately after the intro */
				reset_id = 0;
			} else {
				reset_id = ext_id < reset_id_count ?
					reset_ids[ext_id] : 0;
			}
			log_append_ext_intro(ctx, ext_id, reset_id);
		}
		if (ext_reset.new_reset_id != 0) {
			i_assert(ext_id < reset_id_count &&
				 ext_reset.new_reset_id == reset_ids[ext_id]);
			log_append_buffer(ctx, &reset_buf,
					  MAIL_TRANSACTION_EXT_RESET);
		}
		if (ext_id < hdrs_count && hdrs[ext_id].alloc_size > 0) {
			T_BEGIN {
				log_append_ext_hdr_update(ctx, &hdrs[ext_id]);
			} T_END;
		}
	}
}

static void log_append_ext_recs(struct mail_index_export_context *ctx,
				const ARRAY_TYPE(seq_array_array) *arr,
				enum mail_transaction_type type)
{
	struct mail_index_transaction *t = ctx->trans;
	const ARRAY_TYPE(seq_array) *updates;
	const uint32_t *reset_ids;
	unsigned int ext_id, count, reset_id_count;
	uint32_t reset_id;

	if (!array_is_created(&t->ext_reset_ids)) {
		reset_ids = NULL;
		reset_id_count = 0;
	} else {
		reset_ids = array_get_modifiable(&t->ext_reset_ids,
						 &reset_id_count);
	}

	updates = array_get(arr, &count);
	for (ext_id = 0; ext_id < count; ext_id++) {
		if (!array_is_created(&updates[ext_id]))
			continue;

		reset_id = ext_id < reset_id_count ? reset_ids[ext_id] : 0;
		log_append_ext_intro(ctx, ext_id, reset_id);

		log_append_buffer(ctx, updates[ext_id].arr.buffer, type);
	}
}

static void
log_append_keyword_update(struct mail_index_export_context *ctx,
			  buffer_t *tmp_buf, enum modify_type modify_type,
			  const char *keyword, const buffer_t *uid_buffer)
{
	struct mail_transaction_keyword_update kt_hdr;

	i_assert(uid_buffer->used > 0);

	memset(&kt_hdr, 0, sizeof(kt_hdr));
	kt_hdr.modify_type = modify_type;
	kt_hdr.name_size = strlen(keyword);

	buffer_set_used_size(tmp_buf, 0);
	buffer_append(tmp_buf, &kt_hdr, sizeof(kt_hdr));
	buffer_append(tmp_buf, keyword, kt_hdr.name_size);
	if ((tmp_buf->used % 4) != 0)
		buffer_append_zero(tmp_buf, 4 - (tmp_buf->used % 4));
	buffer_append(tmp_buf, uid_buffer->data, uid_buffer->used);

	log_append_buffer(ctx, tmp_buf, MAIL_TRANSACTION_KEYWORD_UPDATE);
}

static enum mail_index_sync_type
log_append_keyword_updates(struct mail_index_export_context *ctx)
{
        const struct mail_index_transaction_keyword_update *updates;
	const char *const *keywords;
	buffer_t *tmp_buf;
	enum mail_index_sync_type change_mask = 0;
	unsigned int i, count, keywords_count;

	tmp_buf = buffer_create_dynamic(pool_datastack_create(), 64);

	keywords = array_get_modifiable(&ctx->trans->view->index->keywords,
					&keywords_count);
	updates = array_get_modifiable(&ctx->trans->keyword_updates, &count);
	i_assert(count <= keywords_count);

	for (i = 0; i < count; i++) {
		if (array_is_created(&updates[i].add_seq) &&
		    array_count(&updates[i].add_seq) > 0) {
			change_mask |= MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD;
			log_append_keyword_update(ctx, tmp_buf,
					MODIFY_ADD, keywords[i],
					updates[i].add_seq.arr.buffer);
		}
		if (array_is_created(&updates[i].remove_seq) &&
		    array_count(&updates[i].remove_seq) > 0) {
			change_mask |= MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE;
			log_append_keyword_update(ctx, tmp_buf,
					MODIFY_REMOVE, keywords[i],
					updates[i].remove_seq.arr.buffer);
		}
	}
	return change_mask;
}

void mail_index_transaction_export(struct mail_index_transaction *t,
				   struct mail_transaction_log_append_ctx *append_ctx)
{
	static uint8_t null4[4] = { 0, 0, 0, 0 };
	enum mail_index_sync_type change_mask = 0;
	struct mail_index_export_context ctx;

	memset(&ctx, 0, sizeof(ctx));
	ctx.trans = t;
	ctx.append_ctx = append_ctx;

	if (t->index_undeleted) {
		i_assert(!t->index_deleted);
		mail_transaction_log_append_add(ctx.append_ctx,
			MAIL_TRANSACTION_INDEX_UNDELETED, &null4, 4);
	}

	/* send all extension introductions and resizes before appends
	   to avoid resize overhead as much as possible */
        mail_transaction_log_append_ext_intros(&ctx);

	if (t->pre_hdr_changed) {
		log_append_buffer(&ctx, log_get_hdr_update_buffer(t, TRUE),
				  MAIL_TRANSACTION_HEADER_UPDATE);
	}
	if (array_is_created(&t->appends)) {
		change_mask |= MAIL_INDEX_SYNC_TYPE_APPEND;
		log_append_buffer(&ctx, t->appends.arr.buffer,
				  MAIL_TRANSACTION_APPEND);
	}

	if (array_is_created(&t->updates)) {
		change_mask |= MAIL_INDEX_SYNC_TYPE_FLAGS;
		log_append_buffer(&ctx, t->updates.arr.buffer, 
				  MAIL_TRANSACTION_FLAG_UPDATE);
	}

	if (array_is_created(&t->ext_rec_updates)) {
		log_append_ext_recs(&ctx, &t->ext_rec_updates,
				    MAIL_TRANSACTION_EXT_REC_UPDATE);
	}
	if (array_is_created(&t->ext_rec_atomics)) {
		log_append_ext_recs(&ctx, &t->ext_rec_atomics,
				    MAIL_TRANSACTION_EXT_ATOMIC_INC);
	}

	/* keyword resets before updates */
	if (array_is_created(&t->keyword_resets)) {
		change_mask |= MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET;
		log_append_buffer(&ctx, t->keyword_resets.arr.buffer,
				  MAIL_TRANSACTION_KEYWORD_RESET);
	}
	if (array_is_created(&t->keyword_updates))
		change_mask |= log_append_keyword_updates(&ctx);
	/* keep modseq updates almost last */
	if (array_is_created(&t->modseq_updates)) {
		log_append_buffer(&ctx, t->modseq_updates.arr.buffer,
				  MAIL_TRANSACTION_MODSEQ_UPDATE);
	}

	if (array_is_created(&t->expunges)) {
		/* non-external expunges are only requests, ignore them when
		   checking fsync_mask */
		if ((t->flags & MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL) != 0)
			change_mask |= MAIL_INDEX_SYNC_TYPE_EXPUNGE;
		log_append_buffer(&ctx, t->expunges.arr.buffer,
				  MAIL_TRANSACTION_EXPUNGE_GUID);
	}

	if (t->post_hdr_changed) {
		log_append_buffer(&ctx, log_get_hdr_update_buffer(t, FALSE),
				  MAIL_TRANSACTION_HEADER_UPDATE);
	}

	if (t->index_deleted) {
		i_assert(!t->index_undeleted);
		mail_transaction_log_append_add(ctx.append_ctx,
						MAIL_TRANSACTION_INDEX_DELETED,
						&null4, 4);
	}

	/* Update the tail offsets only when committing the sync transaction.
	   Other transactions may not know the latest tail offset and might
	   end up shrinking it. (Alternatively the shrinking tail offsets could
	   just be ignored, which would probably work fine too.) */
	append_ctx->append_sync_offset = t->sync_transaction;

	append_ctx->want_fsync =
		(t->view->index->fsync_mask & change_mask) != 0 ||
		(t->flags & MAIL_INDEX_TRANSACTION_FLAG_FSYNC) != 0;
}
