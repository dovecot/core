/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ostream.h"
#include "nfs-workarounds.h"
#include "read-full.h"
#include "file-dotlock.h"
#include "file-cache.h"
#include "file-set-size.h"
#include "mail-cache-private.h"

#include <stdio.h>
#include <sys/stat.h>

struct mail_cache_copy_context {
	struct mail_cache *cache;

	buffer_t *buffer, *field_seen;
	ARRAY(unsigned int) bitmask_pos;
	uint32_t *field_file_map;

	uint8_t field_seen_value;
	bool new_msg;
};

static void
mail_cache_merge_bitmask(struct mail_cache_copy_context *ctx,
			 const struct mail_cache_iterate_field *field)
{
	unsigned char *dest;
	unsigned int i, *pos;

	pos = array_idx_get_space(&ctx->bitmask_pos, field->field_idx);
	if (*pos == 0) {
		/* we decided to drop this field */
		return;
	}

	dest = buffer_get_space_unsafe(ctx->buffer, *pos, field->size);
	for (i = 0; i < field->size; i++)
		dest[i] |= ((const unsigned char*)field->data)[i];
}

static void
mail_cache_purge_field(struct mail_cache_copy_context *ctx,
		       const struct mail_cache_iterate_field *field)
{
        struct mail_cache_field *cache_field;
	enum mail_cache_decision_type dec;
	uint32_t file_field_idx, size32;
	uint8_t *field_seen;

	file_field_idx = ctx->field_file_map[field->field_idx];
	if (file_field_idx == (uint32_t)-1)
		return;

	cache_field = &ctx->cache->fields[field->field_idx].field;

	field_seen = buffer_get_space_unsafe(ctx->field_seen,
					     field->field_idx, 1);
	if (*field_seen == ctx->field_seen_value) {
		/* duplicate */
		if (cache_field->type == MAIL_CACHE_FIELD_BITMASK)
			mail_cache_merge_bitmask(ctx, field);
		return;
	}
	*field_seen = ctx->field_seen_value;

	dec = cache_field->decision & ~MAIL_CACHE_DECISION_FORCED;
	if (ctx->new_msg) {
		if (dec == MAIL_CACHE_DECISION_NO)
			return;
	} else {
		if (dec != MAIL_CACHE_DECISION_YES)
			return;
	}

	buffer_append(ctx->buffer, &file_field_idx, sizeof(file_field_idx));

	if (cache_field->field_size == UINT_MAX) {
		size32 = (uint32_t)field->size;
		buffer_append(ctx->buffer, &size32, sizeof(size32));
	}

	if (cache_field->type == MAIL_CACHE_FIELD_BITMASK) {
		/* remember the position in case we need to update it */
		unsigned int pos = ctx->buffer->used;

		array_idx_set(&ctx->bitmask_pos, field->field_idx, &pos);
	}
	buffer_append(ctx->buffer, field->data, field->size);
	if ((field->size & 3) != 0)
		buffer_append_zero(ctx->buffer, 4 - (field->size & 3));
}

static uint32_t get_next_file_seq(struct mail_cache *cache)
{
	const struct mail_index_ext *ext;
	struct mail_index_view *view;
	uint32_t file_seq;

	/* make sure we look up the latest reset_id */
	if (mail_index_refresh(cache->index) < 0)
		return -1;

	view = mail_index_view_open(cache->index);
	ext = mail_index_view_get_ext(view, cache->ext_id);
	file_seq = ext != NULL ? ext->reset_id + 1 : (uint32_t)ioloop_time;

	if (cache->hdr != NULL && file_seq <= cache->hdr->file_seq)
		file_seq = cache->hdr->file_seq + 1;
	mail_index_view_close(&view);

	return file_seq != 0 ? file_seq : 1;
}

static void
mail_cache_purge_get_fields(struct mail_cache_copy_context *ctx,
			    unsigned int used_fields_count)
{
	struct mail_cache *cache = ctx->cache;
	struct mail_cache_field *field;
	unsigned int i, j, idx;

	/* Make mail_cache_header_fields_get() return the fields in
	   the same order as we saved them. */
	memcpy(cache->field_file_map, ctx->field_file_map,
	       sizeof(uint32_t) * cache->fields_count);

	/* reverse mapping */
	cache->file_fields_count = used_fields_count;
	i_free(cache->file_field_map);
	cache->file_field_map = used_fields_count == 0 ? NULL :
		i_new(unsigned int, used_fields_count);
	for (i = j = 0; i < cache->fields_count; i++) {
		idx = cache->field_file_map[i];
		if (idx != (uint32_t)-1) {
			i_assert(idx < used_fields_count &&
				 cache->file_field_map != NULL &&
				 cache->file_field_map[idx] == 0);
			cache->file_field_map[idx] = i;
			j++;
		}

		/* change permanent decisions to temporary decisions.
		   if they're still permanent they'll get updated later. */
		field = &cache->fields[i].field;
		if (field->decision == MAIL_CACHE_DECISION_YES)
			field->decision = MAIL_CACHE_DECISION_TEMP;
	}
	i_assert(j == used_fields_count);

	buffer_set_used_size(ctx->buffer, 0);
	mail_cache_header_fields_get(cache, ctx->buffer);
}

static int
mail_cache_copy(struct mail_cache *cache, struct mail_index_transaction *trans,
		struct event *event, int fd, uint32_t *file_seq_r,
		uoff_t *file_size_r, uint32_t *max_uid_r,
		ARRAY_TYPE(uint32_t) *ext_offsets)
{
        struct mail_cache_copy_context ctx;
	struct mail_cache_lookup_iterate_ctx iter;
	struct mail_cache_iterate_field field;
	struct mail_index_view *view;
	struct mail_cache_view *cache_view;
	const struct mail_index_header *idx_hdr;
	struct mail_cache_header hdr;
	struct mail_cache_record cache_rec;
	struct ostream *output;
	uint32_t message_count, seq, first_new_seq, ext_offset;
	unsigned int i, used_fields_count, orig_fields_count, record_count;
	time_t max_drop_time;

	*max_uid_r = 0;

	/* get the latest info on fields */
	if (mail_cache_header_fields_read(cache) < 0)
		return -1;

	view = mail_index_transaction_get_view(trans);
	cache_view = mail_cache_view_open(cache, view);
	output = o_stream_create_fd_file(fd, 0, FALSE);

	i_zero(&hdr);
	hdr.major_version = MAIL_CACHE_MAJOR_VERSION;
	hdr.minor_version = MAIL_CACHE_MINOR_VERSION;
	hdr.compat_sizeof_uoff_t = sizeof(uoff_t);
	hdr.indexid = cache->index->indexid;
	hdr.file_seq = get_next_file_seq(cache);
	o_stream_nsend(output, &hdr, sizeof(hdr));

	event_add_int(event, "file_seq", hdr.file_seq);
	event_set_name(event, "mail_cache_purge_started");
	e_debug(event, "Purging (new file_seq=%u)", hdr.file_seq);

	i_zero(&ctx);
	ctx.cache = cache;
	ctx.buffer = buffer_create_dynamic(default_pool, 4096);
	ctx.field_seen = buffer_create_dynamic(default_pool, 64);
	ctx.field_seen_value = 0;
	ctx.field_file_map = t_new(uint32_t, cache->fields_count + 1);
	t_array_init(&ctx.bitmask_pos, 32);

	/* @UNSAFE: drop unused fields and create a field mapping for
	   used fields */
	idx_hdr = mail_index_get_header(view);
	max_drop_time = idx_hdr->day_stamp == 0 ? 0 :
		idx_hdr->day_stamp -
		cache->index->optimization_set.cache.unaccessed_field_drop_secs;

	orig_fields_count = cache->fields_count;
	if (cache->file_fields_count == 0) {
		/* creating the initial cache file. add all fields. */
		for (i = 0; i < orig_fields_count; i++)
			ctx.field_file_map[i] = i;
		used_fields_count = i;
	} else {
		for (i = used_fields_count = 0; i < orig_fields_count; i++) {
			struct mail_cache_field_private *priv =
				&cache->fields[i];
			enum mail_cache_decision_type dec =
				priv->field.decision;

			/* if the decision isn't forced and this field hasn't
			   been accessed for a while, drop it */
			if ((dec & MAIL_CACHE_DECISION_FORCED) == 0 &&
			    priv->field.last_used < max_drop_time) {
				dec = MAIL_CACHE_DECISION_NO;
				priv->field.decision = dec;
			}

			/* drop all fields we don't want */
			if ((dec & ~MAIL_CACHE_DECISION_FORCED) ==
			    MAIL_CACHE_DECISION_NO) {
				priv->used = FALSE;
				priv->field.last_used = 0;
			}

			ctx.field_file_map[i] = !priv->used ?
				(uint32_t)-1 : used_fields_count++;
		}
	}

	/* get sequence of first message which doesn't need its temp fields
	   removed. */
	first_new_seq = mail_cache_get_first_new_seq(view);
	message_count = mail_index_view_get_messages_count(view);

	i_array_init(ext_offsets, message_count); record_count = 0;
	for (seq = 1; seq <= message_count; seq++) {
		if (mail_index_transaction_is_expunged(trans, seq)) {
			array_append_zero(ext_offsets);
			continue;
		}

		ctx.new_msg = seq >= first_new_seq;
		buffer_set_used_size(ctx.buffer, 0);

		if (++ctx.field_seen_value == 0) {
			memset(buffer_get_modifiable_data(ctx.field_seen, NULL),
			       0, buffer_get_size(ctx.field_seen));
			ctx.field_seen_value++;
		}
		array_clear(&ctx.bitmask_pos);

		i_zero(&cache_rec);
		buffer_append(ctx.buffer, &cache_rec, sizeof(cache_rec));

		mail_cache_lookup_iter_init(cache_view, seq, &iter);
		while (mail_cache_lookup_iter_next(&iter, &field) > 0)
			mail_cache_purge_field(&ctx, &field);

		if (ctx.buffer->used == sizeof(cache_rec) ||
		    ctx.buffer->used > cache->index->optimization_set.cache.record_max_size) {
			/* nothing cached */
			ext_offset = 0;
		} else {
			mail_index_lookup_uid(view, seq, max_uid_r);
			cache_rec.size = ctx.buffer->used;
			ext_offset = output->offset;
			buffer_write(ctx.buffer, 0, &cache_rec,
				     sizeof(cache_rec));
			o_stream_nsend(output, ctx.buffer->data, cache_rec.size);
			record_count++;
		}

		array_push_back(ext_offsets, &ext_offset);
	}
	i_assert(orig_fields_count == cache->fields_count);

	hdr.record_count = record_count;
	hdr.field_header_offset = mail_index_uint32_to_offset(output->offset);
	mail_cache_purge_get_fields(&ctx, used_fields_count);
	o_stream_nsend(output, ctx.buffer->data, ctx.buffer->used);

	hdr.backwards_compat_used_file_size = output->offset;
	buffer_free(&ctx.buffer);
	buffer_free(&ctx.field_seen);

	(void)o_stream_seek(output, 0);
	o_stream_nsend(output, &hdr, sizeof(hdr));

	mail_cache_view_close(&cache_view);

	if (o_stream_finish(output) < 0) {
		mail_cache_set_syscall_error(cache, "write()");
		o_stream_destroy(&output);
		array_free(ext_offsets);
		return -1;
	}
	*file_size_r = output->offset;
	o_stream_destroy(&output);

	if (cache->index->fsync_mode == FSYNC_MODE_ALWAYS) {
		if (fdatasync(fd) < 0) {
			mail_cache_set_syscall_error(cache, "fdatasync()");
			array_free(ext_offsets);
			return -1;
		}
	}

	*file_seq_r = hdr.file_seq;
	return 0;
}

static int
mail_cache_purge_write(struct mail_cache *cache,
		       struct mail_index_transaction *trans,
		       int fd, const char *temp_path, bool *unlock)
{
	struct event *event;
	struct stat st;
	uint32_t prev_file_seq, file_seq, old_offset, max_uid;
	ARRAY_TYPE(uint32_t) ext_offsets;
	const uint32_t *offsets;
	uoff_t prev_file_size, file_size;
	unsigned int i, count, prev_deleted_records;

	if (cache->hdr == NULL) {
		prev_file_seq = 0;
		prev_file_size = 0;
		prev_deleted_records = 0;
	} else {
		prev_file_seq = cache->hdr->file_seq;
		prev_file_size = cache->last_stat_size;
		prev_deleted_records = cache->hdr->deleted_record_count;
	}
	event = event_create(cache->event);
	event_add_int(event, "prev_file_seq", prev_file_seq);
	event_add_int(event, "prev_file_size", prev_file_size);
	event_add_int(event, "prev_deleted_records", prev_deleted_records);

	if (mail_cache_copy(cache, trans, event, fd, &file_seq, &file_size,
			    &max_uid, &ext_offsets) < 0)
		return -1;

	if (fstat(fd, &st) < 0) {
		mail_cache_set_syscall_error(cache, "fstat()");
		array_free(&ext_offsets);
		return -1;
	}
	if (rename(temp_path, cache->filepath) < 0) {
		mail_cache_set_syscall_error(cache, "rename()");
		array_free(&ext_offsets);
		return -1;
	}

	event_add_int(event, "file_size", file_size);
	event_add_int(event, "max_uid", max_uid);
	event_set_name(event, "mail_cache_purge_finished");
	e_debug(event, "Purging finished, file_seq changed %u -> %u, "
		"size=%"PRIuUOFF_T" -> %"PRIuUOFF_T", max_uid=%u",
		prev_file_seq, file_seq, prev_file_size, file_size, max_uid);
	event_unref(&event);

	/* once we're sure that the purging was successful,
	   update the offsets */
	mail_index_ext_reset(trans, cache->ext_id, file_seq, TRUE);
	offsets = array_get(&ext_offsets, &count);
	for (i = 0; i < count; i++) {
		if (offsets[i] != 0) {
			mail_index_update_ext(trans, i + 1, cache->ext_id,
					      &offsets[i], &old_offset);
		}
	}
	array_free(&ext_offsets);

	if (*unlock) {
		mail_cache_unlock(cache);
		*unlock = FALSE;
	}

	mail_cache_file_close(cache);
	cache->opened = TRUE;
	cache->fd = fd;
	cache->st_ino = st.st_ino;
	cache->st_dev = st.st_dev;
	cache->field_header_write_pending = FALSE;
	return 0;
}

static int
mail_cache_purge_has_file_changed(struct mail_cache *cache,
				  uint32_t purge_file_seq)
{
	struct mail_cache_header hdr;
	unsigned int i;
	int fd, ret;

	for (i = 0;; i++) {
		fd = nfs_safe_open(cache->filepath, O_RDONLY);
		if (fd == -1) {
			if (errno == ENOENT)
				return 0;

			mail_cache_set_syscall_error(cache, "open()");
			return -1;
		}

		ret = read_full(fd, &hdr, sizeof(hdr));
		i_close_fd(&fd);

		if (ret >= 0) {
			if (ret == 0)
				return 0;
			if (purge_file_seq == 0) {
				/* previously it didn't exist or it
				   was unusable and was just unlinked */
				return 1;
			}
			return hdr.file_seq != purge_file_seq ? 1 : 0;
		} else if (errno != ESTALE || i >= NFS_ESTALE_RETRY_COUNT) {
			mail_cache_set_syscall_error(cache, "read()");
			return -1;
		}
	}
}

static int mail_cache_purge_locked(struct mail_cache *cache,
				   uint32_t purge_file_seq,
				   struct mail_index_transaction *trans,
				   bool *unlock)
{
	const char *temp_path;
	int fd, ret;

	/* we've locked the cache purging now. if somebody else had just
	   recreated the cache, reopen the cache and return success. */
	if (purge_file_seq != (uint32_t)-1 &&
	    (ret = mail_cache_purge_has_file_changed(cache, purge_file_seq)) != 0) {
		if (ret < 0)
			return -1;

		/* was just purged, forget this */
		cache->need_purge_file_seq = 0;

		if (*unlock) {
			(void)mail_cache_unlock(cache);
			*unlock = FALSE;
		}

		return mail_cache_reopen(cache) < 0 ? -1 : 0;
	}
	if (cache->fd != -1) {
		/* make sure we have mapped it before reading. */
		if (mail_cache_map_all(cache) <= 0)
			return -1;
	}

	/* we want to recreate the cache. write it first to a temporary file */
	fd = mail_index_create_tmp_file(cache->index, cache->filepath, &temp_path);
	if (fd == -1)
		return -1;
	if (mail_cache_purge_write(cache, trans, fd, temp_path, unlock) < 0) {
		i_close_fd(&fd);
		i_unlink(temp_path);
		return -1;
	}
	if (cache->file_cache != NULL)
		file_cache_set_fd(cache->file_cache, cache->fd);

	if (mail_cache_map_all(cache) <= 0)
		return -1;
	if (mail_cache_header_fields_read(cache) < 0)
		return -1;

	cache->need_purge_file_seq = 0;
	return 0;
}

static int
mail_cache_purge_full(struct mail_cache *cache,
		      struct mail_index_transaction *trans,
		      uint32_t purge_file_seq)
{
	bool unlock = FALSE;
	int ret;

	i_assert(!cache->purging);
	i_assert(cache->index->log_sync_locked);

	if (MAIL_INDEX_IS_IN_MEMORY(cache->index) || cache->index->readonly)
		return 0;

	/* purging isn't very efficient with small read()s */
	if (cache->map_with_read) {
		cache->map_with_read = FALSE;
		if (cache->read_buf != NULL)
			buffer_set_used_size(cache->read_buf, 0);
		cache->hdr = NULL;
		cache->mmap_length = 0;
	}

	/* .log lock already prevents other processes from purging cache at
	   the same time, but locking the cache file itself prevents other
	   processes from doing other changes to it (header changes, adding
	   more cached data). */
	switch (mail_cache_lock(cache)) {
	case -1:
		/* lock timeout or some other error */
		return -1;
	case 0:
		/* cache is broken or doesn't exist.
		   just start creating it. */
		break;
	default:
		/* locking succeeded. */
		unlock = TRUE;
	}
	cache->purging = TRUE;
	ret = mail_cache_purge_locked(cache, purge_file_seq, trans, &unlock);
	cache->purging = FALSE;
	if (unlock)
		mail_cache_unlock(cache);
	i_assert(!cache->hdr_modified);
	if (ret < 0) {
		/* the fields may have been updated in memory already.
		   reverse those changes by re-reading them from file. */
		(void)mail_cache_header_fields_read(cache);
	}
	return ret;
}

int mail_cache_purge_with_trans(struct mail_cache *cache,
				struct mail_index_transaction *trans,
				uint32_t purge_file_seq)
{
	return mail_cache_purge_full(cache, trans, purge_file_seq);
}

int mail_cache_purge(struct mail_cache *cache, uint32_t purge_file_seq)
{
	struct mail_index_view *view;
	struct mail_index_transaction *trans;
	bool lock_log;
	int ret;

	lock_log = !cache->index->log_sync_locked;
	if (lock_log) {
		uint32_t file_seq;
		uoff_t file_offset;

		if (mail_transaction_log_sync_lock(cache->index->log,
						   "mail cache purge",
						   &file_seq, &file_offset) < 0)
			return -1;
	}
	/* make sure we see the latest changes in index */
	ret = mail_index_refresh(cache->index);

	view = mail_index_view_open(cache->index);
	trans = mail_index_transaction_begin(view,
		MAIL_INDEX_TRANSACTION_FLAG_EXTERNAL);
	if (ret < 0)
		;
	else if ((ret = mail_cache_purge_full(cache, trans, purge_file_seq)) < 0)
		mail_index_transaction_rollback(&trans);
	else {
		if (mail_index_transaction_commit(&trans) < 0)
			ret = -1;
	}
	mail_index_view_close(&view);
	if (lock_log) {
		mail_transaction_log_sync_unlock(cache->index->log,
						 "mail cache purge");
	}
	return ret;
}

bool mail_cache_need_purge(struct mail_cache *cache)
{
	return cache->need_purge_file_seq != 0 &&
		(cache->index->flags & MAIL_INDEX_OPEN_FLAG_SAVEONLY) == 0 &&
		!cache->index->readonly;
}
