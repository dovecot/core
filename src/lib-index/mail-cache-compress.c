/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ostream.h"
#include "nfs-workarounds.h"
#include "read-full.h"
#include "close-keep-errno.h"
#include "file-dotlock.h"
#include "file-cache.h"
#include "file-set-size.h"
#include "mail-cache-private.h"

#include <sys/stat.h>

struct mail_cache_copy_context {
	struct mail_cache *cache;

	buffer_t *buffer, *field_seen;
	ARRAY_DEFINE(bitmask_pos, unsigned int);
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

	pos = array_idx_modifiable(&ctx->bitmask_pos, field->field_idx);
	if (*pos == 0) {
		/* we decided to drop this field */
		return;
	}

	dest = buffer_get_space_unsafe(ctx->buffer, *pos, field->size);
	for (i = 0; i < field->size; i++)
		dest[i] |= ((const unsigned char*)field->data)[i];
}

static void
mail_cache_compress_field(struct mail_cache_copy_context *ctx,
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

	if (cache_field->field_size == (unsigned int)-1) {
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

static uint32_t
get_next_file_seq(struct mail_cache *cache, struct mail_index_view *view)
{
	const struct mail_index_ext *ext;
	uint32_t file_seq;

	ext = mail_index_view_get_ext(view, cache->ext_id);
	file_seq = ext != NULL ? ext->reset_id + 1 : (uint32_t)ioloop_time;

	if (cache->hdr != NULL && file_seq <= cache->hdr->file_seq)
		file_seq = cache->hdr->file_seq + 1;

	return file_seq != 0 ? file_seq : 1;
}

static void
mail_cache_compress_get_fields(struct mail_cache_copy_context *ctx,
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
		int fd, uint32_t *file_seq_r,
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
	unsigned int i, used_fields_count, orig_fields_count;
	time_t max_drop_time;

	view = mail_index_transaction_get_view(trans);
	cache_view = mail_cache_view_open(cache, view);
	output = o_stream_create_fd_file(fd, 0, FALSE);

	memset(&hdr, 0, sizeof(hdr));
	hdr.version = MAIL_CACHE_VERSION;
	hdr.compat_sizeof_uoff_t = sizeof(uoff_t);
	hdr.indexid = cache->index->indexid;
	hdr.file_seq = get_next_file_seq(cache, view);
	o_stream_send(output, &hdr, sizeof(hdr));

	memset(&ctx, 0, sizeof(ctx));
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
		idx_hdr->day_stamp - MAIL_CACHE_FIELD_DROP_SECS;

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
			    (time_t)priv->last_used < max_drop_time &&
			    !priv->adding) {
				dec = MAIL_CACHE_DECISION_NO;
				priv->field.decision = dec;
			}

			/* drop all fields we don't want */
			if ((dec & ~MAIL_CACHE_DECISION_FORCED) ==
			    MAIL_CACHE_DECISION_NO && !priv->adding) {
				priv->used = FALSE;
				priv->last_used = 0;
			}

			ctx.field_file_map[i] = !priv->used ?
				(uint32_t)-1 : used_fields_count++;
		}
	}

	/* get sequence of first message which doesn't need its temp fields
	   removed. */
	first_new_seq = mail_cache_get_first_new_seq(view);
	message_count = mail_index_view_get_messages_count(view);

	i_array_init(ext_offsets, message_count);
	for (seq = 1; seq <= message_count; seq++) {
		if (mail_index_transaction_is_expunged(trans, seq)) {
			(void)array_append_space(ext_offsets);
			continue;
		}

		ctx.new_msg = seq >= first_new_seq;
		buffer_set_used_size(ctx.buffer, 0);

		if (++ctx.field_seen_value == 0) {
			memset(buffer_get_modifiable_data(ctx.field_seen, NULL),
			       0, buffer_get_size(ctx.field_seen));
			ctx.field_seen_value++;
		}

		memset(&cache_rec, 0, sizeof(cache_rec));
		buffer_append(ctx.buffer, &cache_rec, sizeof(cache_rec));

		mail_cache_lookup_iter_init(cache_view, seq, &iter);
		while (mail_cache_lookup_iter_next(&iter, &field) > 0)
			mail_cache_compress_field(&ctx, &field);

		cache_rec.size = buffer_get_used_size(ctx.buffer);
		if (cache_rec.size == sizeof(cache_rec)) {
			/* nothing cached */
			ext_offset = 0;
		} else {
			ext_offset = output->offset;
			buffer_write(ctx.buffer, 0, &cache_rec,
				     sizeof(cache_rec));
			o_stream_send(output, ctx.buffer->data, cache_rec.size);
		}

		array_append(ext_offsets, &ext_offset, 1);
	}
	i_assert(orig_fields_count == cache->fields_count);

	hdr.field_header_offset = mail_index_uint32_to_offset(output->offset);
	mail_cache_compress_get_fields(&ctx, used_fields_count);
	o_stream_send(output, ctx.buffer->data, ctx.buffer->used);

	hdr.used_file_size = output->offset;
	buffer_free(&ctx.buffer);
	buffer_free(&ctx.field_seen);

	o_stream_seek(output, 0);
	o_stream_send(output, &hdr, sizeof(hdr));

	mail_cache_view_close(cache_view);

	if (o_stream_flush(output) < 0) {
		errno = output->stream_errno;
		mail_cache_set_syscall_error(cache, "o_stream_flush()");
		o_stream_destroy(&output);
		array_free(ext_offsets);
		return -1;
	}

	if (hdr.used_file_size < MAIL_CACHE_INITIAL_SIZE) {
		/* grow the file some more. doesn't matter if it fails */
		(void)file_set_size(fd, MAIL_CACHE_INITIAL_SIZE);
	}

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

static int mail_cache_compress_has_file_changed(struct mail_cache *cache)
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
		close_keep_errno(fd);

		if (ret >= 0) {
			if (ret == 0)
				return 0;
			if (cache->need_compress_file_seq == 0) {
				/* previously it didn't exist */
				return 1;
			}
			return hdr.file_seq != cache->need_compress_file_seq;
		} else if (errno != ESTALE || i >= NFS_ESTALE_RETRY_COUNT) {
			mail_cache_set_syscall_error(cache, "read()");
			return -1;
		}
	}
}

static int mail_cache_compress_locked(struct mail_cache *cache,
				      struct mail_index_transaction *trans,
				      bool *unlock)
{
	struct dotlock *dotlock;
	struct stat st;
	mode_t old_mask;
	uint32_t file_seq, old_offset;
	ARRAY_TYPE(uint32_t) ext_offsets;
	const uint32_t *offsets;
	unsigned int i, count;
	int fd, ret;

	/* get the latest info on fields */
	if (mail_cache_header_fields_read(cache) < 0)
		return -1;

	old_mask = umask(cache->index->mode ^ 0666);
	fd = file_dotlock_open(&cache->dotlock_settings, cache->filepath,
			       DOTLOCK_CREATE_FLAG_NONBLOCK, &dotlock);
	umask(old_mask);

	if (fd == -1) {
		if (errno != EAGAIN)
			mail_cache_set_syscall_error(cache, "file_dotlock_open()");
		return -1;
	}

	if ((ret = mail_cache_compress_has_file_changed(cache)) != 0) {
		if (ret < 0)
			return -1;

		/* was just compressed, forget this */
		cache->need_compress_file_seq = 0;
		file_dotlock_delete(&dotlock);

		if (*unlock) {
			(void)mail_cache_unlock(cache);
			*unlock = FALSE;
		}

		return mail_cache_reopen(cache);
	}

	mail_index_fchown(cache->index, fd,
			  file_dotlock_get_lock_path(dotlock));

	if (mail_cache_copy(cache, trans, fd, &file_seq, &ext_offsets) < 0) {
		/* the fields may have been updated in memory already.
		   reverse those changes by re-reading them from file. */
		if (mail_cache_header_fields_read(cache) < 0)
			return -1;
		(void)file_dotlock_delete(&dotlock);
		return -1;
	}

	if (fstat(fd, &st) < 0) {
		mail_cache_set_syscall_error(cache, "fstat()");
		(void)file_dotlock_delete(&dotlock);
		return -1;
	}

	if (file_dotlock_replace(&dotlock,
				 DOTLOCK_REPLACE_FLAG_DONT_CLOSE_FD) < 0) {
		mail_cache_set_syscall_error(cache,
					     "file_dotlock_replace()");
		(void)close(fd);
		array_free(&ext_offsets);
		return -1;
	}

	/* once we're sure that the compression was successful,
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
		(void)mail_cache_unlock(cache);
		*unlock = FALSE;
	}

	mail_cache_file_close(cache);
	cache->fd = fd;
	cache->st_ino = st.st_ino;
	cache->st_dev = st.st_dev;
	cache->field_header_write_pending = FALSE;

	if (cache->file_cache != NULL)
		file_cache_set_fd(cache->file_cache, cache->fd);

	if (mail_cache_map(cache, 0, 0) < 0)
		return -1;
	if (mail_cache_header_fields_read(cache) < 0)
		return -1;

	cache->need_compress_file_seq = 0;
	return 0;
}

int mail_cache_compress(struct mail_cache *cache,
			struct mail_index_transaction *trans)
{
	bool unlock = FALSE;
	int ret;

	i_assert(!cache->compressing);

	if (MAIL_INDEX_IS_IN_MEMORY(cache->index) || cache->index->readonly)
		return 0;

	if (cache->index->lock_method == FILE_LOCK_METHOD_DOTLOCK) {
		/* we're using dotlocking, cache file creation itself creates
		   the dotlock file we need. */
		if (!MAIL_CACHE_IS_UNUSABLE(cache)) {
			mail_index_flush_read_cache(cache->index,
						    cache->filepath, cache->fd,
						    FALSE);
		}
	} else {
		switch (mail_cache_try_lock(cache)) {
		case -1:
			return -1;
		case 0:
			/* couldn't lock, either it's broken or doesn't exist.
			   just start creating it. */
			break;
		default:
			/* locking succeeded. */
			unlock = TRUE;
		}
	}
	cache->compressing = TRUE;
	ret = mail_cache_compress_locked(cache, trans, &unlock);
	cache->compressing = FALSE;
	if (unlock) {
		if (mail_cache_unlock(cache) < 0)
			ret = -1;
	}
	return ret;
}

bool mail_cache_need_compress(struct mail_cache *cache)
{
	return cache->need_compress_file_seq != 0 &&
		!cache->index->readonly;
}
