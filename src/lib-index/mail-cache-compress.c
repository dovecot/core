/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "ostream.h"
#include "file-cache.h"
#include "file-set-size.h"
#include "mail-cache-private.h"

struct mail_cache_copy_context {
	int new_msg;
	buffer_t *buffer, *field_seen;
	uint8_t field_seen_value;
};

static void mail_cache_merge_bitmask(struct mail_cache *cache, buffer_t *buffer,
				     uint32_t field, const void *data,
				     size_t data_size)
{
	void *buf_data;
	uint32_t buf_field;
	unsigned int i, buf_data_size;
	size_t pos, buf_size;

	buf_data = buffer_get_modifyable_data(buffer, &buf_size);
	for (pos = sizeof(struct mail_cache_record); pos < buf_size; ) {
		buf_field = *((uint32_t *)PTR_OFFSET(buf_data, pos));
		pos += sizeof(uint32_t);
		i_assert(buf_field < cache->fields_count);

		buf_data_size = cache->fields[buf_field].field.field_size;
		if (buf_data_size == (unsigned int)-1) {
			buf_data_size =
				*((uint32_t *)PTR_OFFSET(buf_data, pos));
			pos += sizeof(uint32_t);
		}

		if (buf_field == field) {
			/* @UNSAFE: found it, do the merging */
			unsigned char *dest = PTR_OFFSET(buf_data, pos);

			i_assert(buf_data_size == data_size);
			i_assert(pos + buf_data_size <= buf_size);
			for (i = 0; i < buf_data_size; i++)
				dest[i] |= ((const unsigned char*)data)[i];
			break;
		}
		pos += (data_size + 3) & ~3;
		i_assert(pos <= buf_size);
	}
}

static int
mail_cache_compress_callback(struct mail_cache_view *view, uint32_t field,
			     const void *data, size_t data_size, void *context)
{
	struct mail_cache_copy_context *ctx = context;
        struct mail_cache_field *cache_field;
	enum mail_cache_decision_type dec;
	uint8_t *field_seen;
	uint32_t size32;

	cache_field = &view->cache->fields[field].field;

	field_seen = buffer_get_space_unsafe(ctx->field_seen, field, 1);
	if (*field_seen == ctx->field_seen_value) {
		/* duplicate */
		if (cache_field->type == MAIL_CACHE_FIELD_BITMASK) {
			mail_cache_merge_bitmask(view->cache, ctx->buffer,
						 field, data, data_size);
		}
		return 1;
	}
	*field_seen = ctx->field_seen_value;

	dec = cache_field->decision & ~MAIL_CACHE_DECISION_FORCED;
	if (ctx->new_msg) {
		if (dec == MAIL_CACHE_DECISION_NO)
			return 1;
	} else {
		if (dec != MAIL_CACHE_DECISION_YES)
			return 1;
	}

	buffer_append(ctx->buffer, &field, sizeof(field));

	if (cache_field->field_size == (unsigned int)-1) {
		size32 = (uint32_t)data_size;
		buffer_append(ctx->buffer, &size32, sizeof(size32));
	}

	buffer_append(ctx->buffer, data, data_size);
	if ((data_size & 3) != 0)
		buffer_append(ctx->buffer, null4, 4 - (data_size & 3));
	return 1;
}

static uint32_t
get_next_file_seq(struct mail_cache *cache, struct mail_index_view *view)
{
	const struct mail_index_ext *ext;
	uint32_t file_seq;

	ext = mail_index_view_get_ext(view, cache->ext_id);
	file_seq = ext != NULL ? ext->reset_id + 1 : (uint32_t)ioloop_time;
	return file_seq != 0 ? file_seq : 1;
}

static int
mail_cache_copy(struct mail_cache *cache, struct mail_index_view *view, int fd)
{
        struct mail_cache_copy_context ctx;
	struct mail_cache_view *cache_view;
	struct mail_index_transaction *t;
	const struct mail_index_header *idx_hdr;
	struct mail_cache_header hdr;
	struct mail_cache_record cache_rec;
	struct ostream *output;
	buffer_t *buffer;
	uint32_t i, message_count, seq, first_new_seq, old_offset;
	uoff_t offset;

	/* get sequence of first message which doesn't need it's temp fields
	   removed. */
	if (mail_index_get_header(view, &idx_hdr) < 0)
		return -1;
	if (idx_hdr->day_first_uid[7] == 0) {
		first_new_seq = 1;
		message_count = mail_index_view_get_message_count(view);
	} else {
		if (mail_index_lookup_uid_range(view, idx_hdr->day_first_uid[7],
						(uint32_t)-1, &first_new_seq,
						&message_count) < 0)
			return -1;
		if (first_new_seq == 0)
			first_new_seq = message_count+1;
	}

	cache_view = mail_cache_view_open(cache, view);
	t = mail_index_transaction_begin(view, FALSE, TRUE);
	output = o_stream_create_file(fd, default_pool, 0, FALSE);

	memset(&hdr, 0, sizeof(hdr));
	hdr.version = MAIL_CACHE_VERSION;
	hdr.indexid = idx_hdr->indexid;
	hdr.file_seq = get_next_file_seq(cache, view);
	o_stream_send(output, &hdr, sizeof(hdr));

	memset(&ctx, 0, sizeof(ctx));
	ctx.buffer = buffer_create_dynamic(default_pool, 4096);
	ctx.field_seen = buffer_create_dynamic(default_pool, 64);
	ctx.field_seen_value = 0;

	mail_index_ext_reset(t, cache->ext_id, hdr.file_seq);

	for (seq = 1; seq <= message_count; seq++) {
		ctx.new_msg = seq >= first_new_seq;
		buffer_set_used_size(ctx.buffer, 0);

		if (++ctx.field_seen_value == 0) {
			memset(buffer_get_modifyable_data(ctx.field_seen, NULL),
			       0, buffer_get_size(ctx.field_seen));
			ctx.field_seen_value++;
		}

		memset(&cache_rec, 0, sizeof(cache_rec));
		buffer_append(ctx.buffer, &cache_rec, sizeof(cache_rec));

		(void)mail_cache_foreach(cache_view, seq,
					 mail_cache_compress_callback, &ctx);

		cache_rec.size = buffer_get_used_size(ctx.buffer);
		if (cache_rec.size == sizeof(cache_rec))
			continue;

		mail_index_update_ext(t, seq, cache->ext_id, &output->offset,
				      &old_offset);

		buffer_write(ctx.buffer, 0, &cache_rec, sizeof(cache_rec));
		o_stream_send(output, ctx.buffer->data, cache_rec.size);
	}

	if (cache->fields_count != 0) {
		hdr.field_header_offset =
			mail_index_uint32_to_offset(output->offset);

		/* we wrote everything using our internal field ids. so we want
		   mail_cache_header_fields_get() to use them and ignore any
		   existing id mappings in the old cache file. */
		cache->file_fields_count = 0;
		for (i = 0; i < cache->fields_count; i++)
                        cache->field_file_map[i] = (uint32_t)-1;

		t_push();
		buffer = buffer_create_dynamic(pool_datastack_create(), 256);
		mail_cache_header_fields_get(cache, buffer);
		o_stream_send(output, buffer_get_data(buffer, NULL),
			      buffer_get_used_size(buffer));
		t_pop();
	}

	hdr.used_file_size = output->offset;
	buffer_free(ctx.buffer);
	buffer_free(ctx.field_seen);

	o_stream_seek(output, 0);
	o_stream_send(output, &hdr, sizeof(hdr));

	mail_cache_view_close(cache_view);

	if (o_stream_flush(output) < 0) {
		errno = output->stream_errno;
		mail_cache_set_syscall_error(cache, "o_stream_flush()");
		(void)mail_index_transaction_rollback(t);
		o_stream_unref(output);
		return -1;
	}

	if (hdr.used_file_size < MAIL_CACHE_INITIAL_SIZE) {
		/* grow the file some more. doesn't matter if it fails */
		(void)file_set_size(fd, MAIL_CACHE_INITIAL_SIZE);
	}

	o_stream_unref(output);

	if (fdatasync(fd) < 0) {
		mail_cache_set_syscall_error(cache, "fdatasync()");
		(void)mail_index_transaction_rollback(t);
		return -1;
	}

	return mail_index_transaction_commit(t, &seq, &offset);
}

int mail_cache_compress(struct mail_cache *cache, struct mail_index_view *view)
{
	int fd, ret, locked;

	if ((ret = mail_cache_lock(cache)) < 0)
		return -1;
	locked = ret > 0;

	/* get the latest info on fields */
	if (mail_cache_header_fields_read(cache) < 0) {
		if (locked) mail_cache_unlock(cache);
		return -1;
	}

#ifdef DEBUG
	i_warning("Compressing cache file %s", cache->filepath);
#endif

	fd = file_dotlock_open(cache->filepath, NULL, NULL,
			       MAIL_CACHE_LOCK_TIMEOUT,
			       MAIL_CACHE_LOCK_CHANGE_TIMEOUT,
			       MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "file_dotlock_open()");
		if (locked) mail_cache_unlock(cache);
		return -1;
	}

	// FIXME: check that cache file wasn't just recreated

	ret = 0;
	if (mail_cache_copy(cache, view, fd) < 0) {
		(void)file_dotlock_delete(cache->filepath, NULL, fd);
		ret = -1;
	} else {
		if (file_dotlock_replace(cache->filepath, NULL,
					 -1, FALSE) < 0) {
			mail_cache_set_syscall_error(cache,
						     "file_dotlock_replace()");
			(void)close(fd);
			ret = -1;
		} else {
			mail_cache_file_close(cache);
			cache->fd = fd;

			if (cache->file_cache != NULL)
				file_cache_set_fd(cache->file_cache, cache->fd);

			if (mail_cache_map(cache, 0, 0) < 0)
				ret = -1;
			else if (mail_cache_header_fields_read(cache) < 0)
				ret = -1;
		}
	}

	if (locked)
		mail_cache_unlock(cache);

	if (ret == 0)
                cache->need_compress = FALSE;
	return ret;
}

int mail_cache_need_compress(struct mail_cache *cache)
{
	return cache->need_compress;
}
