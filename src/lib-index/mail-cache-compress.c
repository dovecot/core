/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "ostream.h"
#include "file-set-size.h"
#include "mail-cache-private.h"

static unsigned char null4[4] = { 0, 0, 0, 0 };

struct mail_cache_copy_context {
	int new_msg;
	char field_seen[32], keep_fields[32], temp_fields[32];
	buffer_t *buffer, *header;
};

static int
mail_cache_compress_callback(struct mail_cache_view *view __attr_unused__,
			     enum mail_cache_field field,
			     const void *data, size_t data_size, void *context)
{
        struct mail_cache_copy_context *ctx = context;
	uint32_t size32;
	int i;

	if (ctx->new_msg) {
		if (!ctx->temp_fields[field])
			return 1;
	} else {
		if (!ctx->keep_fields[field])
			return 1;
	}

	if (ctx->field_seen[field]) {
		/* drop duplicates */
		return 1;
	}
	ctx->field_seen[field] = TRUE;

	for (i = 0; i < MAIL_CACHE_HEADERS_COUNT; i++) {
		if (mail_cache_header_fields[i] == field) {
			/* it's header - save it into header field */
			size32 = buffer_get_used_size(ctx->header);
			if (size32 > 0) {
				/* remove old terminating \0 */
				buffer_set_used_size(ctx->header, size32-1);
			}
			buffer_append(ctx->header, data, data_size);
			return 1;
		}
	}

	buffer_append(ctx->buffer, &field, sizeof(field));

	if (mail_cache_field_sizes[field] == (unsigned int)-1) {
		size32 = (uint32_t)data_size;
		buffer_append(ctx->buffer, &size32, sizeof(size32));
	}

	buffer_append(ctx->buffer, data, data_size);
	if ((data_size & 3) != 0)
		buffer_append(ctx->buffer, null4, 4 - (data_size & 3));
	return 1;
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
        enum mail_cache_field field;
	struct ostream *output;
	const char *str;
	uint32_t size32, message_count, seq, first_new_seq, old_offset;
	uoff_t offset;
	int i, ret, header_idx;

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
	t = mail_index_transaction_begin(view, FALSE);
	output = o_stream_create_file(fd, default_pool, 0, FALSE);

	memset(&hdr, 0, sizeof(hdr));
	hdr.version = MAIL_CACHE_VERSION;
	hdr.indexid = idx_hdr->indexid;
	hdr.file_seq = idx_hdr->cache_file_seq + 1;

	if (cache->hdr != NULL) {
		memcpy(hdr.field_usage_decision_type,
		       cache->hdr->field_usage_decision_type,
		       sizeof(hdr.field_usage_decision_type));
		memcpy(hdr.field_usage_last_used,
		       cache->hdr->field_usage_last_used,
		       sizeof(hdr.field_usage_last_used));
	} else {
		memcpy(hdr.field_usage_decision_type,
		       cache->default_field_usage_decision_type,
		       sizeof(hdr.field_usage_decision_type));
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.buffer = buffer_create_dynamic(default_pool, 4096, (size_t)-1);
	ctx.header = buffer_create_dynamic(default_pool, 4096, (size_t)-1);

	for (i = 0; i < 32; i++) {
		if (hdr.field_usage_decision_type[i] & MAIL_CACHE_DECISION_YES)
			ctx.keep_fields[i] = TRUE;
		else if (hdr.field_usage_decision_type[i] &
			 MAIL_CACHE_DECISION_TEMP) {
			ctx.temp_fields[i] = TRUE;
			ctx.keep_fields[i] = TRUE;
		}
	}

	o_stream_send(output, &hdr, sizeof(hdr));

	/* merge all the header pieces into one. if some message doesn't have
	   all the required pieces, we'll just have to drop them all. */
	for (i = MAIL_CACHE_HEADERS_COUNT-1; i >= 0; i--) {
		str = mail_cache_get_header_fields_str(cache, i);
		if (str != NULL)
			break;
	}

	if (str == NULL)
		header_idx = -1;
	else {
		hdr.header_offsets[0] =
			mail_cache_uint32_to_offset(output->offset);
		header_idx = i;

		size32 = strlen(str) + 1;
		o_stream_send(output, &size32, sizeof(size32));
		o_stream_send(output, str, size32);
		if ((size32 & 3) != 0)
			o_stream_send(output, null4, 4 - (size32 & 3));
	}

	mail_index_reset_cache(t, hdr.file_seq);

	ret = 0;
	for (seq = 1; seq <= message_count; seq++) {
		ctx.new_msg = seq >= first_new_seq;
		buffer_set_used_size(ctx.buffer, 0);
		buffer_set_used_size(ctx.header, 0);
		memset(ctx.field_seen, 0, sizeof(ctx.field_seen));

		memset(&cache_rec, 0, sizeof(cache_rec));
		buffer_append(ctx.buffer, &cache_rec, sizeof(cache_rec));

		mail_cache_foreach(cache_view, seq,
				   mail_cache_compress_callback, &ctx);

		size32 = buffer_get_used_size(ctx.header);
		if (size32 > 0 && ctx.field_seen[header_idx]) {
			field = MAIL_CACHE_HEADERS1;
			buffer_append(ctx.buffer, &field, sizeof(field));
			buffer_append(ctx.buffer, &size32, sizeof(size32));
			buffer_append(ctx.buffer,
				      buffer_get_data(ctx.header, NULL),
				      size32);
			if ((size32 & 3) != 0) {
				buffer_append(ctx.buffer, null4,
					      4 - (size32 & 3));
			}
		}

		if (buffer_get_used_size(ctx.buffer) == sizeof(cache_rec))
			continue;

		mail_index_update_cache(t, seq, hdr.file_seq,
					output->offset, &old_offset);
		o_stream_send(output, buffer_get_data(ctx.buffer, NULL),
			      buffer_get_used_size(ctx.buffer));
	}
	hdr.used_file_size = output->offset;
	buffer_free(ctx.buffer);
	buffer_free(ctx.header);

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

	if (output->offset < MAIL_CACHE_INITIAL_SIZE) {
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

#ifdef DEBUG
	i_warning("Compressing cache file %s", cache->filepath);
#endif

	fd = file_dotlock_open(cache->filepath, NULL, NULL,
			       MAIL_CACHE_LOCK_TIMEOUT,
			       MAIL_CACHE_LOCK_CHANGE_TIMEOUT,
			       MAIL_CACHE_LOCK_IMMEDIATE_TIMEOUT, NULL, NULL);
	if (fd == -1) {
		mail_cache_set_syscall_error(cache, "file_dotlock_open()");
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

			if (mail_cache_map(cache, 0, 0) < 0)
				ret = -1;
		}
	}

	/* headers could have changed, reread them */
	memset(cache->split_offsets, 0, sizeof(cache->split_offsets));
	memset(cache->split_headers, 0, sizeof(cache->split_headers));

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
