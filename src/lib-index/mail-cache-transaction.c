/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "byteorder.h"
#include "file-set-size.h"
#include "mmap-util.h"
#include "mail-cache-private.h"

#include <sys/stat.h>

struct mail_cache_transaction_ctx {
	struct mail_cache *cache;
	struct mail_cache_view *view;
	struct mail_index_transaction *trans;

	unsigned int next_unused_header_lowwater;

	struct mail_cache_record cache_rec;
	buffer_t *cache_data;

	uint32_t first_seq, last_seq, prev_seq;
	enum mail_cache_field prev_fields;
	buffer_t *cache_marks;
};

static const unsigned char *null4[] = { 0, 0, 0, 0 };

int mail_cache_transaction_begin(struct mail_cache_view *view, int nonblock,
				 struct mail_index_transaction *t,
				 struct mail_cache_transaction_ctx **ctx_r)
{
        struct mail_cache_transaction_ctx *ctx;
	int ret;

	i_assert(view->cache->trans_ctx == NULL);

	ret = mail_cache_lock(view->cache, nonblock);
	if (ret <= 0)
		return ret;

	ctx = i_new(struct mail_cache_transaction_ctx, 1);
	ctx->cache = view->cache;
	ctx->view = view;
	ctx->trans = t;
	ctx->cache_data = buffer_create_dynamic(system_pool, 8192, (size_t)-1);

	view->cache->trans_ctx = ctx;
	*ctx_r = ctx;
	return 1;
}

int mail_cache_transaction_end(struct mail_cache_transaction_ctx *ctx)
{
	int ret = 0;

	i_assert(ctx->cache->trans_ctx != NULL);

	(void)mail_cache_transaction_rollback(ctx);

	if (mail_cache_unlock(ctx->cache) < 0)
		ret = -1;

	ctx->cache->trans_ctx = NULL;

	if (ctx->cache_marks != NULL)
		buffer_free(ctx->cache_marks);
	buffer_free(ctx->cache_data);
	i_free(ctx);
	return ret;
}

static void mail_cache_transaction_flush(struct mail_cache_transaction_ctx *ctx)
{
	memset(&ctx->cache_rec, 0, sizeof(ctx->cache_rec));

	ctx->next_unused_header_lowwater = 0;
	ctx->first_seq = ctx->last_seq = ctx->prev_seq = 0;
	ctx->prev_fields = 0;

	if (ctx->cache_marks != NULL)
		buffer_set_used_size(ctx->cache_marks, 0);
	buffer_set_used_size(ctx->cache_data, 0);
}

static void mark_update(buffer_t **buf, uint32_t offset, uint32_t data)
{
	if (*buf == NULL)
		*buf = buffer_create_dynamic(system_pool, 1024, (size_t)-1);

	buffer_append(*buf, &offset, sizeof(offset));
	buffer_append(*buf, &data, sizeof(data));
}

static int write_mark_updates(struct mail_cache *cache)
{
	const uint32_t *data, *end;
	size_t size;

	data = buffer_get_data(cache->trans_ctx->cache_marks, &size);
	end = data + size/sizeof(uint32_t);

	while (data < end) {
		if (pwrite(cache->fd, data+1, sizeof(*data), data[0]) < 0) {
			mail_cache_set_syscall_error(cache, "pwrite()");
			return -1;
		}
		data += 2;
	}
	return 0;
}

static int commit_all_changes(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache *cache = ctx->cache;
	uint32_t cont;

	/* write everything to disk */
	if (msync(cache->mmap_base, cache->mmap_length, MS_SYNC) < 0) {
		mail_cache_set_syscall_error(cache, "msync()");
		return -1;
	}

	if (fdatasync(cache->fd) < 0) {
		mail_cache_set_syscall_error(cache, "fdatasync()");
		return -1;
	}

	if (ctx->cache_marks == NULL ||
	    buffer_get_used_size(ctx->cache_marks) == 0)
		return 0;

	/* now that we're sure it's written, set on all the used-bits */
	if (write_mark_updates(cache) < 0)
		return -1;

	/* update continued records count */
	cont = nbo_to_uint32(cache->hdr->continued_record_count);
	cont += buffer_get_used_size(ctx->cache_marks) /
		(sizeof(uint32_t) * 2);

	if (cont * 100 / cache->index->hdr->messages_count >=
	    COMPRESS_CONTINUED_PERCENTAGE &&
	    cache->used_file_size >= COMPRESS_MIN_SIZE) {
		/* too many continued rows, compress */
		//FIXME:cache->index->set_flags |= MAIL_INDEX_HDR_FLAG_COMPRESS_CACHE;
	}

	cache->hdr->continued_record_count = uint32_to_nbo(cont);
	return 0;
}

static int mail_cache_grow(struct mail_cache *cache, uint32_t size)
{
	struct stat st;
	uoff_t grow_size, new_fsize;

	new_fsize = cache->used_file_size + size;
	grow_size = new_fsize / 100 * MAIL_CACHE_GROW_PERCENTAGE;
	if (grow_size < 16384)
		grow_size = 16384;

	new_fsize += grow_size;
	new_fsize &= ~1023;

	if (fstat(cache->fd, &st) < 0) {
		mail_cache_set_syscall_error(cache, "fstat()");
		return -1;
	}

	if (cache->used_file_size + size <= (uoff_t)st.st_size) {
		/* no need to grow, just update mmap */
		if (mail_cache_mmap_update(cache, 0, 0) < 0)
			return -1;

		i_assert(cache->mmap_length >= (uoff_t)st.st_size);
		return 0;
	}

	if (file_set_size(cache->fd, (off_t)new_fsize) < 0) {
		mail_cache_set_syscall_error(cache, "file_set_size()");
		return -1;
	}

	return mail_cache_mmap_update(cache, 0, 0);
}

static uint32_t mail_cache_append_space(struct mail_cache_transaction_ctx *ctx,
					uint32_t size)
{
	/* NOTE: must be done within transaction or rollback would break it */
	uint32_t offset;

	i_assert((size & 3) == 0);

	offset = ctx->cache->used_file_size;
	if (offset >= 0x40000000) {
		mail_index_set_error(ctx->cache->index,
				     "Cache file too large: %s",
				     ctx->cache->filepath);
		return 0;
	}

	if (offset + size > ctx->cache->mmap_length) {
		if (mail_cache_grow(ctx->cache, size) < 0)
			return 0;
	}

	ctx->cache->used_file_size += size;
	return offset;
}

static int mail_cache_write(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache *cache = ctx->cache;
	struct mail_cache_record *cache_rec, *next;
	const struct mail_index_record *rec;
	uint32_t write_offset, update_offset;
	const void *buf;
	size_t size, buf_size;
	int ret;

	buf = buffer_get_data(ctx->cache_data, &buf_size);

	size = sizeof(*cache_rec) + buf_size;
	ctx->cache_rec.size = uint32_to_nbo(size);

	// FIXME: check cache_offset in transaction
	ret = mail_index_lookup(ctx->view->view, ctx->prev_seq, &rec);
	if (ret < 0)
		return -1;

	if (ret == 0) {
		/* it's been expunged already, do nothing */
	} else {
		write_offset = mail_cache_append_space(ctx, size);
		if (write_offset == 0)
			return -1;

		cache_rec = mail_cache_get_record(cache, rec->cache_offset,
						  TRUE);
		if (cache_rec == NULL) {
			/* first cache record - update offset in index file */
			mail_index_update_cache(ctx->trans, ctx->prev_seq,
						write_offset);
		} else {
			/* find the last cache record */
			while ((next = mail_cache_get_next_record(cache,
								  cache_rec)) != NULL)
				cache_rec = next;

			/* mark next_offset to be updated later */
			update_offset = (char *) &cache_rec->next_offset -
				(char *) cache->mmap_base;
			mark_update(&ctx->cache_marks, update_offset,
				    mail_cache_uint32_to_offset(write_offset));
		}

		memcpy((char *) cache->mmap_base + write_offset,
		       &ctx->cache_rec, sizeof(ctx->cache_rec));
		memcpy((char *) cache->mmap_base + write_offset +
		       sizeof(ctx->cache_rec), buf, buf_size);
	}

	/* reset the write context */
	ctx->prev_seq = 0;
	ctx->prev_fields = 0;

	memset(&ctx->cache_rec, 0, sizeof(ctx->cache_rec));
	buffer_set_used_size(ctx->cache_data, 0);
	return 0;
}

int mail_cache_transaction_commit(struct mail_cache_transaction_ctx *ctx)
{
	int ret = 0;

	if (ctx->prev_seq != 0) {
		if (mail_cache_write(ctx) < 0)
			return -1;
	}

	ctx->cache->hdr->used_file_size =
		uint32_to_nbo(ctx->cache->used_file_size);

	if (commit_all_changes(ctx) < 0)
		ret = -1;

	if (ctx->next_unused_header_lowwater == MAIL_CACHE_HEADERS_COUNT) {
		/* they're all used - compress the cache to get more */
		/* FIXME: ctx->cache->index->set_flags |=
			MAIL_INDEX_HDR_FLAG_COMPRESS_CACHE;*/
	}

	mail_cache_transaction_flush(ctx);
	return ret;
}

void mail_cache_transaction_rollback(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache *cache = ctx->cache;
	unsigned int i;

	/* no need to actually modify the file - we just didn't update
	   used_file_size */
	cache->used_file_size = nbo_to_uint32(cache->hdr->used_file_size);

	/* make sure we don't cache the headers */
	for (i = 0; i < ctx->next_unused_header_lowwater; i++) {
		uint32_t offset = cache->hdr->header_offsets[i];
		if (mail_cache_offset_to_uint32(offset) == 0)
			cache->split_offsets[i] = 1;
	}

	mail_cache_transaction_flush(ctx);
}

static const char *write_header_string(const char *const headers[],
				       uint32_t *size_r)
{
	buffer_t *buffer;
	size_t size;

	buffer = buffer_create_dynamic(pool_datastack_create(),
				       512, (size_t)-1);

	while (*headers != NULL) {
		if (buffer_get_used_size(buffer) != 0)
			buffer_append(buffer, "\n", 1);
		buffer_append(buffer, *headers, strlen(*headers));
		headers++;
	}
	buffer_append(buffer, null4, 1);

	size = buffer_get_used_size(buffer);
	if ((size & 3) != 0) {
		buffer_append(buffer, null4, 4 - (size & 3));
		size += 4 - (size & 3);
	}
	*size_r = size;
	return buffer_get_data(buffer, NULL);
}

int mail_cache_set_header_fields(struct mail_cache_transaction_ctx *ctx,
				 unsigned int idx, const char *const headers[])
{
	struct mail_cache *cache = ctx->cache;
	uint32_t offset, update_offset, size;
	const char *header_str, *prev_str;

	i_assert(*headers != NULL);
	i_assert(idx < MAIL_CACHE_HEADERS_COUNT);
	i_assert(idx >= ctx->next_unused_header_lowwater);
	i_assert(mail_cache_offset_to_uint32(cache->hdr->
					     header_offsets[idx]) == 0);

	t_push();

	header_str = write_header_string(headers, &size);
	if (idx != 0) {
		prev_str = mail_cache_get_header_fields_str(cache, idx-1);
		if (prev_str == NULL) {
			t_pop();
			return FALSE;
		}

		i_assert(strcmp(header_str, prev_str) != 0);
	}

	offset = mail_cache_append_space(ctx, size + sizeof(uint32_t));
	if (offset != 0) {
		memcpy((char *) cache->mmap_base + offset + sizeof(uint32_t),
		       header_str, size);

		size = uint32_to_nbo(size);
		memcpy((char *) cache->mmap_base + offset,
		       &size, sizeof(uint32_t));

		/* update cached headers */
		cache->split_offsets[idx] = cache->hdr->header_offsets[idx];
		cache->split_headers[idx] =
			mail_cache_split_header(cache, header_str);

		/* mark used-bit to be updated later. not really needed for
		   read-safety, but if transaction get rolled back we can't let
		   this point to invalid location. */
		update_offset = (char *) &cache->hdr->header_offsets[idx] -
			(char *) cache->mmap_base;
		mark_update(&ctx->cache_marks, update_offset,
			    mail_cache_uint32_to_offset(offset));

		/* make sure get_header_fields() still works for this header
		   while the transaction isn't yet committed. */
		ctx->next_unused_header_lowwater = idx + 1;
	}

	t_pop();
	return offset > 0;
}

static size_t get_insert_offset(struct mail_cache_transaction_ctx *ctx,
				enum mail_cache_field field)
{
	const unsigned char *buf;
	unsigned int mask;
	uint32_t data_size;
	size_t offset = 0;
	int i;

	buf = buffer_get_data(ctx->cache_data, NULL);

	for (i = 0, mask = 1; i < 31; i++, mask <<= 1) {
		if ((field & mask) != 0)
			return offset;

		if ((ctx->cache_rec.fields & mask) != 0) {
			if ((mask & MAIL_CACHE_FIXED_MASK) != 0)
				data_size = mail_cache_field_sizes[i];
			else {
				memcpy(&data_size, buf + offset,
				       sizeof(data_size));
				data_size = nbo_to_uint32(data_size);
				offset += sizeof(data_size);
			}
			offset += (data_size + 3) & ~3;
		}
	}

	i_unreached();
	return offset;
}

static int get_field_num(enum mail_cache_field field)
{
	unsigned int mask;
	int i;

	for (i = 0, mask = 1; i < 31; i++, mask <<= 1) {
		if ((field & mask) != 0)
			return i;
	}

	return -1;
}

int mail_cache_add(struct mail_cache_transaction_ctx *ctx, uint32_t seq,
		   enum mail_cache_field field,
		   const void *data, size_t data_size)
{
	uint32_t nb_data_size;
	size_t full_size, offset;
	unsigned char *buf;
	int field_num;

	i_assert(data_size > 0);
	i_assert(data_size < (uint32_t)-1);

	nb_data_size = uint32_to_nbo((uint32_t)data_size);

	if ((field & MAIL_CACHE_FIXED_MASK) != 0) {
		field_num = get_field_num(field);
		i_assert(field_num != -1);
		i_assert(mail_cache_field_sizes[field_num] == data_size);
	} else if ((field & MAIL_CACHE_STRING_MASK) != 0) {
		i_assert(((char *) data)[data_size-1] == '\0');
	}

	if (ctx->prev_seq != seq && ctx->prev_seq != 0) {
		if (mail_cache_write(ctx) < 0)
			return -1;
	}
	ctx->prev_seq = seq;

	i_assert((ctx->cache_rec.fields & field) == 0);

	full_size = (data_size + 3) & ~3;
	if ((field & MAIL_CACHE_FIXED_MASK) == 0)
		full_size += sizeof(nb_data_size);

	/* fields must be ordered. find where to insert it. */
	if (field > ctx->cache_rec.fields)
                buf = buffer_append_space_unsafe(ctx->cache_data, full_size);
	else {
		offset = get_insert_offset(ctx, field);
		buffer_copy(ctx->cache_data, offset + full_size,
			    ctx->cache_data, offset, (size_t)-1);
		buf = buffer_get_space_unsafe(ctx->cache_data,
					      offset, full_size);
	}
	ctx->cache_rec.fields |= field;

	/* @UNSAFE */
	if ((field & MAIL_CACHE_FIXED_MASK) == 0) {
		memcpy(buf, &nb_data_size, sizeof(nb_data_size));
		buf += sizeof(nb_data_size);
	}
	memcpy(buf, data, data_size); buf += data_size;
	if ((data_size & 3) != 0)
		memset(buf, 0, 4 - (data_size & 3));

	/* remember the transaction uid range */
	if (seq < ctx->first_seq || ctx->first_seq == 0)
		ctx->first_seq = seq;
	if (seq > ctx->last_seq)
		ctx->last_seq = seq;
	ctx->prev_fields |= field;

	return 0;
}

int mail_cache_delete(struct mail_cache_transaction_ctx *ctx, uint32_t seq)
{
	struct mail_cache *cache = ctx->cache;
	struct mail_cache_record *cache_rec;
	uint32_t deleted_space;
	uoff_t max_del_space;

	cache_rec = mail_cache_lookup(ctx->view, seq, 0);
	if (cache_rec == NULL)
		return 0;

	/* we'll only update the deleted_space in header. we can't really
	   do any actual deleting as other processes might still be using
	   the data. also it's actually useful as some index views are still
	   able to ask cached data from messages that have already been
	   expunged. */
	deleted_space = nbo_to_uint32(cache->hdr->deleted_space);

	do {
		deleted_space -= nbo_to_uint32(cache_rec->size);
		cache_rec = mail_cache_get_next_record(cache, cache_rec);
	} while (cache_rec != NULL);

	/* see if we've reached the max. deleted space in file */
	max_del_space = cache->used_file_size / 100 * COMPRESS_PERCENTAGE;
	if (deleted_space >= max_del_space &&
	    cache->used_file_size >= COMPRESS_MIN_SIZE) {
		//FIXME:cache->index->set_flags |= MAIL_INDEX_HDR_FLAG_COMPRESS_CACHE;
	}

	cache->hdr->deleted_space = uint32_to_nbo(deleted_space);
	return 0;
}

int
mail_cache_transaction_autocommit(struct mail_cache_view *view,
				  uint32_t seq, enum mail_cache_field fields)
{
	struct mail_cache *cache = view->cache;

	if (cache->trans_ctx != NULL &&
	    cache->trans_ctx->first_seq <= seq &&
	    cache->trans_ctx->last_seq >= seq &&
	    (cache->trans_ctx->prev_seq != seq || fields == 0 ||
	     (cache->trans_ctx->prev_fields & fields) != 0)) {
		/* write non-index changes */
		if (cache->trans_ctx->prev_seq == seq) {
			if (mail_cache_write(cache->trans_ctx) < 0)
				return -1;
		}

		if (mail_cache_transaction_commit(cache->trans_ctx) < 0)
			return -1;
	}

	return 0;
}

int mail_cache_update_record_flags(struct mail_cache_view *view, uint32_t seq,
				   enum mail_cache_record_flag flags)
{
	return -1;
}
