/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "file-set-size.h"
#include "read-full.h"
#include "write-full.h"
#include "mail-cache-private.h"
#include "mail-index-transaction-private.h"

#include <stddef.h>
#include <sys/stat.h>

struct mail_cache_transaction_ctx {
	struct mail_cache *cache;
	struct mail_cache_view *view;
	struct mail_index_transaction *trans;

	uint32_t update_header_offsets[MAIL_CACHE_HEADERS_COUNT];
	unsigned int next_unused_header_lowwater;

	buffer_t *cache_data, *cache_data_seq;
	uint32_t prev_seq;
	size_t prev_pos;

        buffer_t *reservations;
	uint32_t reserved_space_offset, reserved_space;
	uint32_t last_grow_size;

	uint32_t first_seq, last_seq;
	enum mail_cache_field fields[32];

	unsigned int changes:1;
};

static const unsigned char *null4[] = { 0, 0, 0, 0 };

struct mail_cache_transaction_ctx *
mail_cache_get_transaction(struct mail_cache_view *view,
			   struct mail_index_transaction *t)
{
	struct mail_cache_transaction_ctx *ctx;

	if (t->cache_trans_ctx != NULL)
		return t->cache_trans_ctx;

	ctx = i_new(struct mail_cache_transaction_ctx, 1);
	ctx->cache = view->cache;
	ctx->view = view;
	ctx->trans = t;
	ctx->cache_data =
		buffer_create_dynamic(system_pool, 32768, (size_t)-1);
	ctx->cache_data_seq =
		buffer_create_dynamic(system_pool, 256, (size_t)-1);
	ctx->reservations =
		buffer_create_dynamic(system_pool, 256, (size_t)-1);

	i_assert(view->transaction == NULL);
	view->transaction = ctx;

	t->cache_trans_ctx = ctx;
	return ctx;
}

static void mail_cache_transaction_free(struct mail_cache_transaction_ctx *ctx)
{
	ctx->view->transaction = NULL;

	buffer_free(ctx->cache_data);
	buffer_free(ctx->cache_data_seq);
	buffer_free(ctx->reservations);
	i_free(ctx);
}

static int mail_cache_grow_file(struct mail_cache *cache, size_t size)
{
	struct stat st;
	uoff_t new_fsize, grow_size;

	i_assert(cache->locked);

	/* grow the file */
	new_fsize = cache->hdr_copy.used_file_size + size;
	grow_size = new_fsize / 100 * MAIL_CACHE_GROW_PERCENTAGE;
	if (grow_size < 16384)
		grow_size = 16384;
	new_fsize += grow_size;
	new_fsize &= ~1023;

	if (fstat(cache->fd, &st) < 0) {
		mail_cache_set_syscall_error(cache, "fstat()");
		return -1;
	}

	if ((uoff_t)st.st_size < new_fsize) {
		if (file_set_size(cache->fd, new_fsize) < 0) {
			mail_cache_set_syscall_error(cache, "file_set_size()");
			return -1;
		}
	}
	return 0;
}

static int mail_cache_unlink_hole(struct mail_cache *cache, size_t size,
				  struct mail_cache_hole_header *hole_r)
{
	struct mail_cache_header *hdr = &cache->hdr_copy;
	struct mail_cache_hole_header hole;
	uint32_t offset, prev_offset;

	i_assert(cache->locked);

	offset = hdr->hole_offset; prev_offset = 0;
	while (offset != 0) {
		if (pread_full(cache->fd, &hole, sizeof(hole), offset) <= 0) {
			mail_cache_set_syscall_error(cache, "pread_full()");
			return FALSE;
		}

		if (hole.magic != MAIL_CACHE_HOLE_HEADER_MAGIC) {
			mail_cache_set_corrupted(cache,
				"Invalid magic in hole header");
			return FALSE;
		}

		if (hole.size >= size)
			break;
		offset = hole.next_offset;
	}
	if (offset == 0)
		return FALSE;

	if (prev_offset == 0)
		hdr->hole_offset = hole.next_offset;
	else {
		if (pwrite_full(cache->fd, &hole.next_offset,
				sizeof(hole.next_offset), prev_offset) < 0) {
			mail_cache_set_syscall_error(cache, "pwrite_full()");
			return FALSE;
		}
	}
	hdr->deleted_space -= hole.size;

	hole_r->next_offset = offset;
	hole_r->size = hole.size;
	return TRUE;
}

static void
mail_cache_transaction_add_reservation(struct mail_cache_transaction_ctx *ctx)
{
	buffer_append(ctx->reservations, &ctx->reserved_space_offset,
		      sizeof(ctx->reserved_space_offset));
	buffer_append(ctx->reservations, &ctx->reserved_space,
		      sizeof(ctx->reserved_space));
}

static int
mail_cache_transaction_reserve_more(struct mail_cache_transaction_ctx *ctx,
				    size_t size, int commit)
{
	struct mail_cache *cache = ctx->cache;
	struct mail_cache_header *hdr = &cache->hdr_copy;
	struct mail_cache_hole_header hole;
	uint32_t *buf;

	i_assert(cache->locked);

	if (mail_cache_unlink_hole(cache, size, &hole)) {
		/* found a large enough hole. */
		ctx->reserved_space_offset = hole.next_offset;
		ctx->reserved_space = hole.size;
		mail_cache_transaction_add_reservation(ctx);
		return 0;
	}

	if (MAIL_CACHE_IS_UNUSABLE(cache)) {
		/* mail_cache_unlink_hole() could have noticed corruption */
		return -1;
	}

	if ((uoff_t)hdr->used_file_size + size > (uint32_t)-1) {
		mail_index_set_error(cache->index, "Cache file too large: %s",
				     cache->filepath);
		return -1;
	}

	if (!commit) {
		size = (size + ctx->last_grow_size) * 2;
		if ((uoff_t)hdr->used_file_size + size > (uint32_t)-1)
			size = (uint32_t)-1;
		ctx->last_grow_size = size;
	}

	if (mail_cache_grow_file(ctx->cache, size) < 0)
		return -1;

	if (ctx->reserved_space_offset + ctx->reserved_space ==
	    hdr->used_file_size) {
		/* we can simply grow it */
		ctx->reserved_space = size - ctx->reserved_space;

		/* grow reservation. it's probably the last one in the buffer,
		   but it's not guarateed because we might have used holes
		   as well */
		buf = buffer_get_modifyable_data(ctx->reservations, &size);
		size /= sizeof(uint32_t);
		i_assert(size >= 2);

		do {
			size -= 2;
			if (buf[size] == ctx->reserved_space_offset) {
				buf[size+1] = ctx->reserved_space;
				break;
			}
		} while (size >= 2);
	} else {
		ctx->reserved_space_offset = hdr->used_file_size;
		ctx->reserved_space = size;
		mail_cache_transaction_add_reservation(ctx);
	}

	cache->hdr_modified = TRUE;
	hdr->used_file_size = ctx->reserved_space_offset + ctx->reserved_space;
	return 0;
}

static void
mail_cache_free_space(struct mail_cache *cache, uint32_t offset, uint32_t size)
{
	struct mail_cache_hole_header hole;

	i_assert(cache->locked);

	if (offset + size == cache->hdr_copy.used_file_size) {
		/* we can just set used_file_size back */
		cache->hdr_modified = TRUE;
		cache->hdr_copy.used_file_size = offset;
	} else if (size >= MAIL_CACHE_MIN_HOLE_SIZE) {
		/* set it up as a hole */
		hole.next_offset = cache->hdr_copy.hole_offset;
		hole.size = size;
		hole.magic = MAIL_CACHE_HOLE_HEADER_MAGIC;

		if (pwrite_full(cache->fd, &hole, sizeof(hole), offset) < 0) {
			mail_cache_set_syscall_error(cache, "pwrite_full()");
			return;
		}

		cache->hdr_copy.deleted_space += size;
		cache->hdr_copy.hole_offset = offset;
		cache->hdr_modified = TRUE;
	}
}

static void
mail_cache_transaction_free_space(struct mail_cache_transaction_ctx *ctx)
{
	int locked = ctx->cache->locked;

	if (ctx->reserved_space == 0)
		return;

	if (!locked) {
		if (mail_cache_lock(ctx->cache) <= 0)
			return;
	}

	mail_cache_free_space(ctx->cache, ctx->reserved_space_offset,
			      ctx->reserved_space);

	if (!locked)
		mail_cache_unlock(ctx->cache);
}

static uint32_t
mail_cache_transaction_get_space(struct mail_cache_transaction_ctx *ctx,
				 size_t min_size, size_t max_size,
				 size_t *available_space_r, int commit)
{
	int locked = ctx->cache->locked;
	uint32_t offset;
	size_t size;
	int ret;

	if (min_size > ctx->reserved_space) {
		if (!locked) {
			if (mail_cache_lock(ctx->cache) <= 0)
				return -1;
		}
		ret = mail_cache_transaction_reserve_more(ctx, max_size,
							  commit);
		if (!locked)
			mail_cache_unlock(ctx->cache);

		if (ret < 0)
			return 0;

		size = max_size;
	} else {
		size = I_MIN(max_size, ctx->reserved_space);
	}

	offset = ctx->reserved_space_offset;
	ctx->reserved_space_offset += size;
	ctx->reserved_space -= size;
	if (available_space_r != NULL)
		*available_space_r = size;

	if (size == max_size && commit) {
		/* final commit - see if we can free the rest of the
		   reserved space */
		mail_cache_transaction_free_space(ctx);
	}

	return offset;
}

static int
mail_cache_transaction_flush(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache *cache = ctx->cache;
	const struct mail_cache_record *rec, *tmp_rec;
	const uint32_t *seq;
	uint32_t write_offset, old_offset, rec_pos;
	size_t size, max_size, seq_idx, seq_limit, seq_count;
	int commit;

	commit = ctx->prev_seq == 0;
	if (commit) {
		/* committing, remove the last dummy record */
		buffer_set_used_size(ctx->cache_data, ctx->prev_pos);
	}

	rec = buffer_get_data(ctx->cache_data, &size);
	i_assert(ctx->prev_pos <= size);

	seq = buffer_get_data(ctx->cache_data_seq, &seq_count);
	seq_count /= sizeof(*seq);
	seq_limit = 0;

	for (seq_idx = 0, rec_pos = 0; rec_pos < ctx->prev_pos;) {
		max_size = ctx->prev_pos - rec_pos;
		write_offset = mail_cache_transaction_get_space(ctx, rec->size,
								max_size,
								&max_size,
								commit);
		if (write_offset == 0) {
			/* nothing to write / error */
			return ctx->prev_pos == 0 ? 0 : -1;
		}

		if (rec_pos + max_size < ctx->prev_pos) {
			/* see how much we can really write there */
			tmp_rec = rec;
			for (size = 0; size + tmp_rec->size <= max_size; ) {
				seq_limit++;
				size += tmp_rec->size;
				tmp_rec = CONST_PTR_OFFSET(tmp_rec,
							   tmp_rec->size);
			}
			max_size = size;
		} else {
			seq_limit = seq_count;
		}

		/* write it to file */
		if (pwrite_full(cache->fd, rec, max_size, write_offset) < 0) {
			mail_cache_set_syscall_error(cache, "pwrite_full()");
			return -1;
		}

		/* write the cache_offsets to index file. records' prev_offset
		   is updated to point to old cache record when index is being
		   synced. */
		for (; seq_idx < seq_limit; seq_idx++) {
			mail_index_update_cache(ctx->trans, seq[seq_idx],
						cache->hdr->file_seq,
						write_offset, &old_offset);
			if (old_offset != 0) {
				/* we added records for this message multiple
				   times in this same uncommitted transaction.
				   only the new one will be written to
				   transaction log, we need to do the linking
				   ourself here. */
				if (mail_cache_link(cache, old_offset,
						    write_offset) < 0)
					return -1;
			}

			write_offset += rec->size;
			rec_pos += rec->size;
			rec = CONST_PTR_OFFSET(rec, rec->size);
		}
	}

	/* drop the written data from buffer */
	buffer_copy(ctx->cache_data, 0,
		    ctx->cache_data, ctx->prev_pos, (size_t)-1);
	buffer_set_used_size(ctx->cache_data,
			     buffer_get_used_size(ctx->cache_data) -
			     ctx->prev_pos);
	ctx->prev_pos = 0;

	buffer_set_used_size(ctx->cache_data_seq, 0);
	return 0;
}

static void
mail_cache_transaction_switch_seq(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache_record *rec, new_rec;
	void *data;
	size_t size;

	if (ctx->prev_seq != 0) {
		/* fix record size */
		data = buffer_get_modifyable_data(ctx->cache_data, &size);
		rec = PTR_OFFSET(data, ctx->prev_pos);
		rec->size = size - ctx->prev_pos;
		i_assert(rec->size != 0);

		buffer_append(ctx->cache_data_seq, &ctx->prev_seq,
			      sizeof(ctx->prev_seq));
		ctx->prev_pos = size;
	}

	memset(&new_rec, 0, sizeof(new_rec));
	buffer_append(ctx->cache_data, &new_rec, sizeof(new_rec));

	ctx->prev_seq = 0;
	ctx->changes = TRUE;
}

int mail_cache_transaction_commit(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache *cache = ctx->cache;
	uint32_t offset;
	int i, ret = 0;

	if (!ctx->changes) {
		mail_cache_transaction_free(ctx);
		return 0;
	}

	if (mail_cache_lock(cache) <= 0) {
		mail_cache_transaction_rollback(ctx);
		return -1;
	}

	if (ctx->prev_seq != 0)
                mail_cache_transaction_switch_seq(ctx);

	if (mail_cache_transaction_flush(ctx) < 0)
		ret = -1;

	/* make sure everything's written before updating offsets */
	if (fdatasync(cache->fd) < 0) {
		mail_cache_set_syscall_error(cache, "fdatasync()");
		ret = -1;
	}

	if (ret == 0) {
		for (i = 0; i < MAIL_CACHE_HEADERS_COUNT; i++) {
			offset = ctx->update_header_offsets[i];
			if (offset != 0) {
				cache->hdr_copy.header_offsets[i] =
					mail_cache_uint32_to_offset(offset);
				cache->hdr_modified = TRUE;
			}
		}
	}

	mail_cache_unlock(cache);

	if (ctx->next_unused_header_lowwater == MAIL_CACHE_HEADERS_COUNT) {
		/* they're all used - compress the cache to get more */
		cache->need_compress = TRUE;
	}

	mail_cache_transaction_free(ctx);
	return ret;
}

void mail_cache_transaction_rollback(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache *cache = ctx->cache;
	const uint32_t *buf;
	size_t size;
	unsigned int i;

	mail_cache_transaction_free_space(ctx);

	buf = buffer_get_data(ctx->reservations, &size);
	i_assert(size % sizeof(uint32_t)*2 == 0);
	size /= sizeof(*buf);

	if (size > 0) {
		/* free flushed data as well. do it from end to beginning so
		   we have a better chance of updating used_file_size instead
		   of adding holes */
		do {
			size -= 2;
			mail_cache_free_space(ctx->cache, buf[size],
					      buf[size+1]);
		} while (size > 0);
	}

	/* make sure we don't cache the headers */
	for (i = 0; i < ctx->next_unused_header_lowwater; i++) {
		uint32_t offset = cache->hdr->header_offsets[i];
		if (mail_cache_offset_to_uint32(offset) == 0)
			cache->split_offsets[i] = 1;
	}

	mail_cache_transaction_free(ctx);
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
	uint32_t offset, size, total_size;
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

	total_size = size + sizeof(uint32_t);
	offset = mail_cache_transaction_get_space(ctx, total_size, total_size,
						  NULL, FALSE);
	if (offset != 0) {
		if (pwrite_full(cache->fd, &size, sizeof(size), offset) < 0 ||
		    pwrite_full(cache->fd, header_str, size,
				offset + sizeof(uint32_t)) < 0) {
			mail_cache_set_syscall_error(cache, "pwrite_full()");
			offset = 0;
		}
	}

	if (offset != 0) {
		ctx->update_header_offsets[idx] = offset;
		ctx->changes = TRUE;

		/* update cached headers */
		cache->split_offsets[idx] = cache->hdr->header_offsets[idx];
		cache->split_headers[idx] =
			mail_cache_split_header(cache, header_str);

		/* make sure get_header_fields() still works for this header
		   while the transaction isn't yet committed. */
		ctx->next_unused_header_lowwater = idx + 1;
	}

	t_pop();
	return offset > 0;
}

void mail_cache_add(struct mail_cache_transaction_ctx *ctx, uint32_t seq,
		    enum mail_cache_field field,
		    const void *data, size_t data_size)
{
	uint32_t fixed_size, data_size32;
	size_t full_size;

	i_assert(field < MAIL_CACHE_FIELD_COUNT);
	i_assert(data_size > 0);
	i_assert(data_size < (uint32_t)-1);

	mail_cache_decision_add(ctx->view, seq, field);

	fixed_size = mail_cache_field_sizes[field];
	i_assert(fixed_size == (unsigned int)-1 || fixed_size == data_size);

	data_size32 = (uint32_t)data_size;

	if (ctx->prev_seq != seq) {
		mail_cache_transaction_switch_seq(ctx);
		ctx->prev_seq = seq;

		/* remember roughly what we have modified, so cache lookups can
		   look into transactions to see changes. */
		if (seq < ctx->first_seq || ctx->first_seq == 0)
			ctx->first_seq = seq;
		if (seq > ctx->last_seq)
			ctx->last_seq = seq;
		ctx->view->cached_exists[field] = TRUE;
		ctx->fields[field] = TRUE;
	}

	full_size = (data_size + 3) & ~3;
	if (fixed_size == (unsigned int)-1)
		full_size += sizeof(data_size32);

	if (buffer_get_used_size(ctx->cache_data) + full_size >
	    buffer_get_size(ctx->cache_data)) {
		/* time to flush our buffer */
		if (mail_cache_transaction_flush(ctx) < 0)
			return;
	}

	buffer_append(ctx->cache_data, &field, sizeof(field));
	if (fixed_size == (unsigned int)-1) {
		buffer_append(ctx->cache_data, &data_size32,
			      sizeof(data_size32));
	}

	buffer_append(ctx->cache_data, data, data_size);
	if ((data_size & 3) != 0)
                buffer_append(ctx->cache_data, null4, 4 - (data_size & 3));
}

int mail_cache_update_record_flags(struct mail_cache_view *view, uint32_t seq,
				   enum mail_cache_record_flag flags)
{
	return -1;
}

int mail_cache_link(struct mail_cache *cache, uint32_t old_offset,
		    uint32_t new_offset)
{
	i_assert(cache->locked);

	if (new_offset + sizeof(struct mail_cache_record) >
	    cache->hdr_copy.used_file_size) {
		mail_cache_set_corrupted(cache,
			"Cache record offset %u points outside file",
			new_offset);
		return -1;
	}

	new_offset += offsetof(struct mail_cache_record, prev_offset);
	if (pwrite_full(cache->fd, &old_offset,
			sizeof(old_offset), new_offset) < 0) {
		mail_cache_set_syscall_error(cache, "pwrite_full()");
		return -1;
	}

	cache->hdr_copy.continued_record_count++;
	cache->hdr_modified = TRUE;
	return 0;
}

int mail_cache_delete(struct mail_cache *cache, uint32_t offset)
{
	struct mail_cache_record *cache_rec;

	i_assert(cache->locked);

	cache_rec = mail_cache_get_record(cache, offset);
	if (cache_rec == NULL)
		return 0;

	/* we'll only update the deleted_space in header. we can't really
	   do any actual deleting as other processes might still be using
	   the data. also it's actually useful as some index views are still
	   able to ask cached data from messages that have already been
	   expunged. */
	do {
		cache->hdr_copy.deleted_space += cache_rec->size;
		cache_rec =
			mail_cache_get_record(cache, cache_rec->prev_offset);
	} while (cache_rec != NULL);

	cache->hdr_modified = TRUE;
	return 0;
}
