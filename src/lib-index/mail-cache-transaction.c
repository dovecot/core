/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "buffer.h"
#include "module-context.h"
#include "file-cache.h"
#include "file-set-size.h"
#include "read-full.h"
#include "write-full.h"
#include "mail-cache-private.h"
#include "mail-index-transaction-private.h"

#include <stddef.h>
#include <sys/stat.h>

#define MAIL_CACHE_INIT_WRITE_BUFFER (1024*16)

#define CACHE_TRANS_CONTEXT(obj) \
	MODULE_CONTEXT(obj, cache_mail_index_transaction_module)
#define CACHE_TRANS_CONTEXT_REQUIRE(obj) \
	MODULE_CONTEXT_REQUIRE(obj, cache_mail_index_transaction_module)

struct mail_cache_transaction_rec {
	uint32_t seq;
	uint32_t cache_data_pos;
};

struct mail_cache_transaction_ctx {
	union mail_index_transaction_module_context module_ctx;
	struct mail_index_transaction_vfuncs super;

	struct mail_cache *cache;
	struct mail_cache_view *view;
	struct mail_index_transaction *trans;

	uint32_t cache_file_seq;
	uint32_t first_new_seq;

	buffer_t *cache_data;
	ARRAY(uint8_t) cache_field_idx_used;
	ARRAY(struct mail_cache_transaction_rec) cache_data_seq;
	ARRAY_TYPE(seq_range) cache_data_wanted_seqs;
	uint32_t prev_seq, min_seq;
	size_t last_rec_pos;

	unsigned int records_written;

	bool tried_compression:1;
	bool decisions_refreshed:1;
	bool changes:1;
};

static MODULE_CONTEXT_DEFINE_INIT(cache_mail_index_transaction_module,
				  &mail_index_module_register);

static int mail_cache_transaction_lock(struct mail_cache_transaction_ctx *ctx);
static size_t mail_cache_transaction_update_last_rec_size(struct mail_cache_transaction_ctx *ctx);
static int mail_cache_header_rewrite_fields(struct mail_cache *cache);

static void mail_index_transaction_cache_reset(struct mail_index_transaction *t)
{
	struct mail_cache_transaction_ctx *ctx = CACHE_TRANS_CONTEXT_REQUIRE(t);
	struct mail_index_transaction_vfuncs super = ctx->super;

	mail_cache_transaction_reset(ctx);
	super.reset(t);
}

static int
mail_index_transaction_cache_commit(struct mail_index_transaction *t,
				    struct mail_index_transaction_commit_result *result_r)
{
	struct mail_cache_transaction_ctx *ctx = CACHE_TRANS_CONTEXT_REQUIRE(t);
	struct mail_index_transaction_vfuncs super = ctx->super;

	/* a failed cache commit isn't important enough to fail the entire
	   index transaction, so we'll just ignore it */
	(void)mail_cache_transaction_commit(&ctx);
	return super.commit(t, result_r);
}

static void
mail_index_transaction_cache_rollback(struct mail_index_transaction *t)
{
	struct mail_cache_transaction_ctx *ctx = CACHE_TRANS_CONTEXT_REQUIRE(t);
	struct mail_index_transaction_vfuncs super = ctx->super;

	mail_cache_transaction_rollback(&ctx);
	super.rollback(t);
}

struct mail_cache_transaction_ctx *
mail_cache_get_transaction(struct mail_cache_view *view,
			   struct mail_index_transaction *t)
{
	struct mail_cache_transaction_ctx *ctx;

	ctx = !cache_mail_index_transaction_module.id.module_id_set ? NULL :
		CACHE_TRANS_CONTEXT(t);

	if (ctx != NULL)
		return ctx;

	ctx = i_new(struct mail_cache_transaction_ctx, 1);
	ctx->cache = view->cache;
	ctx->view = view;
	ctx->trans = t;

	i_assert(view->transaction == NULL);
	view->transaction = ctx;
	view->trans_view = mail_index_transaction_open_updated_view(t);

	ctx->super = t->v;
	t->v.reset = mail_index_transaction_cache_reset;
	t->v.commit = mail_index_transaction_cache_commit;
	t->v.rollback = mail_index_transaction_cache_rollback;

	MODULE_CONTEXT_SET(t, cache_mail_index_transaction_module, ctx);
	return ctx;
}

static void
mail_cache_transaction_forget_flushed(struct mail_cache_transaction_ctx *ctx)
{
	ctx->cache_file_seq = MAIL_CACHE_IS_UNUSABLE(ctx->cache) ? 0 :
		ctx->cache->hdr->file_seq;
	/* forget all cache extension updates even if reset_id doesn't change */
	mail_index_ext_set_reset_id(ctx->trans, ctx->cache->ext_id,
				    ctx->cache_file_seq);
}

void mail_cache_transaction_reset(struct mail_cache_transaction_ctx *ctx)
{
	mail_cache_transaction_forget_flushed(ctx);
	if (ctx->cache_data != NULL)
		buffer_set_used_size(ctx->cache_data, 0);
	if (array_is_created(&ctx->cache_data_seq))
		array_clear(&ctx->cache_data_seq);
	ctx->prev_seq = 0;
	ctx->last_rec_pos = 0;

	ctx->changes = FALSE;
}

void mail_cache_transaction_rollback(struct mail_cache_transaction_ctx **_ctx)
{
	struct mail_cache_transaction_ctx *ctx = *_ctx;

	*_ctx = NULL;

	if (ctx->records_written > 0) {
		/* we already wrote to the cache file. we can't (or don't want
		   to) delete that data, so just mark it as deleted space */
		if (mail_cache_transaction_lock(ctx) > 0) {
			ctx->cache->hdr_copy.deleted_record_count +=
				ctx->records_written;
			(void)mail_cache_unlock(ctx->cache);
		}
	}

	MODULE_CONTEXT_UNSET(ctx->trans, cache_mail_index_transaction_module);

	ctx->view->transaction = NULL;
	ctx->view->trans_seq1 = ctx->view->trans_seq2 = 0;

	mail_index_view_close(&ctx->view->trans_view);
	buffer_free(&ctx->cache_data);
	if (array_is_created(&ctx->cache_data_seq))
		array_free(&ctx->cache_data_seq);
	if (array_is_created(&ctx->cache_data_wanted_seqs))
		array_free(&ctx->cache_data_wanted_seqs);
	array_free(&ctx->cache_field_idx_used);
	i_free(ctx);
}

static int
mail_cache_transaction_compress(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache *cache = ctx->cache;

	ctx->tried_compression = TRUE;

	uint32_t compress_file_seq =
		MAIL_CACHE_IS_UNUSABLE(cache) ? 0 : cache->hdr->file_seq;

	int ret = mail_cache_compress(cache, compress_file_seq);
	/* already written cache records must be forgotten, but records in
	   memory can still be written to the new cache file */
	mail_cache_transaction_forget_flushed(ctx);
	return ret;
}

static int mail_cache_transaction_lock(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache *cache = ctx->cache;
	const uoff_t cache_max_size =
		cache->index->optimization_set.cache.max_size;
	int ret;

	if ((ret = mail_cache_lock(cache)) <= 0) {
		if (ret < 0)
			return -1;

		if (!ctx->tried_compression) {
			if (mail_cache_transaction_compress(ctx) < 0)
				return -1;
			return mail_cache_transaction_lock(ctx);
		} else {
			return 0;
		}
	}
	i_assert(!MAIL_CACHE_IS_UNUSABLE(cache));

	if (!ctx->tried_compression && ctx->cache_data != NULL &&
	    cache->last_stat_size + ctx->cache_data->used >= cache_max_size) {
		/* Looks like cache file is becoming too large. Try to compress
		   it to free up some space. */
		if (cache->hdr->continued_record_count > 0 ||
		    cache->hdr->deleted_record_count > 0) {
			(void)mail_cache_unlock(cache);
			(void)mail_cache_transaction_compress(ctx);
			return mail_cache_transaction_lock(ctx);
		}
	}

	if (ctx->cache_file_seq == 0)
		ctx->cache_file_seq = cache->hdr->file_seq;
	else if (ctx->cache_file_seq != cache->hdr->file_seq) {
		/* already written cache records must be forgotten, but records
		   in memory can still be written to the new cache file */
		mail_cache_transaction_forget_flushed(ctx);
		i_assert(ctx->cache_file_seq == cache->hdr->file_seq);
	}
	return 1;
}

const struct mail_cache_record *
mail_cache_transaction_lookup_rec(struct mail_cache_transaction_ctx *ctx,
				  unsigned int seq,
				  unsigned int *trans_next_idx)
{
	const struct mail_cache_transaction_rec *recs;
	unsigned int i, count;

	recs = array_get(&ctx->cache_data_seq, &count);
	for (i = *trans_next_idx; i < count; i++) {
		if (recs[i].seq == seq) {
			*trans_next_idx = i + 1;
			return CONST_PTR_OFFSET(ctx->cache_data->data,
						recs[i].cache_data_pos);
		}
	}
	*trans_next_idx = i + 1;
	if (seq == ctx->prev_seq && i == count) {
		/* update the unfinished record's (temporary) size and
		   return it */
		mail_cache_transaction_update_last_rec_size(ctx);
		return CONST_PTR_OFFSET(ctx->cache_data->data,
					ctx->last_rec_pos);
	}
	return NULL;
}

static void
mail_cache_transaction_update_index(struct mail_cache_transaction_ctx *ctx,
				    uint32_t write_offset)
{
	struct mail_cache *cache = ctx->cache;
	const struct mail_cache_record *rec = ctx->cache_data->data;
	const struct mail_cache_transaction_rec *recs;
	uint32_t i, seq_count;

	mail_index_ext_using_reset_id(ctx->trans, ctx->cache->ext_id,
				      ctx->cache_file_seq);

	/* write the cache_offsets to index file. records' prev_offset
	   is updated to point to old cache record when index is being
	   synced. */
	recs = array_get(&ctx->cache_data_seq, &seq_count);
	for (i = 0; i < seq_count; i++) {
		mail_index_update_ext(ctx->trans, recs[i].seq, cache->ext_id,
				      &write_offset, NULL);

		write_offset += rec->size;
		rec = CONST_PTR_OFFSET(rec, rec->size);
	}
}

static int
mail_cache_link_records(struct mail_cache_transaction_ctx *ctx,
			uint32_t write_offset)
{
	struct mail_index_map *map;
	struct mail_cache_record *rec;
	const struct mail_cache_transaction_rec *recs;
	const uint32_t *prev_offsetp;
	ARRAY_TYPE(uint32_t) seq_offsets;
	uint32_t i, seq_count, reset_id, prev_offset, *offsetp;
	const void *data;

	i_assert(ctx->min_seq != 0);

	i_array_init(&seq_offsets, 64);
	recs = array_get(&ctx->cache_data_seq, &seq_count);
	rec = buffer_get_modifiable_data(ctx->cache_data, NULL);
	for (i = 0; i < seq_count; i++) {
		offsetp = array_idx_get_space(&seq_offsets,
					       recs[i].seq - ctx->min_seq);
		if (*offsetp != 0)
			prev_offset = *offsetp;
		else {
			mail_index_lookup_ext_full(ctx->view->trans_view, recs[i].seq,
						   ctx->cache->ext_id, &map,
						   &data, NULL);
			prev_offsetp = data;

			if (prev_offsetp == NULL || *prev_offsetp == 0)
				prev_offset = 0;
			else if (mail_index_ext_get_reset_id(ctx->view->trans_view, map,
							     ctx->cache->ext_id,
							     &reset_id) &&
				 reset_id == ctx->cache_file_seq)
				prev_offset = *prev_offsetp;
			else
				prev_offset = 0;
			if (prev_offset >= write_offset) {
				mail_cache_set_corrupted(ctx->cache,
					"Cache record offset points outside existing file");
				array_free(&seq_offsets);
				return -1;
			}
		}

		if (prev_offset != 0) {
			/* link this record to previous one */
			rec->prev_offset = prev_offset;
			ctx->cache->hdr_copy.continued_record_count++;
		} else {
			ctx->cache->hdr_copy.record_count++;
		}
		*offsetp = write_offset;

		write_offset += rec->size;
		rec = PTR_OFFSET(rec, rec->size);
	}
	array_free(&seq_offsets);
	ctx->cache->hdr_modified = TRUE;
	return 0;
}

static bool
mail_cache_transaction_set_used(struct mail_cache_transaction_ctx *ctx)
{
	const uint8_t *cache_fields_used;
	unsigned int field_idx, count;
	bool missing_file_fields = FALSE;

	cache_fields_used = array_get(&ctx->cache_field_idx_used, &count);
	i_assert(count <= ctx->cache->fields_count);
	for (field_idx = 0; field_idx < count; field_idx++) {
		if (cache_fields_used[field_idx] != 0) {
			ctx->cache->fields[field_idx].used = TRUE;
			if (ctx->cache->field_file_map[field_idx] == (uint32_t)-1)
				missing_file_fields = TRUE;
		}
	}
	return missing_file_fields;
}

static int
mail_cache_transaction_update_fields(struct mail_cache_transaction_ctx *ctx)
{
	unsigned char *p;
	const unsigned char *end, *rec_end;
	uint32_t field_idx, data_size;

	if (mail_cache_transaction_set_used(ctx)) {
		/* add missing fields to cache */
		if (mail_cache_header_rewrite_fields(ctx->cache) < 0)
			return -1;
		/* make sure they were actually added */
		if (mail_cache_transaction_set_used(ctx)) {
			mail_index_set_error(ctx->cache->index,
				"Cache file %s: Unexpectedly lost newly added field",
				ctx->cache->filepath);
			return -1;
		}
	}

	/* Go through all the added cache records and replace the in-memory
	   field_idx with the cache file-specific field index. Update only
	   up to last_rec_pos, because that's how far flushing is done. The
	   fields after that keep the in-memory field_idx until the next
	   flush. */
	p = buffer_get_modifiable_data(ctx->cache_data, NULL);
	end = CONST_PTR_OFFSET(ctx->cache_data->data, ctx->last_rec_pos);
	rec_end = p;
	while (p < end) {
		if (p >= rec_end) {
			/* next cache record */
			i_assert(p == rec_end);
			const struct mail_cache_record *rec =
				(const struct mail_cache_record *)p;
			/* note that the last rec->size==0 */
			rec_end = CONST_PTR_OFFSET(p, rec->size);
			p += sizeof(*rec);
		}
		/* replace field_idx */
		uint32_t *file_fieldp = (uint32_t *)p;
		field_idx = *file_fieldp;
		*file_fieldp = ctx->cache->field_file_map[field_idx];
		i_assert(*file_fieldp != (uint32_t)-1);
		p += sizeof(field_idx);

		/* Skip to next cache field. Next is <data size> if the field
		   is not fixed size. */
		data_size = ctx->cache->fields[field_idx].field.field_size;
		if (data_size == UINT_MAX) {
			memcpy(&data_size, p, sizeof(data_size));
			p += sizeof(data_size);
		}
		/* data & 32bit padding */
		p += data_size;
		if ((data_size & 3) != 0)
			p += 4 - (data_size & 3);
	}
	i_assert(p == end);
	return 0;
}

static void
mail_cache_transaction_drop_last_flush(struct mail_cache_transaction_ctx *ctx)
{
	buffer_copy(ctx->cache_data, 0,
		    ctx->cache_data, ctx->last_rec_pos, (size_t)-1);
	buffer_set_used_size(ctx->cache_data,
			     ctx->cache_data->used - ctx->last_rec_pos);
	ctx->last_rec_pos = 0;
	ctx->min_seq = 0;

	array_clear(&ctx->cache_data_seq);
	array_clear(&ctx->cache_data_wanted_seqs);
}

static int
mail_cache_transaction_flush(struct mail_cache_transaction_ctx *ctx)
{
	struct stat st;
	uint32_t write_offset = 0;
	int ret = 0;

	i_assert(!ctx->cache->locked);

	if (array_count(&ctx->cache_data_seq) == 0) {
		/* we had done some changes, but they were aborted. */
		i_assert(ctx->last_rec_pos == 0);
		ctx->min_seq = 0;
		return 0;
	}

	if (mail_cache_transaction_lock(ctx) <= 0)
		return -1;

	i_assert(ctx->cache_data != NULL);
	i_assert(ctx->last_rec_pos <= ctx->cache_data->used);

	if (mail_cache_transaction_update_fields(ctx) < 0) {
		(void)mail_cache_unlock(ctx->cache);
		return -1;
	}

	/* we need to get the final write offset for linking records */
	if (fstat(ctx->cache->fd, &st) < 0) {
		if (!ESTALE_FSTAT(errno))
			mail_cache_set_syscall_error(ctx->cache, "fstat()");
		ret = -1;
	} else if (st.st_size + ctx->last_rec_pos > ctx->cache->index->optimization_set.cache.max_size) {
		mail_cache_set_corrupted(ctx->cache, "Cache file too large");
		ret = -1;
	} else {
		write_offset = st.st_size;
		if (mail_cache_link_records(ctx, write_offset) < 0)
			ret = -1;
	}

	/* write to cache file */
	if (ret < 0 ||
	    mail_cache_append(ctx->cache, ctx->cache_data->data,
			      ctx->last_rec_pos, &write_offset) < 0)
		ret = -1;
	else {
		/* update records' cache offsets to index */
		ctx->records_written++;
		mail_cache_transaction_update_index(ctx, write_offset);
	}
	if (mail_cache_unlock(ctx->cache) < 0)
		ret = -1;
	return ret;
}

static void
mail_cache_transaction_drop_unwanted(struct mail_cache_transaction_ctx *ctx,
				     size_t space_needed)
{
	struct mail_cache_transaction_rec *recs;
	unsigned int i, count;

	recs = array_get_modifiable(&ctx->cache_data_seq, &count);
	/* find out how many records to delete. delete all unwanted sequences,
	   and if that's not enough delete some more. */
	for (i = 0; i < count; i++) {
		if (seq_range_exists(&ctx->cache_data_wanted_seqs, recs[i].seq)) {
			if (recs[i].cache_data_pos >= space_needed)
				break;
			/* we're going to forcibly delete it - remove it also
			   from the array since it's no longer useful there */
			seq_range_array_remove(&ctx->cache_data_wanted_seqs,
					       recs[i].seq);
		}
	}
	unsigned int deleted_count = i;
	size_t deleted_space = i < count ?
		recs[i].cache_data_pos : ctx->last_rec_pos;
	for (; i < count; i++)
		recs[i].cache_data_pos -= deleted_space;
	ctx->last_rec_pos -= deleted_space;
	array_delete(&ctx->cache_data_seq, 0, deleted_count);
	buffer_delete(ctx->cache_data, 0, deleted_space);
}

static size_t
mail_cache_transaction_update_last_rec_size(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache_record *rec;
	void *data;
	size_t size;

	data = buffer_get_modifiable_data(ctx->cache_data, &size);
	rec = PTR_OFFSET(data, ctx->last_rec_pos);
	rec->size = size - ctx->last_rec_pos;
	i_assert(rec->size > sizeof(*rec));
	return rec->size;
}

static void
mail_cache_transaction_update_last_rec(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache_transaction_rec *trans_rec;
	size_t size;

	size = mail_cache_transaction_update_last_rec_size(ctx);
	if (size > ctx->cache->index->optimization_set.cache.record_max_size) {
		buffer_set_used_size(ctx->cache_data, ctx->last_rec_pos);
		return;
	}

	if (ctx->min_seq > ctx->prev_seq || ctx->min_seq == 0)
		ctx->min_seq = ctx->prev_seq;
	trans_rec = array_append_space(&ctx->cache_data_seq);
	trans_rec->seq = ctx->prev_seq;
	trans_rec->cache_data_pos = ctx->last_rec_pos;
	ctx->last_rec_pos = ctx->cache_data->used;
}

static void
mail_cache_transaction_switch_seq(struct mail_cache_transaction_ctx *ctx)
{
	struct mail_cache_record new_rec;

	if (ctx->prev_seq != 0) {
		/* update previously added cache record's size */
		mail_cache_transaction_update_last_rec(ctx);
	} else if (ctx->cache_data == NULL) {
		ctx->cache_data =
			buffer_create_dynamic(default_pool,
					      MAIL_CACHE_INIT_WRITE_BUFFER);
		i_array_init(&ctx->cache_data_seq, 64);
		i_array_init(&ctx->cache_data_wanted_seqs, 32);
		i_array_init(&ctx->cache_field_idx_used, 64);
	}

	i_zero(&new_rec);
	buffer_append(ctx->cache_data, &new_rec, sizeof(new_rec));

	ctx->prev_seq = 0;
	ctx->changes = TRUE;
}

int mail_cache_transaction_commit(struct mail_cache_transaction_ctx **_ctx)
{
	struct mail_cache_transaction_ctx *ctx = *_ctx;
	int ret = 0;

	if (ctx->changes) {
		if (ctx->prev_seq != 0)
			mail_cache_transaction_update_last_rec(ctx);
		if (mail_cache_transaction_flush(ctx) < 0)
			ret = -1;
		else {
			/* successfully wrote everything */
			ctx->records_written = 0;
		}
		/* Here would be a good place to do fdatasync() to make sure
		   everything is written before offsets are updated to index.
		   However it slows down I/O needlessly and we're pretty good
		   at catching and fixing cache corruption, so we no longer do
		   it. */
	}
	mail_cache_transaction_rollback(_ctx);
	return ret;
}

static int
mail_cache_header_fields_write(struct mail_cache *cache, const buffer_t *buffer)
{
	uint32_t offset, hdr_offset;

	i_assert(cache->locked);

	offset = 0;
	if (mail_cache_append(cache, buffer->data, buffer->used, &offset) < 0)
		return -1;

	if (cache->index->fsync_mode == FSYNC_MODE_ALWAYS) {
		if (fdatasync(cache->fd) < 0) {
			mail_cache_set_syscall_error(cache, "fdatasync()");
			return -1;
		}
	}
	/* find offset to the previous header's "next_offset" field */
	if (mail_cache_header_fields_get_next_offset(cache, &hdr_offset) < 0)
		return -1;

	/* update the next_offset offset, so our new header will be found */
	offset = mail_index_uint32_to_offset(offset);
	if (mail_cache_write(cache, &offset, sizeof(offset), hdr_offset) < 0)
		return -1;

	if (hdr_offset == offsetof(struct mail_cache_header,
				   field_header_offset)) {
		/* we're adding the first field. hdr_copy needs to be kept
		   in sync so unlocking won't overwrite it. */
		cache->hdr_copy.field_header_offset = hdr_offset;
		cache->hdr_ro_copy.field_header_offset = hdr_offset;
	}
	return 0;
}

static int mail_cache_header_rewrite_fields(struct mail_cache *cache)
{
	int ret;

	/* re-read header to make sure we don't lose any fields. */
	if (mail_cache_header_fields_read(cache) < 0)
		return -1;

	T_BEGIN {
		buffer_t *buffer;

		buffer = t_buffer_create(256);
		mail_cache_header_fields_get(cache, buffer);
		ret = mail_cache_header_fields_write(cache, buffer);
	} T_END;

	if (ret == 0) {
		/* we wrote all the headers, so there are no pending changes */
		cache->field_header_write_pending = FALSE;
		ret = mail_cache_header_fields_read(cache);
	}
	return ret;
}

static void
mail_cache_transaction_refresh_decisions(struct mail_cache_transaction_ctx *ctx)
{
	if (ctx->decisions_refreshed)
		return;

	/* Read latest caching decisions from the cache file's header once
	   per transaction. */
	if (!ctx->cache->opened)
		(void)mail_cache_open_and_verify(ctx->cache);
	else
		(void)mail_cache_header_fields_read(ctx->cache);
	ctx->decisions_refreshed = TRUE;
}

void mail_cache_add(struct mail_cache_transaction_ctx *ctx, uint32_t seq,
		    unsigned int field_idx, const void *data, size_t data_size)
{
	uint32_t data_size32;
	unsigned int fixed_size;
	size_t full_size;

	i_assert(field_idx < ctx->cache->fields_count);
	i_assert(data_size < (uint32_t)-1);

	if (ctx->cache->fields[field_idx].field.decision ==
	    (MAIL_CACHE_DECISION_NO | MAIL_CACHE_DECISION_FORCED))
		return;

	/* If the cache file exists, make sure the caching decisions have been
	   read. */
	mail_cache_transaction_refresh_decisions(ctx);

	mail_cache_decision_add(ctx->view, seq, field_idx);

	fixed_size = ctx->cache->fields[field_idx].field.field_size;
	i_assert(fixed_size == UINT_MAX || fixed_size == data_size);

	data_size32 = (uint32_t)data_size;

	if (ctx->prev_seq != seq) {
		mail_cache_transaction_switch_seq(ctx);
		ctx->prev_seq = seq;
		seq_range_array_add(&ctx->cache_data_wanted_seqs, seq);

		/* remember roughly what we have modified, so cache lookups can
		   look into transactions to see changes. */
		if (seq < ctx->view->trans_seq1 || ctx->view->trans_seq1 == 0)
			ctx->view->trans_seq1 = seq;
		if (seq > ctx->view->trans_seq2)
			ctx->view->trans_seq2 = seq;
	}

	/* Remember that this field has been used within the transaction. Later
	   on we fill mail_cache_field_private.used with it. We can't rely on
	   setting it here, because cache compression may run and clear it. */
	uint8_t field_idx_set = 1;
	array_idx_set(&ctx->cache_field_idx_used, field_idx, &field_idx_set);

	/* Remember that this value exists for the mail, in case we try to look
	   it up. Note that this gets forgotten whenever changing the mail. */
	buffer_write(ctx->view->cached_exists_buf, field_idx,
		     &ctx->view->cached_exists_value, 1);

	full_size = (data_size + 3) & ~3;
	if (fixed_size == UINT_MAX)
		full_size += sizeof(data_size32);

	if (ctx->cache_data->used + full_size > MAIL_CACHE_MAX_WRITE_BUFFER &&
	    ctx->last_rec_pos > 0) {
		/* time to flush our buffer. */
		if (MAIL_INDEX_IS_IN_MEMORY(ctx->cache->index)) {
			/* just drop the old data to free up memory */
			size_t space_needed = ctx->cache_data->used +
				full_size - MAIL_CACHE_MAX_WRITE_BUFFER;
			mail_cache_transaction_drop_unwanted(ctx, space_needed);
		} else {
			if (mail_cache_transaction_flush(ctx) < 0) {
				/* If this is a syscall failure, the already
				   flushed changes could still be finished by
				   writing the offsets to .log file. If this is
				   a corruption/lost cache, the offsets will
				   point to a nonexistent file or be ignored.
				   Either way, we don't really need to handle
				   this failure in any special way. */
			}
			/* Regardless of whether the flush succeeded, drop all
			   data that it would have written. This way the flush
			   is attempted only once, but it could still be
			   possible to write new data later. Also don't reset
			   the transaction entirely so that the last partially
			   cached mail can still be accessed from memory. */
			mail_cache_transaction_drop_last_flush(ctx);
		}
	}

	buffer_append(ctx->cache_data, &field_idx, sizeof(field_idx));
	if (fixed_size == UINT_MAX) {
		buffer_append(ctx->cache_data, &data_size32,
			      sizeof(data_size32));
	}

	buffer_append(ctx->cache_data, data, data_size);
	if ((data_size & 3) != 0)
                buffer_append_zero(ctx->cache_data, 4 - (data_size & 3));
}

bool mail_cache_field_want_add(struct mail_cache_transaction_ctx *ctx,
			       uint32_t seq, unsigned int field_idx)
{
	enum mail_cache_decision_type decision;

	mail_cache_transaction_refresh_decisions(ctx);

	decision = mail_cache_field_get_decision(ctx->view->cache, field_idx);
	decision &= ~MAIL_CACHE_DECISION_FORCED;
	switch (decision) {
	case MAIL_CACHE_DECISION_NO:
		return FALSE;
	case MAIL_CACHE_DECISION_TEMP:
		/* add it only if it's newer than what we would drop when
		   compressing */
		if (ctx->first_new_seq == 0) {
			ctx->first_new_seq =
				mail_cache_get_first_new_seq(ctx->view->view);
		}
		if (seq < ctx->first_new_seq)
			return FALSE;
		break;
	default:
		break;
	}

	return mail_cache_field_exists(ctx->view, seq, field_idx) == 0;
}

bool mail_cache_field_can_add(struct mail_cache_transaction_ctx *ctx,
			      uint32_t seq, unsigned int field_idx)
{
	enum mail_cache_decision_type decision;

	mail_cache_transaction_refresh_decisions(ctx);

	decision = mail_cache_field_get_decision(ctx->view->cache, field_idx);
	if (decision == (MAIL_CACHE_DECISION_FORCED | MAIL_CACHE_DECISION_NO))
		return FALSE;

	return mail_cache_field_exists(ctx->view, seq, field_idx) == 0;
}

void mail_cache_close_mail(struct mail_cache_transaction_ctx *ctx,
			   uint32_t seq)
{
	if (array_is_created(&ctx->cache_data_wanted_seqs))
		seq_range_array_remove(&ctx->cache_data_wanted_seqs, seq);
}
