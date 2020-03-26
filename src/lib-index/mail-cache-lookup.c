/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "str.h"
#include "mail-cache-private.h"


#define CACHE_PREFETCH IO_BLOCK_SIZE

int mail_cache_get_record(struct mail_cache *cache, uint32_t offset,
			  const struct mail_cache_record **rec_r)
{
	const struct mail_cache_record *rec;
	const void *data;
	int ret;

	i_assert(offset != 0);

	if (offset % sizeof(uint32_t) != 0) {
		/* records are always 32-bit aligned */
		mail_cache_set_corrupted(cache, "invalid record offset");
		return -1;
	}

	/* we don't know yet how large the record is, so just guess */
	if (mail_cache_map(cache, offset, sizeof(*rec) + CACHE_PREFETCH,
			   &data) < 0)
		return -1;

	if (offset + sizeof(*rec) > cache->mmap_length) {
		mail_cache_set_corrupted(cache, "record points outside file");
		return -1;
	}
	rec = data;

	if (rec->size < sizeof(*rec)) {
		mail_cache_set_corrupted(cache, "invalid record size");
		return -1;
	}
	if (rec->size > CACHE_PREFETCH) {
		/* larger than we guessed. map the rest of the record. */
		if ((ret = mail_cache_map(cache, offset, rec->size, &data)) < 0)
			return -1;
		if (ret == 0) {
			mail_cache_set_corrupted(cache, "record points outside file");
			return -1;
		}
		rec = data;
	}

	*rec_r = rec;
	return 0;
}

uint32_t mail_cache_lookup_cur_offset(struct mail_index_view *view,
				      uint32_t seq, uint32_t *reset_id_r)
{
	struct mail_cache *cache = mail_index_view_get_index(view)->cache;
	struct mail_index_map *map;
	const void *data;
	uint32_t offset;

	mail_index_lookup_ext_full(view, seq, cache->ext_id, &map, &data, NULL);
	if (data == NULL) {
		/* no cache offsets */
		return 0;
	}
	offset = *((const uint32_t *)data);
	if (offset == 0)
		return 0;

	if (!mail_index_ext_get_reset_id(view, map, cache->ext_id, reset_id_r))
		i_unreached();
	return offset;
}

static int
mail_cache_lookup_offset(struct mail_cache *cache, struct mail_index_view *view,
			 uint32_t seq, uint32_t *offset_r)
{
	uint32_t offset, reset_id;
	int i, ret;

	offset = mail_cache_lookup_cur_offset(view, seq, &reset_id);
	if (offset == 0)
		return 0;

	/* reset_id must match file_seq or the offset is for a different cache
	   file. if this happens, try if reopening the cache helps. if not,
	   it was probably for an old cache file that's already lost by now. */
	i = 0;
	while (cache->hdr->file_seq != reset_id) {
		if (++i == 2 || reset_id < cache->hdr->file_seq)
			return 0;

		if (cache->locked) {
			/* we're probably compressing */
			return 0;
		}

		if ((ret = mail_cache_reopen(cache)) <= 0) {
			/* error / we already have the latest file open */
			return ret;
		}
	}

	*offset_r = offset;
	return 1;
}

bool mail_cache_track_loops(struct mail_cache_loop_track *loop_track,
			    uoff_t offset, uoff_t size)
{
	i_assert(offset != 0);
	i_assert(size != 0);

	/* looping happens only in rare error conditions, so it's enough if we
	   just catch it eventually. we do this by checking if we've seen
	   more record data than possible in the accessed file area. */
	if (loop_track->size_sum == 0) {
		/* first call */
		loop_track->min_offset = offset;
		loop_track->max_offset = offset + size;
	} else {
		if (loop_track->min_offset > offset)
			loop_track->min_offset = offset;
		if (loop_track->max_offset < offset + size)
			loop_track->max_offset = offset + size;
	}

	loop_track->size_sum += size;
	return loop_track->size_sum >
		(loop_track->max_offset - loop_track->min_offset);
}

void mail_cache_lookup_iter_init(struct mail_cache_view *view, uint32_t seq,
				 struct mail_cache_lookup_iterate_ctx *ctx_r)
{
	struct mail_cache_lookup_iterate_ctx *ctx = ctx_r;
	int ret;

	if (!view->cache->opened)
		(void)mail_cache_open_and_verify(view->cache);

	i_zero(ctx);
	ctx->view = view;
	ctx->seq = seq;

	if (!MAIL_CACHE_IS_UNUSABLE(view->cache)) {
		/* look up the first offset */
		ret = mail_cache_lookup_offset(view->cache, view->view, seq,
					       &ctx->offset);
		if (ret <= 0) {
			ctx->stop = TRUE;
			ctx->failed = ret < 0;
		}
	}
	ctx->remap_counter = view->cache->remap_counter;

	i_zero(&view->loop_track);
}

static bool
mail_cache_lookup_iter_transaction(struct mail_cache_lookup_iterate_ctx *ctx)
{
	ctx->rec = mail_cache_transaction_lookup_rec(ctx->view->transaction,
						     ctx->seq,
						     &ctx->trans_next_idx);
	if (ctx->rec == NULL)
		return FALSE;

	ctx->remap_counter = ctx->view->cache->remap_counter;
	ctx->pos = sizeof(*ctx->rec);
	ctx->rec_size = ctx->rec->size;
	return TRUE;
}

static int
mail_cache_lookup_iter_next_record(struct mail_cache_lookup_iterate_ctx *ctx)
{
	struct mail_cache_view *view = ctx->view;

	if (ctx->failed)
		return -1;

	if (ctx->rec != NULL)
		ctx->offset = ctx->rec->prev_offset;
	if (ctx->offset == 0) {
		/* end of this record list. check newly appended data. */
		if (view->trans_seq1 > ctx->seq ||
		    view->trans_seq2 < ctx->seq)
			return 0;
		/* check data still in memory. this works for recent mails
		   even with INDEX=MEMORY */
		if (!ctx->memory_appends_checked) {
			if (mail_cache_lookup_iter_transaction(ctx))
				return 1;
			ctx->memory_appends_checked = TRUE;
		}
		if (MAIL_CACHE_IS_UNUSABLE(view->cache) || ctx->stop)
			return 0;

		/* check data already written to cache file */
		if (ctx->disk_appends_checked ||
		    mail_cache_lookup_offset(view->cache, view->trans_view,
					     ctx->seq, &ctx->offset) <= 0)
			return 0;

		ctx->disk_appends_checked = TRUE;
		ctx->remap_counter = view->cache->remap_counter;
		i_zero(&view->loop_track);
	}

	if (ctx->stop)
		return 0;

	/* look up the next record */
	if (mail_cache_get_record(view->cache, ctx->offset, &ctx->rec) < 0)
		return -1;
	if (mail_cache_track_loops(&view->loop_track, ctx->offset,
				   ctx->rec->size)) {
		mail_cache_set_corrupted(view->cache,
					 "record list is circular");
		return -1;
	}
	ctx->remap_counter = view->cache->remap_counter;

	ctx->pos = sizeof(*ctx->rec);
	ctx->rec_size = ctx->rec->size;
	return 1;
}

static int
mail_cache_lookup_rec_get_field(struct mail_cache_lookup_iterate_ctx *ctx,
				unsigned int *field_idx_r)
{
	struct mail_cache *cache = ctx->view->cache;
	uint32_t file_field;

	file_field = *((const uint32_t *)CONST_PTR_OFFSET(ctx->rec, ctx->pos));
	if (file_field >= cache->file_fields_count) {
		/* new field, have to re-read fields header to figure
		   out its size. don't do this if we're compressing. */
		if (!cache->locked) {
			if (mail_cache_header_fields_read(cache) < 0)
				return -1;
		}
		if (file_field >= cache->file_fields_count) {
			mail_cache_set_corrupted(cache,
				"field index too large (%u >= %u)",
				file_field, cache->file_fields_count);
			return -1;
		}

		/* field reading might have re-mmaped the file and
		   caused rec pointer to break. need to get it again. */
		if (mail_cache_get_record(cache, ctx->offset, &ctx->rec) < 0)
			return -1;
		ctx->remap_counter = cache->remap_counter;
	}

	*field_idx_r = cache->file_field_map[file_field];
	return 0;
}

int mail_cache_lookup_iter_next(struct mail_cache_lookup_iterate_ctx *ctx,
				struct mail_cache_iterate_field *field_r)
{
	struct mail_cache *cache = ctx->view->cache;
	unsigned int field_idx;
	unsigned int data_size;
	int ret;

	i_assert(ctx->remap_counter == cache->remap_counter);

	if (ctx->pos + sizeof(uint32_t) > ctx->rec_size) {
		if (ctx->pos != ctx->rec_size) {
			mail_cache_set_corrupted(cache,
				"record has invalid size");
			return -1;
		}

		if ((ret = mail_cache_lookup_iter_next_record(ctx)) <= 0)
			return ret;
	}

	/* return the next field */
	if (mail_cache_lookup_rec_get_field(ctx, &field_idx) < 0)
		return -1;
	ctx->pos += sizeof(uint32_t);

	data_size = cache->fields[field_idx].field.field_size;
	if (data_size == UINT_MAX &&
	    ctx->pos + sizeof(uint32_t) <= ctx->rec->size) {
		/* variable size field. get its size from the file. */
		data_size = *((const uint32_t *)
			      CONST_PTR_OFFSET(ctx->rec, ctx->pos));
		ctx->pos += sizeof(uint32_t);
	}

	if (ctx->rec->size - ctx->pos < data_size) {
		mail_cache_set_corrupted(cache,
			"record continues outside its allocated size");
		return -1;
	}

	field_r->field_idx = field_idx;
	field_r->data = CONST_PTR_OFFSET(ctx->rec, ctx->pos);
	field_r->size = data_size;
	field_r->offset = ctx->offset + ctx->pos;

	/* each record begins from 32bit aligned position */
	ctx->pos += (data_size + sizeof(uint32_t)-1) & ~(sizeof(uint32_t)-1);
	return 1;
}

static int mail_cache_seq(struct mail_cache_view *view, uint32_t seq)
{
	struct mail_cache_lookup_iterate_ctx iter;
	struct mail_cache_iterate_field field;
	int ret;

	if (++view->cached_exists_value == 0) {
		/* wrapped, we'll have to clear the buffer */
		buffer_set_used_size(view->cached_exists_buf, 0);
		view->cached_exists_value++;
	}
	view->cached_exists_seq = seq;

	mail_cache_lookup_iter_init(view, seq, &iter);
	while ((ret = mail_cache_lookup_iter_next(&iter, &field)) > 0) {
		buffer_write(view->cached_exists_buf, field.field_idx,
			     &view->cached_exists_value, 1);
	}
	return ret;
}

static bool
mail_cache_file_has_field(struct mail_cache *cache, unsigned int field)
{
	i_assert(field < cache->fields_count);
	return cache->field_file_map[field] != (uint32_t)-1;
}

int mail_cache_field_exists(struct mail_cache_view *view, uint32_t seq,
			    unsigned int field)
{
	const uint8_t *data;

	i_assert(seq > 0);

	if (!view->cache->opened)
		(void)mail_cache_open_and_verify(view->cache);

	if (!mail_cache_file_has_field(view->cache, field))
		return 0;

	/* FIXME: we should discard the cache if view has been synced */
	if (view->cached_exists_seq != seq) {
		if (mail_cache_seq(view, seq) < 0)
			return -1;
	}

	data = view->cached_exists_buf->data;
	return (field < view->cached_exists_buf->used &&
		data[field] == view->cached_exists_value) ? 1 : 0;
}

bool mail_cache_field_exists_any(struct mail_cache_view *view, uint32_t seq)
{
	uint32_t reset_id;

	return mail_cache_lookup_cur_offset(view->view, seq, &reset_id) != 0;
}

enum mail_cache_decision_type
mail_cache_field_get_decision(struct mail_cache *cache, unsigned int field_idx)
{
	i_assert(field_idx < cache->fields_count);

	return cache->fields[field_idx].field.decision;
}

static int
mail_cache_lookup_bitmask(struct mail_cache_lookup_iterate_ctx *iter,
			  unsigned int field_idx, unsigned int field_size,
			  buffer_t *dest_buf)
{
	struct mail_cache_iterate_field field;
	const unsigned char *src;
	unsigned char *dest;
	unsigned int i;
	bool found = FALSE;
	int ret;

	/* make sure all bits are cleared first */
	buffer_write_zero(dest_buf, 0, field_size);

	while ((ret = mail_cache_lookup_iter_next(iter, &field)) > 0) {
		if (field.field_idx != field_idx)
			continue;

		/* merge all bits */
		src = field.data;
		dest = buffer_get_space_unsafe(dest_buf, 0, field.size);
		for (i = 0; i < field.size; i++)
			dest[i] |= src[i];
		found = TRUE;
	}
	return ret < 0 ? -1 : (found ? 1 : 0);
}

int mail_cache_lookup_field(struct mail_cache_view *view, buffer_t *dest_buf,
			    uint32_t seq, unsigned int field_idx)
{
	const struct mail_cache_field *field_def;
	struct mail_cache_lookup_iterate_ctx iter;
	struct mail_cache_iterate_field field;
	int ret;

	ret = mail_cache_field_exists(view, seq, field_idx);
	mail_cache_decision_state_update(view, seq, field_idx);
	if (ret <= 0)
		return ret;

	/* the field should exist */
	mail_cache_lookup_iter_init(view, seq, &iter);
	field_def = &view->cache->fields[field_idx].field;
	if (field_def->type == MAIL_CACHE_FIELD_BITMASK) {
		return mail_cache_lookup_bitmask(&iter, field_idx,
						 field_def->field_size,
						 dest_buf);
	}

	/* return the first one that's found. if there are multiple
	   they're all identical. */
	while ((ret = mail_cache_lookup_iter_next(&iter, &field)) > 0) {
		if (field.field_idx == field_idx) {
			buffer_append(dest_buf, field.data, field.size);
			break;
		}
	}
	return ret;
}

struct header_lookup_data {
	uint32_t data_size;
	const unsigned char *data;
};

struct header_lookup_line {
	uint32_t line_num;
	struct header_lookup_data *data;
};

struct header_lookup_context {
	struct mail_cache_view *view;
	pool_t pool;
	ARRAY(struct header_lookup_line) lines;
};

enum {
	HDR_FIELD_STATE_DONTWANT = 0,
	HDR_FIELD_STATE_WANT,
	HDR_FIELD_STATE_SEEN
};

static void header_lines_save(struct header_lookup_context *ctx,
			      const struct mail_cache_iterate_field *field)
{
	const uint32_t *lines = field->data;
	uint32_t data_size = field->size;
	struct header_lookup_line hdr_line;
        struct header_lookup_data *hdr_data;
	void *data_dup;
	unsigned int i, lines_count, pos;

	/* data = { line_nums[], 0, "headers" } */
	for (i = 0; data_size >= sizeof(uint32_t); i++) {
		data_size -= sizeof(uint32_t);
		if (lines[i] == 0)
			break;
	}
	lines_count = i;
	pos = (lines_count+1) * sizeof(uint32_t);

	hdr_data = p_new(ctx->pool, struct header_lookup_data, 1);
	hdr_data->data_size = data_size;
	if (data_size > 0) {
		hdr_data->data = data_dup =
			p_malloc(ctx->pool, data_size);
		memcpy(data_dup, CONST_PTR_OFFSET(field->data, pos), data_size);
	}

	for (i = 0; i < lines_count; i++) {
		hdr_line.line_num = lines[i];
		hdr_line.data = hdr_data;
		array_push_back(&ctx->lines, &hdr_line);
	}
}

static int header_lookup_line_cmp(const struct header_lookup_line *l1,
				  const struct header_lookup_line *l2)
{
	return (int)l1->line_num - (int)l2->line_num;
}

static int
mail_cache_lookup_headers_real(struct mail_cache_view *view, string_t *dest,
			       uint32_t seq, unsigned int field_idxs[],
			       unsigned int fields_count, pool_t *pool_r)
{
	struct mail_cache *cache = view->cache;
	struct mail_cache_lookup_iterate_ctx iter;
	struct mail_cache_iterate_field field;
	struct header_lookup_context ctx;
	struct header_lookup_line *lines;
	const unsigned char *p, *start, *end;
	uint8_t *field_state;
	unsigned int i, count, max_field = 0;
	size_t hdr_size;
	uint8_t want = HDR_FIELD_STATE_WANT;
	buffer_t *buf;
	int ret;

	*pool_r = NULL;

	if (fields_count == 0)
		return 1;

	if (!view->cache->opened)
		(void)mail_cache_open_and_verify(view->cache);

	/* update the decision state regardless of whether the fields
	   actually exist or not. */
	for (i = 0; i < fields_count; i++)
		mail_cache_decision_state_update(view, seq, field_idxs[i]);

	/* mark all the fields we want to find. */
	buf = t_buffer_create(32);
	for (i = 0; i < fields_count; i++) {
		if (!mail_cache_file_has_field(cache, field_idxs[i]))
			return 0;

		if (field_idxs[i] > max_field)
			max_field = field_idxs[i];

		buffer_write(buf, field_idxs[i], &want, 1);
	}
	field_state = buffer_get_modifiable_data(buf, NULL);

	/* lookup the fields */
	i_zero(&ctx);
	ctx.view = view;
	ctx.pool = *pool_r = pool_alloconly_create(MEMPOOL_GROWING"mail cache headers", 1024);
	t_array_init(&ctx.lines, 32);

	mail_cache_lookup_iter_init(view, seq, &iter);
	while ((ret = mail_cache_lookup_iter_next(&iter, &field)) > 0) {
		if (field.field_idx > max_field ||
		    field_state[field.field_idx] != HDR_FIELD_STATE_WANT) {
			/* a) don't want it, b) duplicate */
		} else {
			field_state[field.field_idx] = HDR_FIELD_STATE_SEEN;
			header_lines_save(&ctx, &field);
		}

	}
	if (ret < 0)
		return -1;

	/* check that all fields were found */
	for (i = 0; i <= max_field; i++) {
		if (field_state[i] == HDR_FIELD_STATE_WANT)
			return 0;
	}

	/* we need to return headers in the order they existed originally.
	   we can do this by sorting the messages by their line numbers. */
	array_sort(&ctx.lines, header_lookup_line_cmp);
	lines = array_get_modifiable(&ctx.lines, &count);

	/* then start filling dest buffer from the headers */
	for (i = 0; i < count; i++) {
		start = lines[i].data->data;
		end = start + lines[i].data->data_size;

		/* find the end of the (multiline) header */
		for (p = start; p != end; p++) {
			if (*p == '\n' &&
			    (p+1 == end || (p[1] != ' ' && p[1] != '\t'))) {
				p++;
				break;
			}
		}
		hdr_size = (size_t)(p - start);
		buffer_append(dest, start, hdr_size);

		/* if there are more lines for this header, the following lines
		   continue after this one. so skip this line. */
		lines[i].data->data += hdr_size;
		lines[i].data->data_size -= hdr_size;
	}
	return 1;
}

int mail_cache_lookup_headers(struct mail_cache_view *view, string_t *dest,
			      uint32_t seq, unsigned int field_idxs[],
			      unsigned int fields_count)
{
	pool_t pool = NULL;
	int ret;

	if (buffer_get_pool(dest)->datastack_pool)
		ret = mail_cache_lookup_headers_real(view, dest, seq,
						     field_idxs, fields_count,
						     &pool);
	else T_BEGIN {
		ret = mail_cache_lookup_headers_real(view, dest, seq,
						     field_idxs, fields_count,
						     &pool);
	} T_END;
	pool_unref(&pool);
	return ret;
}

static uint32_t
mail_cache_get_highest_seq_with_cache(struct mail_cache_view *view,
				      uint32_t below_seq, uint32_t *reset_id_r)
{
	struct mail_cache_missing_reason_cache *rc = &view->reason_cache;
	uint32_t seq = below_seq-1, highest_checked_seq = 0;

	/* find the newest mail that has anything in cache */
	if (rc->log_file_head_offset == view->view->log_file_head_offset &&
	    rc->log_file_head_seq == view->view->log_file_head_seq) {
		/* reason_cache matches the current view - we can use it */
		highest_checked_seq = rc->highest_checked_seq;
	} else {
		rc->log_file_head_offset = view->view->log_file_head_offset;
		rc->log_file_head_seq = view->view->log_file_head_seq;
	}
	rc->highest_checked_seq = below_seq;

	/* first check anything not already in reason_cache */
	for (; seq > highest_checked_seq; seq--) {
		if (mail_cache_lookup_cur_offset(view->view, seq, reset_id_r) != 0) {
			rc->highest_seq_with_cache = seq;
			rc->reset_id = *reset_id_r;
			return seq;
		}
	}
	if (seq == 0)
		return 0;
	/* then return the result from cache */
	*reset_id_r = rc->reset_id;
	return rc->highest_seq_with_cache;
}

const char *
mail_cache_get_missing_reason(struct mail_cache_view *view, uint32_t seq)
{
	uint32_t offset, reset_id;

	if (MAIL_CACHE_IS_UNUSABLE(view->cache))
		return "Cache file is unusable";

	offset = mail_cache_lookup_cur_offset(view->view, seq, &reset_id);
	if (offset != 0) {
		if (view->cache->hdr->file_seq != reset_id) {
			return t_strdup_printf(
				"Index reset_id=%u doesn't match cache reset_id=%u",
				reset_id, view->cache->hdr->file_seq);
		}
		return t_strdup_printf(
			"Mail has other cached fields, reset_id=%u", reset_id);
	}
	seq = mail_cache_get_highest_seq_with_cache(view, seq, &reset_id);
	if (seq == 0) {
		return t_strdup_printf("Cache file is empty, reset_id=%u",
				       view->cache->hdr->file_seq);
	}

	uint32_t uid;
	mail_index_lookup_uid(view->view, seq, &uid);

	if (view->cache->hdr->file_seq != reset_id) {
		return t_strdup_printf(
			"Mail not cached, highest cached seq=%u uid=%u: "
			"Index reset_id=%u doesn't match cache reset_id=%u",
			seq, uid, reset_id, view->cache->hdr->file_seq);
	}
	return t_strdup_printf(
		"Mail not cached, highest cached seq=%u uid=%u: reset_id=%u",
		seq, uid, reset_id);
}
