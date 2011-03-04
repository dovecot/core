/* Copyright (c) 2008-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-transaction-log-private.h"
#include "mail-index-private.h"
#include "mail-index-sync-private.h"
#include "mail-index-modseq.h"

ARRAY_DEFINE_TYPE(modseqs, uint64_t);

enum modseq_metadata_idx {
	/* must be in the same order as enum mail_flags */
	METADATA_MODSEQ_IDX_ANSWERED = 0,
	METADATA_MODSEQ_IDX_FLAGGED,
	METADATA_MODSEQ_IDX_DELETED,
	METADATA_MODSEQ_IDX_SEEN,
	METADATA_MODSEQ_IDX_DRAFT,

	METADATA_MODSEQ_IDX_KEYWORD_START
};

struct metadata_modseqs {
	ARRAY_TYPE(modseqs) modseqs;
};

struct mail_index_map_modseq {
	/* indexes use enum modseq_metadata_idx */
	ARRAY_DEFINE(metadata_modseqs, struct metadata_modseqs);
};

struct mail_index_modseq_sync {
	struct mail_index_sync_map_ctx *sync_map_ctx;
	struct mail_index_view *view;
	struct mail_transaction_log_view *log_view;
	struct mail_index_map_modseq *mmap;

	uint64_t highest_modseq;
};

void mail_index_modseq_init(struct mail_index *index)
{
	index->modseq_ext_id =
		mail_index_ext_register(index, MAIL_INDEX_MODSEQ_EXT_NAME,
					sizeof(struct mail_index_modseq_header),
					sizeof(uint64_t), sizeof(uint64_t));
}

static uint64_t mail_index_modseq_get_head(struct mail_index *index)
{
	return index->log->head == NULL ? 1 :
		I_MAX(index->log->head->sync_highest_modseq, 1);
}

void mail_index_modseq_enable(struct mail_index *index)
{
	struct mail_index_transaction *trans;
	struct mail_index_view *view;
	struct mail_index_modseq_header hdr;
	uint32_t ext_map_idx;

	if (index->modseqs_enabled)
		return;

	if (!mail_index_map_get_ext_idx(index->map, index->modseq_ext_id,
					&ext_map_idx)) {
		/* modseqs not enabled to the index yet, add them. */
		view = mail_index_view_open(index);
		trans = mail_index_transaction_begin(view, 0);

		memset(&hdr, 0, sizeof(hdr));
		hdr.highest_modseq = mail_index_modseq_get_head(index);
		mail_index_update_header_ext(trans, index->modseq_ext_id,
					     0, &hdr, sizeof(hdr));

		/* commit also refreshes the index, which syncs the modseqs */
		(void)mail_index_transaction_commit(&trans);
		mail_index_view_close(&view);

		/* get the modseq extension to index map */
		if (!mail_index_map_get_ext_idx(index->map,
						index->modseq_ext_id,
						&ext_map_idx)) {
			/* didn't work for some reason */
			return;
		}
	}
	index->modseqs_enabled = TRUE;
}

const struct mail_index_modseq_header *
mail_index_map_get_modseq_header(struct mail_index_map *map)
{
	const struct mail_index_ext *ext;
	uint32_t idx;

	if (!mail_index_map_get_ext_idx(map, map->index->modseq_ext_id, &idx))
		return NULL;

	ext = array_idx(&map->extensions, idx);
	if (ext->hdr_size != sizeof(struct mail_index_modseq_header))
		return NULL;

	return CONST_PTR_OFFSET(map->hdr_base, ext->hdr_offset);
}

uint64_t mail_index_map_modseq_get_highest(struct mail_index_map *map)
{
	const struct mail_index_modseq_header *modseq_hdr;

	modseq_hdr = mail_index_map_get_modseq_header(map);
	if (modseq_hdr != NULL && modseq_hdr->highest_modseq != 0)
		return modseq_hdr->highest_modseq;
	else {
		/* fallback to returning the log head. if modseqs aren't
		   enabled, we return 0. */
		return map->index->log->head == NULL ? 0 :
			map->index->log->head->sync_highest_modseq;
	}
}

uint64_t mail_index_modseq_get_highest(struct mail_index_view *view)
{
	return mail_index_map_modseq_get_highest(view->map);
}

static struct mail_index_map_modseq *
mail_index_map_modseq(struct mail_index_view *view)
{
	struct mail_index_map_modseq *mmap = view->map->rec_map->modseq;
	uint32_t ext_map_idx;

	if (mmap != NULL)
		return mmap;

	/* don't start tracking until we've seen modseq extension intro */
	if (!mail_index_map_get_ext_idx(view->map, view->index->modseq_ext_id,
					&ext_map_idx))
		return NULL;

	mmap = i_new(struct mail_index_map_modseq, 1);
	i_array_init(&mmap->metadata_modseqs,
		     METADATA_MODSEQ_IDX_KEYWORD_START +
		     array_count(&view->index->keywords));
	view->map->rec_map->modseq = mmap;
	return mmap;
}

uint64_t mail_index_modseq_lookup(struct mail_index_view *view, uint32_t seq)
{
	struct mail_index_map_modseq *mmap = mail_index_map_modseq(view);
	struct mail_index_map *map;
	const struct mail_index_ext *ext;
	const struct mail_index_record *rec;
	const uint64_t *modseqp;
	uint32_t ext_map_idx;

	if (mmap == NULL)
		return mail_index_modseq_get_head(view->index);

	rec = mail_index_lookup_full(view, seq, &map);
	if (!mail_index_map_get_ext_idx(map, view->index->modseq_ext_id,
					&ext_map_idx)) {
		/* not enabled yet */
		return mail_index_modseq_get_head(view->index);
	}

	ext = array_idx(&map->extensions, ext_map_idx);
	modseqp = CONST_PTR_OFFSET(rec, ext->record_offset);
	if (*modseqp == 0) {
		/* If we're here because we just enabled modseqs, we'll return
		   the same modseq (initial highestmodseq) for all messages.
		   The next sync will change these zeros to initial
		   highestmodseq or higher.

		   If we're here because a message got appended but modseq
		   wasn't set (older Dovecot?), we'll again use the current
		   highest modseq. This isn't exactly correct, but it gets
		   fixed after the next sync and this situation shouldn't
		   normally happen anyway. */
		return mail_index_modseq_get_highest(view);
	}
	return *modseqp;
}

int mail_index_modseq_set(struct mail_index_view *view,
			  uint32_t seq, uint64_t min_modseq)
{
	struct mail_index_map_modseq *mmap = mail_index_map_modseq(view);
	const struct mail_index_ext *ext;
	struct mail_index_record *rec;
	uint64_t *modseqp;
	uint32_t ext_map_idx;

	if (mmap == NULL)
		return -1;

	rec = MAIL_INDEX_MAP_IDX(view->map, seq-1);
	if (!mail_index_map_get_ext_idx(view->map, view->index->modseq_ext_id,
					&ext_map_idx))
		return -1;

	ext = array_idx(&view->map->extensions, ext_map_idx);
	modseqp = PTR_OFFSET(rec, ext->record_offset);
	if (*modseqp > min_modseq)
		return 0;
	else {
		*modseqp = min_modseq;
		return 1;
	}
}

static uint64_t
modseq_idx_lookup(struct mail_index_map_modseq *mmap,
		  unsigned int idx, uint32_t seq)
{
	const struct metadata_modseqs *metadata;
	const uint64_t *modseqs;
	unsigned int count;

	metadata = array_get(&mmap->metadata_modseqs, &count);
	if (idx >= count || !array_is_created(&metadata[idx].modseqs))
		return 0;

	modseqs = array_get(&metadata[idx].modseqs, &count);
	return seq > count ? 0 : modseqs[seq-1];
}

uint64_t mail_index_modseq_lookup_flags(struct mail_index_view *view,
					enum mail_flags flags_mask,
					uint32_t seq)
{
	struct mail_index_map_modseq *mmap = mail_index_map_modseq(view);
	unsigned int i;
	uint64_t modseq, highest_modseq = 0;

	if (mmap != NULL) {
		/* first try to find a specific match */
		for (i = 0; i < METADATA_MODSEQ_IDX_KEYWORD_START; i++) {
			if ((flags_mask & (1 << i)) != 0) {
				modseq = modseq_idx_lookup(mmap, i, seq);
				if (highest_modseq < modseq)
					highest_modseq = modseq;
			}
		}
	}

	if (highest_modseq == 0) {
		/* no specific matches, fallback to using the highest */
		highest_modseq = mail_index_modseq_lookup(view, seq);
	}
	return highest_modseq;
}

uint64_t mail_index_modseq_lookup_keywords(struct mail_index_view *view,
					   const struct mail_keywords *keywords,
					   uint32_t seq)
{
	struct mail_index_map_modseq *mmap = mail_index_map_modseq(view);
	unsigned int i, metadata_idx;
	uint64_t modseq, highest_modseq = 0;

	if (mmap != NULL) {
		/* first try to find a specific match */
		for (i = 0; i < keywords->count; i++) {
			metadata_idx = METADATA_MODSEQ_IDX_KEYWORD_START +
				keywords->idx[i];

			modseq = modseq_idx_lookup(mmap, metadata_idx, seq);
			if (highest_modseq < modseq)
				highest_modseq = modseq;
		}
	}

	if (highest_modseq == 0) {
		/* no specific matches, fallback to using the highest */
		highest_modseq = mail_index_modseq_lookup(view, seq);
	}
	return highest_modseq;
}

static void
mail_index_modseq_update(struct mail_index_modseq_sync *ctx,
			 uint64_t modseq, bool nonzeros,
			 uint32_t seq1, uint32_t seq2)
{
	const struct mail_index_ext *ext;
	struct mail_index_record *rec;
	uint32_t ext_map_idx;
	uint64_t *modseqp;

	if (!mail_index_map_get_ext_idx(ctx->view->map,
					ctx->view->index->modseq_ext_id,
					&ext_map_idx))
		return;

	if (modseq > ctx->highest_modseq)
		ctx->highest_modseq = modseq;

	ext = array_idx(&ctx->view->map->extensions, ext_map_idx);
	for (; seq1 <= seq2; seq1++) {
		rec = MAIL_INDEX_MAP_IDX(ctx->view->map, seq1-1);
		modseqp = PTR_OFFSET(rec, ext->record_offset);
		if (*modseqp == 0 || (nonzeros && *modseqp < modseq))
			*modseqp = modseq;
	}
}

static bool
mail_index_modseq_update_to_highest(struct mail_index_modseq_sync *ctx,
				    uint32_t seq1, uint32_t seq2)
{
	uint64_t modseq;

	if (ctx->mmap == NULL)
		return FALSE;

	modseq = mail_transaction_log_view_get_prev_modseq(ctx->log_view);
	mail_index_modseq_update(ctx, modseq, TRUE, seq1, seq2);
	return TRUE;
}

static void
mail_index_modseq_update_old_rec(struct mail_index_modseq_sync *ctx,
				 const struct mail_transaction_header *thdr,
				 const void *tdata)
{
	ARRAY_TYPE(seq_range) uids = ARRAY_INIT;
	const struct seq_range *rec;
	buffer_t uid_buf;
	unsigned int i, count;
	uint32_t seq1, seq2;

	switch (thdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_APPEND: {
		const struct mail_index_record *appends = tdata;

		count = thdr->size / sizeof(*appends);
		for (i = 0; i < count; i++) {
			if (mail_index_lookup_seq(ctx->view,
						  appends[i].uid, &seq1)) {
				mail_index_modseq_update_to_highest(ctx, seq1,
								    seq1);
			}
		}
		return;
	}
	case MAIL_TRANSACTION_FLAG_UPDATE: {
		buffer_create_const_data(&uid_buf, tdata, thdr->size);
		array_create_from_buffer(&uids, &uid_buf,
			sizeof(struct mail_transaction_flag_update));
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_UPDATE: {
		const struct mail_transaction_keyword_update *rec = tdata;
		unsigned int seqset_offset;

		seqset_offset = sizeof(*rec) + rec->name_size;
		if ((seqset_offset % 4) != 0)
			seqset_offset += 4 - (seqset_offset % 4);

		buffer_create_const_data(&uid_buf,
					 CONST_PTR_OFFSET(tdata, seqset_offset),
					 thdr->size - seqset_offset);
		array_create_from_buffer(&uids, &uid_buf, sizeof(uint32_t)*2);
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_RESET:
		buffer_create_const_data(&uid_buf, tdata, thdr->size);
		array_create_from_buffer(&uids, &uid_buf,
			sizeof(struct mail_transaction_keyword_reset));
		break;
	default:
		return;
	}

	/* update modseqs */
	count = array_count(&uids);
	for (i = 0; i < count; i++) {
		rec = array_idx(&uids, i);
		if (mail_index_lookup_seq_range(ctx->view, rec->seq1, rec->seq2,
						&seq1, &seq2))
			mail_index_modseq_update_to_highest(ctx, seq1, seq2);
	}
}

static void mail_index_modseq_sync_init(struct mail_index_modseq_sync *ctx)
{
	struct mail_index_map *map = ctx->view->map;
	const struct mail_index_ext *ext;
	const struct mail_index_modseq_header *hdr;
	const struct mail_transaction_header *thdr;
	const void *tdata;
	uint32_t ext_map_idx;
	uint32_t end_seq;
	uoff_t end_offset;
	uint64_t cur_modseq;
	bool reset;
	int ret;

	if (!mail_index_map_get_ext_idx(map, ctx->view->index->modseq_ext_id,
					&ext_map_idx))
		i_unreached();
	ext = array_idx(&map->extensions, ext_map_idx);

	/* get the current highest_modseq. don't change any modseq below it. */
	hdr = CONST_PTR_OFFSET(map->hdr_base, ext->hdr_offset);
	ctx->highest_modseq = hdr->highest_modseq;

	/* Scan logs for updates between ext_hdr.log_* .. view position.
	   There are two reasons why there could be any:

	   1) We just enabled modseqs and we're filling the initial values.
	   2) A non-modseq-aware Dovecot version added new messages and wrote
	      dovecot.index file. */
	mail_transaction_log_view_get_prev_pos(ctx->view->log_view,
					       &end_seq, &end_offset);
	if (end_seq <= hdr->log_seq ||
	    (end_seq == hdr->log_seq && end_offset <= hdr->log_offset)) {
		/* modseqs are up to date */
		return;
	}

	ctx->log_view = mail_transaction_log_view_open(ctx->view->index->log);
	ret = mail_transaction_log_view_set(ctx->log_view,
					    I_MAX(1, hdr->log_seq),
					    hdr->log_offset,
					    end_seq, end_offset, &reset);
	if (ret == 0) {
		/* missing files - try with only the last file */
		ret = mail_transaction_log_view_set(ctx->log_view, end_seq, 0,
						    end_seq, end_offset,
						    &reset);
		/* since we don't know if we skipped some changes, set all
		   modseqs to beginning of the latest file. */
		cur_modseq = mail_transaction_log_view_get_prev_modseq(
								ctx->log_view);
		if (cur_modseq < hdr->highest_modseq) {
			/* should happen only when setting initial modseqs.
			   we may already have returned highest_modseq as
			   some messages' modseq value. don't shrink it. */
			cur_modseq = hdr->highest_modseq;
		}
		mail_index_modseq_update(ctx, cur_modseq, TRUE, 1,
					 map->hdr.messages_count);
	} else {
		/* we have all the logs. replace zero modseqs with the current
		   highest modseq (we may have already returned it for them). */
		mail_index_modseq_update(ctx, hdr->highest_modseq, FALSE, 1,
					 map->hdr.messages_count);
	}
	if (ret > 0) {
		while (mail_transaction_log_view_next(ctx->log_view,
						      &thdr, &tdata) > 0) {
			T_BEGIN {
				mail_index_modseq_update_old_rec(ctx, thdr,
								 tdata);
			} T_END;
		}
	}
	mail_index_sync_write_seq_update(ctx->sync_map_ctx, 1,
					 map->hdr.messages_count);
	mail_transaction_log_view_close(&ctx->log_view);
}

struct mail_index_modseq_sync *
mail_index_modseq_sync_begin(struct mail_index_sync_map_ctx *sync_map_ctx)
{
	struct mail_index_modseq_sync *ctx;

	ctx = i_new(struct mail_index_modseq_sync, 1);
	ctx->sync_map_ctx = sync_map_ctx;
	ctx->view = sync_map_ctx->view;
	ctx->mmap = mail_index_map_modseq(ctx->view);
	if (ctx->mmap != NULL) {
		mail_index_modseq_sync_init(ctx);
		ctx->log_view = ctx->view->log_view;
	}
	return ctx;
}

static void mail_index_modseq_update_header(struct mail_index_view *view,
					    uint64_t highest_modseq)
{
	struct mail_index_map *map = view->map;
	const struct mail_index_ext *ext;
	const struct mail_index_modseq_header *old_modseq_hdr;
	struct mail_index_modseq_header new_modseq_hdr;
	uint32_t ext_map_idx, log_seq;
	uoff_t log_offset;

	if (!mail_index_map_get_ext_idx(map, view->index->modseq_ext_id,
					&ext_map_idx))
		return;

	mail_transaction_log_view_get_prev_pos(view->log_view,
					       &log_seq, &log_offset);

	ext = array_idx(&map->extensions, ext_map_idx);
	old_modseq_hdr = CONST_PTR_OFFSET(map->hdr_base, ext->hdr_offset);

	if (old_modseq_hdr->log_seq < log_seq ||
	    (old_modseq_hdr->log_seq == log_seq &&
	     old_modseq_hdr->log_offset < log_offset)) {
		memset(&new_modseq_hdr, 0, sizeof(new_modseq_hdr));
		new_modseq_hdr.highest_modseq = highest_modseq;
		new_modseq_hdr.log_seq = log_seq;
		new_modseq_hdr.log_offset = log_offset;

		buffer_write(map->hdr_copy_buf, ext->hdr_offset,
			     &new_modseq_hdr, sizeof(new_modseq_hdr));
		map->hdr_base = map->hdr_copy_buf->data;
		map->write_ext_header = TRUE;
	}
}

void mail_index_modseq_sync_end(struct mail_index_modseq_sync **_ctx)
{
	struct mail_index_modseq_sync *ctx = *_ctx;

	*_ctx = NULL;
	if (ctx->mmap != NULL) {
		i_assert(ctx->mmap == ctx->view->map->rec_map->modseq);
		mail_index_modseq_update_header(ctx->view, ctx->highest_modseq);
	}
	i_free(ctx);
}

void mail_index_modseq_sync_map_replaced(struct mail_index_modseq_sync *ctx)
{
	ctx->mmap = mail_index_map_modseq(ctx->view);
}

void mail_index_modseq_hdr_update(struct mail_index_modseq_sync *ctx)
{
	if (ctx->mmap == NULL) {
		ctx->mmap = mail_index_map_modseq(ctx->view);
		i_assert(ctx->mmap != NULL);
		mail_index_modseq_sync_init(ctx);
		ctx->log_view = ctx->view->log_view;
	}
}

void mail_index_modseq_append(struct mail_index_modseq_sync *ctx, uint32_t seq)
{
	mail_index_modseq_update_to_highest(ctx, seq, seq);
}

void mail_index_modseq_expunge(struct mail_index_modseq_sync *ctx,
			       uint32_t seq1, uint32_t seq2)
{
	struct metadata_modseqs *metadata;
	uint64_t modseq;

	if (ctx->mmap == NULL)
		return;

	seq1--;
	array_foreach_modifiable(&ctx->mmap->metadata_modseqs, metadata) {
		if (array_is_created(&metadata->modseqs))
			array_delete(&metadata->modseqs, seq1, seq2-seq1);
	}

	modseq = mail_transaction_log_view_get_prev_modseq(ctx->log_view);
	if (ctx->highest_modseq < modseq)
		ctx->highest_modseq = modseq;
}

static void
modseqs_update(ARRAY_TYPE(modseqs) *array, uint32_t seq1, uint32_t seq2,
	       uint64_t value)
{
	for (; seq1 <= seq2; seq1++)
		array_idx_set(array, seq1-1, &value);
}

static void
modseqs_idx_update(struct mail_index_modseq_sync *ctx, unsigned int idx,
		   uint32_t seq1, uint32_t seq2)
{
	struct metadata_modseqs *metadata;

	if (!ctx->view->index->modseqs_enabled) {
		/* we want to keep permanent modseqs updated, but don't bother
		   updating in-memory per-flag updates */
		return;
	}

	metadata = array_idx_modifiable(&ctx->mmap->metadata_modseqs, idx);
	if (!array_is_created(&metadata->modseqs))
		i_array_init(&metadata->modseqs, seq2 + 16);
	modseqs_update(&metadata->modseqs, seq1, seq2, ctx->highest_modseq);
}

void mail_index_modseq_update_flags(struct mail_index_modseq_sync *ctx,
				    enum mail_flags flags_mask,
				    uint32_t seq1, uint32_t seq2)
{
	unsigned int i;

	if (!mail_index_modseq_update_to_highest(ctx, seq1, seq2))
		return;

	for (i = 0; i < METADATA_MODSEQ_IDX_KEYWORD_START; i++) {
		if ((flags_mask & (1 << i)) != 0)
			modseqs_idx_update(ctx, i, seq1, seq2);
	}
}

void mail_index_modseq_update_keyword(struct mail_index_modseq_sync *ctx,
				      unsigned int keyword_idx,
				      uint32_t seq1, uint32_t seq2)
{
	if (!mail_index_modseq_update_to_highest(ctx, seq1, seq2))
		return;

	modseqs_idx_update(ctx, METADATA_MODSEQ_IDX_KEYWORD_START + keyword_idx,
			   seq1, seq2);
}

void mail_index_modseq_reset_keywords(struct mail_index_modseq_sync *ctx,
				      uint32_t seq1, uint32_t seq2)
{
	unsigned int i, count;

	if (!mail_index_modseq_update_to_highest(ctx, seq1, seq2))
		return;

	count = array_count(&ctx->mmap->metadata_modseqs);
	for (i = METADATA_MODSEQ_IDX_KEYWORD_START; i < count; i++)
		modseqs_idx_update(ctx, i, seq1, seq2);
}

void mail_index_modseq_update_highest(struct mail_index_modseq_sync *ctx,
				      uint64_t highest_modseq)
{
	if (ctx->highest_modseq < highest_modseq)
		ctx->highest_modseq = highest_modseq;
}

struct mail_index_map_modseq *
mail_index_map_modseq_clone(const struct mail_index_map_modseq *mmap)
{
	struct mail_index_map_modseq *new_mmap;
	const struct metadata_modseqs *src_metadata;
	struct metadata_modseqs *dest_metadata;
	unsigned int i, count;

	src_metadata = array_get(&mmap->metadata_modseqs, &count);

	new_mmap = i_new(struct mail_index_map_modseq, 1);
	i_array_init(&new_mmap->metadata_modseqs, count + 16);

	for (i = 0; i < count; i++) {
		dest_metadata = array_append_space(&new_mmap->metadata_modseqs);
		if (array_is_created(&src_metadata[i].modseqs)) {
			i_array_init(&dest_metadata->modseqs,
				     array_count(&src_metadata[i].modseqs));
			array_append_array(&dest_metadata->modseqs,
					   &src_metadata[i].modseqs);
		}
	}
	return new_mmap;
}

void mail_index_map_modseq_free(struct mail_index_map_modseq **_mmap)
{
	struct mail_index_map_modseq *mmap = *_mmap;
	struct metadata_modseqs *metadata;

	*_mmap = NULL;

	array_foreach_modifiable(&mmap->metadata_modseqs, metadata) {
		if (array_is_created(&metadata->modseqs))
			array_free(&metadata->modseqs);
	}
	array_free(&mmap->metadata_modseqs);
	i_free(mmap);
}

bool mail_index_modseq_get_next_log_offset(struct mail_index_view *view,
					   uint64_t modseq, uint32_t *log_seq_r,
					   uoff_t *log_offset_r)
{
	struct mail_transaction_log_file *file, *prev_file = NULL;

	for (file = view->index->log->files; file != NULL; file = file->next) {
		if (modseq < file->hdr.initial_modseq)
			break;
		prev_file = file;
	}

	if (prev_file == NULL) {
		/* the log file has been deleted already */
		return FALSE;
	}

	*log_seq_r = prev_file->hdr.file_seq;
	return mail_transaction_log_file_get_modseq_next_offset(
					prev_file, modseq, log_offset_r) == 0;
}
