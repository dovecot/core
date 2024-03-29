/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "buffer.h"
#include "mail-index-view-private.h"
#include "mail-index-sync-private.h"
#include "mail-index-modseq.h"
#include "mail-transaction-log.h"


struct mail_index_view_sync_ctx {
	struct mail_index_view *view;
	enum mail_index_view_sync_flags flags;
	struct mail_index_sync_map_ctx sync_map_ctx;

	/* After syncing view, map is replaced with sync_new_map. */
	struct mail_index_map *sync_new_map;

	ARRAY_TYPE(seq_range) expunges;
	unsigned int finish_min_msg_count;

	const struct mail_transaction_header *hdr;
	const void *data;

	/* temporary variables while handling lost transaction logs: */
	ARRAY_TYPE(keyword_indexes) lost_old_kw, lost_new_kw;
	buffer_t *lost_kw_buf;
	uint32_t lost_new_ext_idx;
	/* result of lost transaction logs: */
	ARRAY_TYPE(seq_range) lost_flags;
	unsigned int lost_flag_idx;

	size_t data_offset;
	bool failed:1;
	bool sync_map_update:1;
	bool skipped_expunges:1;
	bool last_read:1;
	bool log_was_lost:1;
	bool hidden:1;
};

static int
view_sync_set_log_view_range(struct mail_index_view *view, bool sync_expunges,
			     bool *reset_r, bool *partial_sync_r,
			     const char **error_r)
{
	const struct mail_index_header *hdr = &view->index->map->hdr;
	uint32_t start_seq, end_seq;
	uoff_t start_offset, end_offset;
	const char *reason;
	int ret;

	*partial_sync_r = FALSE;

	if (sync_expunges) {
		/* Sync everything after the last expunge syncing position.
		   We'll just skip over the non-expunge transaction records
		   that have already been synced previously. */
		start_seq = view->log_file_expunge_seq;
		start_offset = view->log_file_expunge_offset;
	} else {
		/* Sync only new changes since the last view sync. */
		start_seq = view->log_file_head_seq;
		start_offset = view->log_file_head_offset;
	}
	/* Sync the view up to the (already refreshed) index map. */
        end_seq = hdr->log_file_seq;
        end_offset = hdr->log_file_head_offset;

	if (end_seq < view->log_file_head_seq ||
	    (end_seq == view->log_file_head_seq &&
	     end_offset < view->log_file_head_offset)) {
		*error_r = t_strdup_printf(
			"%s log position went backwards "
			"(%u,%"PRIuUOFF_T" < %u,%"PRIuUOFF_T")",
			view->index->filepath, end_seq, end_offset,
			view->log_file_head_seq, view->log_file_head_offset);
		return -1;
	}

	for (;;) {
		/* the view begins from the first non-synced transaction */
		ret = mail_transaction_log_view_set(view->log_view,
						    start_seq, start_offset,
						    end_seq, end_offset,
						    reset_r, &reason);
		if (ret <= 0) {
			*error_r = t_strdup_printf(
				"Failed to map view for %s: %s",
				view->index->filepath, reason);
			return ret;
		}

		if (!*reset_r || sync_expunges)
			break;

		/* log was reset, but we don't want to sync expunges.
		   we can't do this, so sync only up to the reset. */
		mail_transaction_log_view_get_prev_pos(view->log_view,
						       &end_seq, &end_offset);
		end_seq--; end_offset = UOFF_T_MAX;
		if (end_seq < start_seq) {
			/* we have only this reset log */
			mail_transaction_log_view_clear(view->log_view,
				view->log_file_expunge_seq);
			break;
		}
		*partial_sync_r = TRUE;
	}
	return 1;
}

static unsigned int
view_sync_expunges2seqs(struct mail_index_view_sync_ctx *ctx)
{
	struct mail_index_view *view = ctx->view;
	struct seq_range *src, *src_end, *dest;
	unsigned int count, expunge_count = 0;
	uint32_t prev_seq = 0;

	/* convert UIDs to sequences */
	src = dest = array_get_modifiable(&ctx->expunges, &count);
	src_end = src + count;
	for (; src != src_end; src++) {
		if (!mail_index_lookup_seq_range(view, src->seq1, src->seq2,
						 &dest->seq1, &dest->seq2))
			count--;
		else {
			i_assert(dest->seq1 > prev_seq);
			prev_seq = dest->seq2;

			expunge_count += dest->seq2 - dest->seq1 + 1;
			dest++;
		}
	}
	array_delete(&ctx->expunges, count,
		     array_count(&ctx->expunges) - count);
	return expunge_count;
}

static void
view_sync_add_expunge_range(ARRAY_TYPE(seq_range) *dest,
			    const struct seq_range *src, size_t src_size)
{
	unsigned int i, src_count;

	i_assert(src_size % sizeof(*src) == 0);

	src_count = src_size / sizeof(*src);
	for (i = 0; i < src_count; i++)
		seq_range_array_add_range(dest, src[i].seq1, src[i].seq2);
}

static void
view_sync_add_expunge_guids(ARRAY_TYPE(seq_range) *dest,
			    const struct mail_transaction_expunge_guid *src,
			    size_t src_size)
{
	unsigned int i, src_count;

	i_assert(src_size % sizeof(*src) == 0);

	src_count = src_size / sizeof(*src);
	for (i = 0; i < src_count; i++)
		seq_range_array_add(dest, src[i].uid);
}

static int
view_sync_get_expunges(struct mail_index_view_sync_ctx *ctx,
		       unsigned int *expunge_count_r)
{
	struct mail_index_view *view = ctx->view;
	const struct mail_transaction_header *hdr;
	const void *data;
	int ret;

	/* get a list of expunge transactions. there may be some that we have
	   already synced, but it doesn't matter because they'll get dropped
	   out when converting to sequences. the uid ranges' validity has
	   already been verified, so we can use them directly. */
	mail_transaction_log_view_mark(view->log_view);
	while ((ret = mail_transaction_log_view_next(view->log_view,
						     &hdr, &data)) > 0) {
		if ((hdr->type & MAIL_TRANSACTION_EXTERNAL) == 0) {
			/* skip expunge requests */
			continue;
		}
		if ((hdr->type & MAIL_TRANSACTION_EXPUNGE_GUID) != 0) {
			view_sync_add_expunge_guids(&ctx->expunges,
						    data, hdr->size);
		} else if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0) {
			view_sync_add_expunge_range(&ctx->expunges,
						    data, hdr->size);
		}
	}
	mail_transaction_log_view_rewind(view->log_view);

	*expunge_count_r = view_sync_expunges2seqs(ctx);
	return ret;
}

static bool have_existing_expunges(struct mail_index_view *view,
				   const struct seq_range *range, size_t size)
{
	const struct seq_range *range_end;
	uint32_t seq1, seq2;

	range_end = CONST_PTR_OFFSET(range, size);
	for (; range != range_end; range++) {
		if (mail_index_lookup_seq_range(view, range->seq1, range->seq2,
						&seq1, &seq2))
			return TRUE;
	}
	return FALSE;
}

static bool
have_existing_guid_expunge(struct mail_index_view *view,
			   const struct mail_transaction_expunge_guid *expunges,
			   size_t size)
{
	const struct mail_transaction_expunge_guid *expunges_end;
	uint32_t seq;

	expunges_end = CONST_PTR_OFFSET(expunges, size);
	for (; expunges != expunges_end; expunges++) {
		if (mail_index_lookup_seq(view, expunges->uid, &seq))
			return TRUE;
	}
	return FALSE;
}

static bool view_sync_have_expunges(struct mail_index_view *view)
{
	const struct mail_transaction_header *hdr;
	const void *data;
	bool have_expunges = FALSE;
	int ret;

	if (mail_transaction_log_view_is_last(view->log_view))
		return FALSE;

	mail_transaction_log_view_mark(view->log_view);

	while ((ret = mail_transaction_log_view_next(view->log_view,
						     &hdr, &data)) > 0) {
		if ((hdr->type & MAIL_TRANSACTION_EXTERNAL) == 0) {
			/* skip expunge requests */
			continue;
		}
		if ((hdr->type & MAIL_TRANSACTION_EXPUNGE_GUID) != 0) {
			/* we have an expunge. see if it still exists. */
			if (have_existing_guid_expunge(view, data, hdr->size)) {
				have_expunges = TRUE;
				break;
			}
		} else if ((hdr->type & MAIL_TRANSACTION_EXPUNGE) != 0) {
			/* we have an expunge. see if it still exists. */
			if (have_existing_expunges(view, data, hdr->size)) {
				have_expunges = TRUE;
				break;
			}
		}
	}

	mail_transaction_log_view_rewind(view->log_view);

	/* handle failures as having expunges (which is safer).
	   we'll probably fail later. */
	return ret < 0 || have_expunges;
}

static int uint_cmp(const void *p1, const void *p2)
{
	const unsigned int *u1 = p1, *u2 = p2;

	if (*u1 < *u2)
		return -1;
	if (*u1 > *u2)
		return 1;
	return 0;
}

static bool view_sync_lost_keywords_equal(struct mail_index_view_sync_ctx *ctx)
{
	unsigned int *old_idx, *new_idx;
	unsigned int old_count, new_count;

	old_idx = array_get_modifiable(&ctx->lost_old_kw, &old_count);
	new_idx = array_get_modifiable(&ctx->lost_new_kw, &new_count);
	if (old_count != new_count)
		return FALSE;

	qsort(old_idx, old_count, sizeof(*old_idx), uint_cmp);
	qsort(new_idx, new_count, sizeof(*new_idx), uint_cmp);
	return memcmp(old_idx, new_idx, old_count * sizeof(*old_idx)) == 0;
}

static int view_sync_update_keywords(struct mail_index_view_sync_ctx *ctx,
				     uint32_t uid)
{
	struct mail_transaction_header thdr;
	struct mail_transaction_keyword_update kw_up;
	const unsigned int *kw_idx;
	const char *const *kw_names;
	unsigned int i, count;

	kw_idx = array_get(&ctx->lost_new_kw, &count);
	if (count == 0)
		return 0;
	kw_names = array_front(&ctx->view->index->keywords);

	i_zero(&thdr);
	thdr.type = MAIL_TRANSACTION_KEYWORD_UPDATE | MAIL_TRANSACTION_EXTERNAL;
	i_zero(&kw_up);
	kw_up.modify_type = MODIFY_ADD;
	/* add new flags one by one */
	for (i = 0; i < count; i++) {
		kw_up.name_size = strlen(kw_names[kw_idx[i]]);
		buffer_set_used_size(ctx->lost_kw_buf, 0);
		buffer_append(ctx->lost_kw_buf, &kw_up, sizeof(kw_up));
		buffer_append(ctx->lost_kw_buf, kw_names[kw_idx[i]],
			      kw_up.name_size);
		if (ctx->lost_kw_buf->used % 4 != 0) {
			buffer_append_zero(ctx->lost_kw_buf,
					   4 - ctx->lost_kw_buf->used % 4);
		}
		buffer_append(ctx->lost_kw_buf, &uid, sizeof(uid));
		buffer_append(ctx->lost_kw_buf, &uid, sizeof(uid));

		thdr.size = ctx->lost_kw_buf->used;
		if (mail_index_sync_record(&ctx->sync_map_ctx, &thdr,
					   ctx->lost_kw_buf->data) < 0)
			return -1;
	}
	return 0;
}

static int view_sync_apply_lost_changes(struct mail_index_view_sync_ctx *ctx,
					uint32_t old_seq, uint32_t new_seq)
{
	struct mail_index_map *old_map = ctx->view->map;
	struct mail_index_map *new_map = ctx->view->index->map;
	const struct mail_index_record *old_rec, *new_rec;
	struct mail_transaction_header thdr;
	const struct mail_index_ext *ext;
	const uint64_t *modseqp;
	uint64_t new_modseq;
	bool changed = FALSE;

	old_rec = MAIL_INDEX_REC_AT_SEQ(old_map, old_seq);
	new_rec = MAIL_INDEX_REC_AT_SEQ(new_map, new_seq);

	i_zero(&thdr);
	if (old_rec->flags != new_rec->flags) {
		struct mail_transaction_flag_update flag_update;

		/* check this before syncing the record, since it updates
		   old_rec. */
		if ((old_rec->flags & MAIL_INDEX_FLAGS_MASK) !=
		    (new_rec->flags & MAIL_INDEX_FLAGS_MASK))
			changed = TRUE;

		thdr.type = MAIL_TRANSACTION_FLAG_UPDATE |
			MAIL_TRANSACTION_EXTERNAL;
		thdr.size = sizeof(flag_update);

		i_zero(&flag_update);
		flag_update.uid1 = flag_update.uid2 = new_rec->uid;
		flag_update.add_flags = new_rec->flags;
		flag_update.remove_flags = ~new_rec->flags & 0xff;
		if (mail_index_sync_record(&ctx->sync_map_ctx, &thdr,
					   &flag_update) < 0)
			return -1;
	}

	mail_index_map_lookup_keywords(old_map, old_seq, &ctx->lost_old_kw);
	mail_index_map_lookup_keywords(new_map, new_seq, &ctx->lost_new_kw);
	if (!view_sync_lost_keywords_equal(ctx)) {
		struct mail_transaction_keyword_reset kw_reset;

		thdr.type = MAIL_TRANSACTION_KEYWORD_RESET |
			MAIL_TRANSACTION_EXTERNAL;
		thdr.size = sizeof(kw_reset);

		/* remove all old flags by resetting them */
		i_zero(&kw_reset);
		kw_reset.uid1 = kw_reset.uid2 = new_rec->uid;
		if (mail_index_sync_record(&ctx->sync_map_ctx, &thdr,
					   &kw_reset) < 0)
			return -1;

		if (view_sync_update_keywords(ctx, new_rec->uid) < 0)
			return -1;
		changed = TRUE;
	}

	if (changed) {
		/* flags or keywords changed */
	} else if (ctx->view->highest_modseq != 0 &&
		   ctx->lost_new_ext_idx != (uint32_t)-1) {
		/* if modseq has changed include this message in changed flags
		   list, even if we didn't see any changes above. */
		ext = array_idx(&new_map->extensions, ctx->lost_new_ext_idx);
		modseqp = CONST_PTR_OFFSET(new_rec, ext->record_offset);
		new_modseq = *modseqp;

		if (new_modseq > ctx->view->highest_modseq)
			changed = TRUE;
	}

	/* without modseqs lost_flags isn't updated perfectly correctly, because
	   by the time we're comparing old flags it may have changed from what
	   we last sent to the client (because the map is shared). This could
	   be avoided by always keeping a private copy of the map in the view,
	   but that's a waste of memory for as rare of a problem as this. */
	if (changed)
		seq_range_array_add(&ctx->lost_flags, new_rec->uid);
	return 0;
}

static int
view_sync_get_log_lost_changes(struct mail_index_view_sync_ctx *ctx,
			       unsigned int *expunge_count_r)
{
	struct mail_index_view *view = ctx->view;
	struct mail_index_map *old_map = view->map;
	struct mail_index_map *new_map = view->index->map;
	const unsigned int old_count = old_map->hdr.messages_count;
	const unsigned int new_count = new_map->hdr.messages_count;
	const struct mail_index_record *old_rec, *new_rec;
	struct mail_transaction_header thdr;
	uint32_t seqi, seqj;

	/* we don't update the map in the same order as it's typically done.
	   map->rec_map may already have some messages appended that we don't
	   want. get an atomic map to make sure these get removed. */
	(void)mail_index_sync_get_atomic_map(&ctx->sync_map_ctx);

	if (!mail_index_map_get_ext_idx(new_map, view->index->modseq_ext_id,
					&ctx->lost_new_ext_idx))
		ctx->lost_new_ext_idx = (uint32_t)-1;

	i_array_init(&ctx->lost_flags, 64);
	t_array_init(&ctx->lost_old_kw, 32);
	t_array_init(&ctx->lost_new_kw, 32);
	ctx->lost_kw_buf = t_buffer_create(128);

	/* handle expunges and sync flags */
	seqi = seqj = 1;
	while (seqi <= old_count && seqj <= new_count) {
		old_rec = MAIL_INDEX_REC_AT_SEQ(old_map, seqi);
		new_rec = MAIL_INDEX_REC_AT_SEQ(new_map, seqj);
		if (old_rec->uid == new_rec->uid) {
			/* message found - check if flags have changed */
			if (view_sync_apply_lost_changes(ctx, seqi, seqj) < 0)
				return -1;
			seqi++; seqj++;
		} else if (old_rec->uid < new_rec->uid) {
			/* message expunged */
			seq_range_array_add(&ctx->expunges, old_rec->uid);
			seqi++;
		} else {
			/* new message appeared out of nowhere */
			mail_index_set_error(view->index,
				"%s view is inconsistent: "
				"uid=%u inserted in the middle of mailbox",
				view->index->filepath, new_rec->uid);
			return -1;
		}
	}
	/* if there are old messages left, they're all expunged */
	for (; seqi <= old_count; seqi++) {
		old_rec = MAIL_INDEX_REC_AT_SEQ(old_map, seqi);
		seq_range_array_add(&ctx->expunges, old_rec->uid);
	}
	/* if there are new messages left, they're all new messages */
	thdr.type = MAIL_TRANSACTION_APPEND | MAIL_TRANSACTION_EXTERNAL;
	thdr.size = sizeof(*new_rec);
	for (; seqj <= new_count; seqj++) {
		new_rec = MAIL_INDEX_REC_AT_SEQ(new_map, seqj);
		if (mail_index_sync_record(&ctx->sync_map_ctx,
					   &thdr, new_rec) < 0)
			return -1;
		mail_index_map_lookup_keywords(new_map, seqj,
					       &ctx->lost_new_kw);
		if (view_sync_update_keywords(ctx, new_rec->uid) < 0)
			return -1;
	}
	*expunge_count_r = view_sync_expunges2seqs(ctx);

	/* we have no idea how far we've synced - make sure these aren't used */
	old_map->hdr.log_file_seq = 0;
	old_map->hdr.log_file_head_offset = 0;
	old_map->hdr.log_file_tail_offset = 0;

	if ((ctx->flags & MAIL_INDEX_VIEW_SYNC_FLAG_NOEXPUNGES) != 0) {
		/* Expunges aren't wanted to be synced. Remember if we skipped
		   over any expunges. If yes, we must not update
		   log_file_expunge_seq/offset at the end of the view sync
		   so that a later sync can finish the expunges. */
		array_clear(&ctx->expunges);
		ctx->skipped_expunges = *expunge_count_r > 0;
	}
	/* After the view sync is finished, update
	   log_file_head_seq/offset, since we've synced everything
	   (except maybe the expunges) up to this point. */
	view->log_file_head_seq = new_map->hdr.log_file_seq;
	view->log_file_head_offset = new_map->hdr.log_file_head_offset;
	return 0;
}

static int mail_index_view_sync_init_fix(struct mail_index_view_sync_ctx *ctx)
{
	struct mail_index_view *view = ctx->view;
	uint32_t seq;
	uoff_t offset;
	const char *reason;
	bool reset;
	int ret;

	/* replace the view's map */
	view->index->map->refcount++;
	mail_index_unmap(&view->map);
	view->map = view->index->map;

	/* update log positions */
	view->log_file_head_seq = seq = view->map->hdr.log_file_seq;
	view->log_file_head_offset = offset =
		view->map->hdr.log_file_head_offset;

	ret = mail_transaction_log_view_set(view->log_view, seq, offset,
					    seq, offset, &reset, &reason);
	if (ret <= 0) {
		mail_index_set_error(view->index, "Failed to fix view for %s: %s",
				     view->index->filepath, reason);
		return ret;
	}
	view->inconsistent = FALSE;
	return 0;
}

struct mail_index_view_sync_ctx *
mail_index_view_sync_begin(struct mail_index_view *view,
			   enum mail_index_view_sync_flags flags)
{
	struct mail_index_view_sync_ctx *ctx;
	struct mail_index_map *tmp_map;
	unsigned int expunge_count = 0;
	bool reset, partial_sync, sync_expunges, have_expunges;
	const char *error;
	int ret;

	i_assert(!view->syncing);
	i_assert(view->transactions_list == NULL);

	view->syncing = TRUE;

	/* Syncing the view invalidates all previous looked up records.
	   Unreference the mappings this view keeps because of them. */
	mail_index_view_unref_maps(view);

	ctx = i_new(struct mail_index_view_sync_ctx, 1);
	ctx->view = view;
	ctx->flags = flags;

	sync_expunges = (flags & MAIL_INDEX_VIEW_SYNC_FLAG_NOEXPUNGES) == 0;
	if (sync_expunges)
		i_array_init(&ctx->expunges, 64);
	if ((flags & MAIL_INDEX_VIEW_SYNC_FLAG_FIX_INCONSISTENT) != 0) {
		/* just get this view synced - don't return anything */
		i_assert(sync_expunges);
		if (mail_index_view_sync_init_fix(ctx) < 0)
			ctx->failed = TRUE;
		return ctx;
	}
	if (mail_index_view_is_inconsistent(view)) {
		mail_index_set_error(view->index, "%s view is inconsistent",
				     view->index->filepath);
		ctx->failed = TRUE;
		return ctx;
	}

	ret = view_sync_set_log_view_range(view, sync_expunges, &reset,
					   &partial_sync, &error);
	if (ret < 0) {
		mail_index_set_error(view->index, "%s", error);
		ctx->failed = TRUE;
		return ctx;
	}

	if (ret == 0) {
		/* Log the warning only when all expunges have been synced
		   by previous syncs. This way when there's a _FLAG_NOEXPUNGES
		   sync, there's no second warning logged when the expunges
		   finally are synced. */
		if (view->log_file_expunge_seq == view->log_file_head_seq &&
		    view->log_file_expunge_offset == view->log_file_head_offset) {
			e_warning(view->index->event,
				  "%s - generating missing logs", error);
		}
		ctx->log_was_lost = TRUE;
		if (!sync_expunges)
			i_array_init(&ctx->expunges, 64);
		mail_index_sync_map_init(&ctx->sync_map_ctx, view,
					 MAIL_INDEX_SYNC_HANDLER_VIEW);
		ret = view_sync_get_log_lost_changes(ctx, &expunge_count);
		mail_index_modseq_sync_end(&ctx->sync_map_ctx.modseq_ctx);
		mail_index_sync_map_deinit(&ctx->sync_map_ctx);
		if (ret < 0) {
			mail_index_set_error(view->index,
				"%s view syncing failed to apply changes",
				view->index->filepath);
			view->inconsistent = TRUE;
			ctx->failed = TRUE;
			return ctx;
		}
		have_expunges = expunge_count > 0;
	} else if (sync_expunges) {
		/* get list of all expunges first */
		if (view_sync_get_expunges(ctx, &expunge_count) < 0) {
			ctx->failed = TRUE;
			return ctx;
		}
		have_expunges = expunge_count > 0;
	} else if (view->log_file_expunge_seq == view->log_file_head_seq &&
		   view->log_file_expunge_offset == view->log_file_head_offset) {
		/* Previous syncs haven't left any pending expunges. See if
		   this sync will. */
		have_expunges = view_sync_have_expunges(view);
	} else {
		/* Expunges weren't synced in the previous sync either.
		   We already know there are missing expunges. */
		ctx->skipped_expunges = TRUE;
		have_expunges = TRUE;
	}

	ctx->finish_min_msg_count = reset ? 0 :
		view->map->hdr.messages_count - expunge_count;
	if (!reset)
		;
	else if ((flags & MAIL_INDEX_VIEW_SYNC_FLAG_2ND_INDEX) != 0 &&
		 view->map->hdr.messages_count == 0) {
			/* The secondary index is still empty, so it may have
			   just been created for the first time. This is
			   expected, so it shouldn't cause the view to become
			   inconsistent. */
			if (mail_index_view_sync_init_fix(ctx) < 0)
				ctx->failed = TRUE;
			return ctx;
	} else {
		view->inconsistent = TRUE;
		mail_index_set_error(view->index,
				     "%s reset, view is now inconsistent",
				     view->index->filepath);
		ctx->failed = TRUE;
		return ctx;
	}

	if (!have_expunges && !partial_sync) {
		/* no expunges, we can just replace the map */
		if (view->index->map->hdr.messages_count <
		    ctx->finish_min_msg_count) {
			mail_index_set_error(view->index,
				"Index %s lost messages without expunging "
				"(%u -> %u)", view->index->filepath,
				view->map->hdr.messages_count,
				view->index->map->hdr.messages_count);
			ctx->finish_min_msg_count = 0;
			view->inconsistent = TRUE;
		}

		view->index->map->refcount++;
		mail_index_unmap(&view->map);
		view->map = view->index->map;
	} else {
		/* a) expunges seen. b) doing a partial sync because we saw
		   a reset.

		   Create a private map which we update. If we're syncing
		   expunges the map will finally be replaced with the head map
		   to remove the expunged messages. */
		ctx->sync_map_update = TRUE;

		if (view->map->refcount > 1) {
			tmp_map = mail_index_map_clone(view->map);
			mail_index_unmap(&view->map);
			view->map = tmp_map;
		}

		if (sync_expunges) {
			ctx->sync_new_map = view->index->map;
			ctx->sync_new_map->refcount++;
		}
	}
	mail_index_sync_map_init(&ctx->sync_map_ctx, view,
				 MAIL_INDEX_SYNC_HANDLER_VIEW);

#ifdef DEBUG
	mail_index_map_check(view->map);
#endif
	return ctx;
}

static bool
view_sync_is_hidden(struct mail_index_view *view, uint32_t seq, uoff_t offset)
{
	const struct mail_index_view_log_sync_area *sync;

	if (!array_is_created(&view->syncs_hidden))
		return FALSE;

	array_foreach(&view->syncs_hidden, sync) {
		if (sync->log_file_offset <= offset &&
		    offset - sync->log_file_offset < sync->length &&
		    sync->log_file_seq == seq)
			return TRUE;
	}

	return FALSE;
}

static bool
mail_index_view_sync_want(struct mail_index_view_sync_ctx *ctx,
			  const struct mail_transaction_header *hdr)
{
        struct mail_index_view *view = ctx->view;
	uint32_t seq;
	uoff_t offset, next_offset;

	mail_transaction_log_view_get_prev_pos(view->log_view, &seq, &offset);
	next_offset = offset + sizeof(*hdr) + hdr->size;

	if ((hdr->type & (MAIL_TRANSACTION_EXPUNGE |
			  MAIL_TRANSACTION_EXPUNGE_GUID)) != 0 &&
	    (hdr->type & MAIL_TRANSACTION_EXTERNAL) != 0) {
		if ((ctx->flags & MAIL_INDEX_VIEW_SYNC_FLAG_NOEXPUNGES) != 0) {
			i_assert(!LOG_IS_BEFORE(seq, offset,
						view->log_file_expunge_seq,
						view->log_file_expunge_offset));
			if (!ctx->skipped_expunges) {
				view->log_file_expunge_seq = seq;
				view->log_file_expunge_offset = offset;
				ctx->skipped_expunges = TRUE;
			}
			return FALSE;
		}
		if (LOG_IS_BEFORE(seq, offset, view->log_file_expunge_seq,
				  view->log_file_expunge_offset)) {
			/* already synced */
			return FALSE;
		}
	}

	if (LOG_IS_BEFORE(seq, offset, view->log_file_head_seq,
			  view->log_file_head_offset)) {
		/* already synced */
		return FALSE;
	}

	view->log_file_head_seq = seq;
	view->log_file_head_offset = next_offset;
	return TRUE;
}

static int
mail_index_view_sync_get_next_transaction(struct mail_index_view_sync_ctx *ctx)
{
        struct mail_transaction_log_view *log_view = ctx->view->log_view;
	struct mail_index_view *view = ctx->view;
	const struct mail_transaction_header *hdr;
	uint32_t seq;
	uoff_t offset;
	int ret;
	bool synced_to_map;

	do {
		/* Get the next transaction from log. */
		ret = mail_transaction_log_view_next(log_view, &ctx->hdr,
						     &ctx->data);
		if (ret <= 0) {
			if (ret < 0)
				return -1;

			ctx->hdr = NULL;
			ctx->last_read = TRUE;
			return 0;
		}

		hdr = ctx->hdr;
		/* skip records we've already synced */
	} while (!mail_index_view_sync_want(ctx, hdr));

	mail_transaction_log_view_get_prev_pos(log_view, &seq, &offset);

	/* If we started from a map that we didn't create ourself,
	   some of the transactions may already be synced. at the end
	   of this view sync we'll update file_seq=0 so that this check
	   always becomes FALSE for subsequent syncs. */
	synced_to_map = view->map->hdr.log_file_seq != 0 &&
		LOG_IS_BEFORE(seq, offset, view->map->hdr.log_file_seq,
			      view->map->hdr.log_file_head_offset);

	/* Apply transaction to view's mapping if needed (meaning we
	   didn't just re-map the view to head mapping). */
	if (ctx->sync_map_update && !synced_to_map) {
		if ((hdr->type & (MAIL_TRANSACTION_EXPUNGE |
				  MAIL_TRANSACTION_EXPUNGE_GUID)) == 0) {
			ret = mail_index_sync_record(&ctx->sync_map_ctx,
						     hdr, ctx->data);
		}
		if (ret < 0)
			return -1;
	}

	ctx->hidden = view_sync_is_hidden(view, seq, offset);
	return 1;
}

static bool
mail_index_view_sync_get_rec(struct mail_index_view_sync_ctx *ctx,
			     struct mail_index_view_sync_rec *rec)
{
	const struct mail_transaction_header *hdr = ctx->hdr;
	const void *data = ctx->data;

	switch (hdr->type & MAIL_TRANSACTION_TYPE_MASK) {
	case MAIL_TRANSACTION_FLAG_UPDATE: {
		const struct mail_transaction_flag_update *update =
			CONST_PTR_OFFSET(data, ctx->data_offset);

		/* data contains mail_transaction_flag_update[] */
		for (;;) {
			ctx->data_offset += sizeof(*update);
			if (!MAIL_TRANSACTION_FLAG_UPDATE_IS_INTERNAL(update))
				break;

			/* skip internal flag changes */
			if (ctx->data_offset == ctx->hdr->size)
				return FALSE;

			update = CONST_PTR_OFFSET(data, ctx->data_offset);
		}

		if (update->add_flags != 0 || update->remove_flags != 0)
			rec->type = MAIL_INDEX_VIEW_SYNC_TYPE_FLAGS;
		else
			rec->type = MAIL_INDEX_VIEW_SYNC_TYPE_MODSEQ;
		rec->uid1 = update->uid1;
		rec->uid2 = update->uid2;
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_UPDATE: {
		const struct mail_transaction_keyword_update *update = data;
		const uint32_t *uids;

		/* data contains mail_transaction_keyword_update header,
		   the keyword name and an array of { uint32_t uid1, uid2; } */

		if (ctx->data_offset == 0) {
			/* skip over the header and name */
			ctx->data_offset = sizeof(*update) + update->name_size;
			if ((ctx->data_offset % 4) != 0)
				ctx->data_offset += 4 - (ctx->data_offset % 4);
		}

		uids = CONST_PTR_OFFSET(data, ctx->data_offset);
		rec->type = MAIL_INDEX_VIEW_SYNC_TYPE_FLAGS;
		rec->uid1 = uids[0];
		rec->uid2 = uids[1];

		ctx->data_offset += sizeof(uint32_t) * 2;
		break;
	}
	case MAIL_TRANSACTION_KEYWORD_RESET: {
		const struct mail_transaction_keyword_reset *reset =
			CONST_PTR_OFFSET(data, ctx->data_offset);

		/* data contains mail_transaction_keyword_reset[] */
		rec->type = MAIL_INDEX_VIEW_SYNC_TYPE_FLAGS;
		rec->uid1 = reset->uid1;
		rec->uid2 = reset->uid2;
		ctx->data_offset += sizeof(*reset);
		break;
	}
	default:
		ctx->hdr = NULL;
		return FALSE;
	}

	rec->hidden = ctx->hidden;
	return TRUE;
}

static bool
mail_index_view_sync_next_lost(struct mail_index_view_sync_ctx *ctx,
			       struct mail_index_view_sync_rec *sync_rec)
{
	const struct seq_range *range;
	unsigned int count;

	range = array_get(&ctx->lost_flags, &count);
	if (ctx->lost_flag_idx == count) {
		ctx->last_read = TRUE;
		return FALSE;
	}

	sync_rec->type = MAIL_INDEX_VIEW_SYNC_TYPE_FLAGS;
	sync_rec->uid1 = range[ctx->lost_flag_idx].seq1;
	sync_rec->uid2 = range[ctx->lost_flag_idx].seq2;
	sync_rec->hidden = FALSE;
	ctx->lost_flag_idx++;
	return TRUE;
}

bool mail_index_view_sync_next(struct mail_index_view_sync_ctx *ctx,
			       struct mail_index_view_sync_rec *sync_rec)
{
	int ret;

	if (ctx->log_was_lost)
		return mail_index_view_sync_next_lost(ctx, sync_rec);

	do {
		if (ctx->hdr == NULL || ctx->data_offset == ctx->hdr->size) {
			ret = mail_index_view_sync_get_next_transaction(ctx);
			if (ret <= 0) {
				if (ret < 0)
					ctx->failed = TRUE;
				return FALSE;
			}

			ctx->data_offset = 0;
		}
	} while (!mail_index_view_sync_get_rec(ctx, sync_rec));

	return TRUE;
}

void mail_index_view_sync_get_expunges(struct mail_index_view_sync_ctx *ctx,
				       const ARRAY_TYPE(seq_range) **expunges_r)
{
	*expunges_r = &ctx->expunges;
}

static void
mail_index_view_sync_clean_log_syncs(struct mail_index_view *view)
{
	const struct mail_index_view_log_sync_area *syncs;
	unsigned int i, count;

	if (!array_is_created(&view->syncs_hidden))
		return;

	/* Clean up to view's tail */
	syncs = array_get(&view->syncs_hidden, &count);
	for (i = 0; i < count; i++) {
		if ((syncs[i].log_file_offset +
		     syncs[i].length > view->log_file_expunge_offset &&
                     syncs[i].log_file_seq == view->log_file_expunge_seq) ||
		    syncs[i].log_file_seq > view->log_file_expunge_seq)
			break;
	}
	if (i > 0)
		array_delete(&view->syncs_hidden, 0, i);
}

int mail_index_view_sync_commit(struct mail_index_view_sync_ctx **_ctx,
				bool *delayed_expunges_r)
{
        struct mail_index_view_sync_ctx *ctx = *_ctx;
        struct mail_index_view *view = ctx->view;
	int ret = ctx->failed ? -1 : 0;

	i_assert(view->syncing);

	*_ctx = NULL;
	*delayed_expunges_r = ctx->skipped_expunges;

	if ((!ctx->last_read || view->inconsistent) &&
	    (ctx->flags & MAIL_INDEX_VIEW_SYNC_FLAG_FIX_INCONSISTENT) == 0) {
		/* we didn't sync everything */
		view->inconsistent = TRUE;
		ret = -1;
	}
	if (ctx->sync_map_ctx.modseq_ctx != NULL)
		mail_index_modseq_sync_end(&ctx->sync_map_ctx.modseq_ctx);

	if (ctx->sync_new_map != NULL) {
		mail_index_unmap(&view->map);
		view->map = ctx->sync_new_map;
	} else if (ctx->sync_map_update) {
		/* log offsets have no meaning in views. make sure they're not
		   tried to be used wrong by setting them to zero. */
		view->map->hdr.log_file_seq = 0;
		view->map->hdr.log_file_head_offset = 0;
		view->map->hdr.log_file_tail_offset = 0;
	}

	i_assert(view->map->hdr.messages_count >= ctx->finish_min_msg_count);

	if (!ctx->skipped_expunges) {
		view->log_file_expunge_seq = view->log_file_head_seq;
		view->log_file_expunge_offset = view->log_file_head_offset;
	}

	if (ctx->sync_map_ctx.view != NULL)
		mail_index_sync_map_deinit(&ctx->sync_map_ctx);
	mail_index_view_sync_clean_log_syncs(ctx->view);

#ifdef DEBUG
	mail_index_map_check(view->map);
#endif

	/* set log view to empty range so unneeded memory gets freed */
	mail_transaction_log_view_clear(view->log_view,
					view->log_file_expunge_seq);

	if (array_is_created(&ctx->expunges))
		array_free(&ctx->expunges);
	if (array_is_created(&ctx->lost_flags))
		array_free(&ctx->lost_flags);

	view->highest_modseq = mail_index_map_modseq_get_highest(view->map);
	view->syncing = FALSE;
	i_free(ctx);
	return ret;
}

void mail_index_view_add_hidden_transaction(struct mail_index_view *view,
					    uint32_t log_file_seq,
					    uoff_t log_file_offset,
					    unsigned int length)
{
	struct mail_index_view_log_sync_area *area;

	if (!array_is_created(&view->syncs_hidden))
		i_array_init(&view->syncs_hidden, 32);

	area = array_append_space(&view->syncs_hidden);
	area->log_file_seq = log_file_seq;
	area->log_file_offset = log_file_offset;
	area->length = length;
}
