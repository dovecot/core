/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "seq-range-array.h"
#include "array.h"
#include "buffer.h"
#include "index-storage.h"

struct index_mailbox_sync_context {
	struct mailbox_sync_context ctx;
	struct index_mailbox *ibox;
	struct mail_index_view_sync_ctx *sync_ctx;
	uint32_t messages_count;

	const ARRAY_TYPE(seq_range) *expunges;
	unsigned int expunge_pos;
	uint32_t last_seq1, last_seq2;

	bool failed;
};

void index_mailbox_set_recent(struct index_mailbox *ibox, uint32_t seq)
{
	unsigned char *p;
	size_t dest_idx;

	i_assert(seq != 0);

	if (ibox->recent_flags_start_seq == 0) {
		ibox->recent_flags = buffer_create_dynamic(default_pool, 128);
		ibox->recent_flags_start_seq = seq;
	} else if (seq < ibox->recent_flags_start_seq) {
		dest_idx = ibox->recent_flags_start_seq - seq;
		buffer_copy(ibox->recent_flags, dest_idx,
			    ibox->recent_flags, 0, (size_t)-1);
		memset(buffer_get_modifiable_data(ibox->recent_flags, NULL),
		       0, dest_idx);
		ibox->recent_flags_start_seq = seq;
	}

	p = buffer_get_space_unsafe(ibox->recent_flags,
				    seq - ibox->recent_flags_start_seq, 1);
	if (*p == 0) {
		ibox->recent_flags_count++;
		*p = 1;
	}
}

bool index_mailbox_is_recent(struct index_mailbox *ibox, uint32_t seq)
{
	const unsigned char *data;
	size_t size;
	uint32_t idx;

	if (seq < ibox->recent_flags_start_seq ||
	    ibox->recent_flags_start_seq == 0)
		return FALSE;

	idx = seq - ibox->recent_flags_start_seq;
	data = buffer_get_data(ibox->recent_flags, &size);
	return idx < size ? data[idx] : FALSE;
}

static void index_mailbox_expunge_recent(struct index_mailbox *ibox,
					 uint32_t seq1, uint32_t seq2)
{
	const unsigned char *data;
	size_t size;
	uint32_t i, idx, count, move;

	if (ibox->recent_flags_start_seq == 0) {
		/* no recent flags */
		return;
	}

	if (seq2 < ibox->recent_flags_start_seq) {
		/* expunging messages before recent flags, just modify
		   the recent start position */
		ibox->recent_flags_start_seq -= seq2 - seq1 + 1;
		return;
	}

	if (seq1 < ibox->recent_flags_start_seq) {
		move = ibox->recent_flags_start_seq - seq1;
		seq1 = ibox->recent_flags_start_seq;
	} else {
		move = 0;
	}

	idx = seq1 - ibox->recent_flags_start_seq;
	count = seq2 - seq1 + 1;

	data = buffer_get_data(ibox->recent_flags, &size);
	if (idx < size) {
		if (idx + count > size)
			count = size - idx;

		for (i = 0; i < count; i++) {
			if (data[idx+i])
				ibox->recent_flags_count--;
		}

		buffer_copy(ibox->recent_flags, idx,
			    ibox->recent_flags, idx + count, (size_t)-1);
		buffer_write_zero(ibox->recent_flags, size - count, count);

		buffer_set_used_size(ibox->recent_flags, size - count);
	}
        ibox->recent_flags_start_seq -= move;
}

static int index_mailbox_update_recent(struct index_mailbox *ibox,
				       uint32_t seq1, uint32_t seq2)
{
	const struct mail_index_record *rec;

	for (; seq1 <= seq2; seq1++) {
		if (mail_index_lookup(ibox->view, seq1, &rec) < 0) {
			mail_storage_set_index_error(ibox);
			return -1;
		}

		if ((rec->flags & MAIL_RECENT) != 0 ||
		    (ibox->is_recent != NULL &&
		     ibox->is_recent(ibox, rec->uid)))
                        index_mailbox_set_recent(ibox, seq1);
	}

	return 0;
}

struct mailbox_sync_context *
index_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags,
			bool failed)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
        struct index_mailbox_sync_context *ctx;
	enum mail_index_sync_type sync_mask;

	ctx = i_new(struct index_mailbox_sync_context, 1);
	ctx->ctx.box = box;
	ctx->ibox = ibox;

	if (failed) {
		ctx->failed = TRUE;
		return &ctx->ctx;
	}

	ctx->messages_count = mail_index_view_get_messages_count(ibox->view);

	sync_mask = MAIL_INDEX_SYNC_MASK_ALL;
	if ((flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) != 0)
		sync_mask &= ~MAIL_INDEX_SYNC_TYPE_EXPUNGE;
	if ((flags & MAILBOX_SYNC_FLAG_NO_NEWMAIL) != 0)
		sync_mask &= ~MAIL_INDEX_SYNC_TYPE_APPEND;

	if (mail_index_view_sync_begin(ibox->view, sync_mask,
				       &ctx->sync_ctx) < 0) {
		mail_storage_set_index_error(ibox);
		ctx->failed = TRUE;
		return &ctx->ctx;
	}

	if (!ibox->recent_flags_synced) {
		ibox->recent_flags_synced = TRUE;
                index_mailbox_update_recent(ibox, 1, ctx->messages_count);
	}

	if ((flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) == 0) {
		mail_index_view_sync_get_expunges(ctx->sync_ctx,
						  &ctx->expunges);
		ctx->expunge_pos = array_count(ctx->expunges);
	}
	return &ctx->ctx;
}

static bool sync_rec_check_skips(struct index_mailbox_sync_context *ctx,
				 struct mailbox_sync_rec *sync_rec)
{
	uint32_t seq, new_seq1, new_seq2;

	if (sync_rec->seq1 >= ctx->last_seq1 &&
	    sync_rec->seq1 <= ctx->last_seq2)
		new_seq1 = ctx->last_seq2 + 1;
	else
		new_seq1 = sync_rec->seq1;
	if (sync_rec->seq2 >= ctx->last_seq1 &&
	    sync_rec->seq2 <= ctx->last_seq2)
		new_seq2 = ctx->last_seq1 - 1;
	else
		new_seq2 = sync_rec->seq2;

	if (new_seq1 > new_seq2)
		return FALSE;

	ctx->last_seq1 = sync_rec->seq1;
	ctx->last_seq2 = sync_rec->seq2;

	sync_rec->seq1 = new_seq1;
	sync_rec->seq2 = new_seq2;

	/* FIXME: we're only skipping messages from the beginning and from
	   the end. we should skip also the middle ones. This takes care of
	   the most common repeats though. */
	if (ctx->expunges != NULL) {
		/* skip expunged messages from the beginning and the end */
		for (seq = sync_rec->seq1; seq <= sync_rec->seq2; seq++) {
			if (!seq_range_exists(ctx->expunges, seq))
				break;
		}
		if (seq > sync_rec->seq2) {
			/* everything skipped */
			return FALSE;
		}
		sync_rec->seq1 = seq;

		for (seq = sync_rec->seq2; seq >= sync_rec->seq1; seq--) {
			if (!seq_range_exists(ctx->expunges, seq))
				break;
		}
		sync_rec->seq2 = seq;
	}
	return TRUE;
}

int index_mailbox_sync_next(struct mailbox_sync_context *_ctx,
			    struct mailbox_sync_rec *sync_rec_r)
{
	struct index_mailbox_sync_context *ctx =
		(struct index_mailbox_sync_context *)_ctx;
	struct mail_index_view_sync_rec sync;
	int ret;

	if (ctx->failed)
		return -1;

	while ((ret = mail_index_view_sync_next(ctx->sync_ctx, &sync)) > 0) {
		switch (sync.type) {
		case MAIL_INDEX_SYNC_TYPE_APPEND:
			/* not interested */
			break;
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			/* later */
			break;
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE:
		case MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET:
			/* FIXME: hide the flag updates for expunged messages */
			if (mail_index_lookup_uid_range(ctx->ibox->view,
						sync.uid1, sync.uid2,
						&sync_rec_r->seq1,
						&sync_rec_r->seq2) < 0) {
				ctx->failed = TRUE;
				return -1;
			}

			if (sync_rec_r->seq1 == 0)
				break;

			if (!sync_rec_check_skips(ctx, sync_rec_r))
				break;

			sync_rec_r->type =
				sync.type == MAIL_INDEX_SYNC_TYPE_FLAGS ?
				MAILBOX_SYNC_TYPE_FLAGS :
				MAILBOX_SYNC_TYPE_KEYWORDS;
			return 1;
		}
	}

	if (ret == 0 && ctx->expunge_pos > 0) {
		/* expunges is a sorted array of sequences. it's easiest for
		   us to print them from end to beginning. */
		const struct seq_range *range;

		ctx->expunge_pos--;
		range = array_idx(ctx->expunges, ctx->expunge_pos);

		sync_rec_r->seq1 = range->seq1;
		sync_rec_r->seq2 = range->seq2;
		index_mailbox_expunge_recent(ctx->ibox, sync_rec_r->seq1,
					     sync_rec_r->seq2);

		if (sync_rec_r->seq2 > ctx->messages_count)
			sync_rec_r->seq2 = ctx->messages_count;
		ctx->messages_count -= sync_rec_r->seq2 - sync_rec_r->seq1 + 1;

		sync_rec_r->type = MAILBOX_SYNC_TYPE_EXPUNGE;
		return 1;
	}

	if (ret < 0)
		mail_storage_set_index_error(ctx->ibox);
	return ret;
}

int index_mailbox_sync_deinit(struct mailbox_sync_context *_ctx,
			      enum mailbox_status_items status_items,
			      struct mailbox_status *status_r)
{
	struct index_mailbox_sync_context *ctx =
		(struct index_mailbox_sync_context *)_ctx;
	struct index_mailbox *ibox = ctx->ibox;
	uint32_t messages_count;
	int ret = ctx->failed ? -1 : 0;

	if (ctx->sync_ctx != NULL)
		mail_index_view_sync_end(&ctx->sync_ctx);

	if (ret == 0) {
		messages_count = mail_index_view_get_messages_count(ibox->view);
		if (messages_count != ctx->messages_count) {
			index_mailbox_update_recent(ibox,
						    ctx->messages_count+1,
						    messages_count);
		}
		ibox->synced_recent_count = ibox->recent_flags_count;

		ret = status_items == 0 ? 0 :
			index_storage_get_status_locked(ctx->ibox, status_items,
							status_r);
	}

	mail_index_view_unlock(ibox->view);
	i_free(ctx);
	return ret;
}

bool index_keyword_array_cmp(const ARRAY_TYPE(keyword_indexes) *k1,
			     const ARRAY_TYPE(keyword_indexes) *k2)
{
	const unsigned int *idx1, *idx2;
	unsigned int i, j, count1, count2;

	if (!array_is_created(k1))
		return !array_is_created(k2) || array_count(k2) == 0;
	if (!array_is_created(k2))
		return array_count(k1) == 0;

	/* The arrays may not be sorted, but they usually are. Optimize for
	   the assumption that they are */
	idx1 = array_get(k1, &count1);
	idx2 = array_get(k2, &count2);

	if (count1 != count2)
		return FALSE;

	for (i = 0; i < count1; i++) {
		if (idx1[i] != idx2[i]) {
			/* not found / unsorted array. check. */
			for (j = 0; j < count1; j++) {
				if (idx1[i] == idx2[j])
					break;
			}
			if (j == count1)
				return FALSE;
		}
	}
	return TRUE;
}
