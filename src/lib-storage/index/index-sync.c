/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "index-storage.h"

struct index_mailbox_sync_context {
	struct mailbox_sync_context ctx;
	struct index_mailbox *ibox;
	struct mail_index_view_sync_ctx *sync_ctx;
	uint32_t messages_count;

	const uint32_t *expunges;
	size_t expunges_count;
	int failed;
};

void index_mailbox_set_recent(struct index_mailbox *ibox, uint32_t seq)
{
	unsigned char *p;
	size_t dest_idx;

	if (ibox->recent_flags_start_seq == 0) {
		ibox->recent_flags = buffer_create_dynamic(default_pool, 128);
		ibox->recent_flags_start_seq = seq;
	} else if (seq < ibox->recent_flags_start_seq) {
		dest_idx = ibox->recent_flags_start_seq - seq;
		buffer_copy(ibox->recent_flags, dest_idx,
			    ibox->recent_flags, 0, (size_t)-1);
		memset(buffer_get_modifyable_data(ibox->recent_flags, NULL),
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

int index_mailbox_is_recent(struct index_mailbox *ibox, uint32_t seq)
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
		    ibox->is_recent(ibox, rec->uid))
                        index_mailbox_set_recent(ibox, seq1);
	}

	return 0;
}

struct mailbox_sync_context *
index_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags,
			int failed)
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

	ctx->messages_count = mail_index_view_get_message_count(ibox->view);

	sync_mask = MAIL_INDEX_SYNC_MASK_ALL;
	if ((flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) != 0)
		sync_mask &= ~MAIL_INDEX_SYNC_TYPE_EXPUNGE;

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
		ctx->expunges =
			mail_index_view_sync_get_expunges(ctx->sync_ctx,
							  &ctx->expunges_count);
	}
	return &ctx->ctx;
}

int index_mailbox_sync_next(struct mailbox_sync_context *_ctx,
			    struct mailbox_sync_rec *sync_rec_r)
{
	struct index_mailbox_sync_context *ctx =
		(struct index_mailbox_sync_context *)_ctx;
	struct mail_index_sync_rec sync;
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

			sync_rec_r->type = MAILBOX_SYNC_TYPE_FLAGS;
			return 1;
		}
	}

	if (ret == 0 && ctx->expunges_count > 0) {
		/* expunges[] is a sorted array of sequences. it's easiest for
		   us to print them from end to beginning. */
		sync_rec_r->seq1 = ctx->expunges[ctx->expunges_count*2-2];
		sync_rec_r->seq2 = ctx->expunges[ctx->expunges_count*2-1];
		index_mailbox_expunge_recent(ctx->ibox, sync_rec_r->seq1,
					     sync_rec_r->seq2);

		if (sync_rec_r->seq2 > ctx->messages_count)
			sync_rec_r->seq2 = ctx->messages_count;

		ctx->messages_count -= sync_rec_r->seq2 - sync_rec_r->seq1 + 1;
		ctx->expunges_count--;

		sync_rec_r->type = MAILBOX_SYNC_TYPE_EXPUNGE;
		return 1;
	}

	if (ret < 0)
		mail_storage_set_index_error(ctx->ibox);
	return ret;
}

#define SYNC_STATUS_FLAGS \
	(STATUS_MESSAGES | STATUS_RECENT | STATUS_UIDNEXT | \
	 STATUS_UIDVALIDITY | STATUS_UNSEEN | STATUS_KEYWORDS)

int index_mailbox_sync_deinit(struct mailbox_sync_context *_ctx,
			      struct mailbox_status *status_r)
{
	struct index_mailbox_sync_context *ctx =
		(struct index_mailbox_sync_context *)_ctx;
	struct index_mailbox *ibox = ctx->ibox;
	uint32_t messages_count;
	int ret = ctx->failed ? -1 : 0;

	if (ctx->sync_ctx != NULL)
		mail_index_view_sync_end(ctx->sync_ctx);

	if (ret == 0) {
		messages_count = mail_index_view_get_message_count(ibox->view);
		if (messages_count != ctx->messages_count) {
			index_mailbox_update_recent(ibox,
						    ctx->messages_count+1,
						    messages_count);
		}
		ibox->synced_recent_count = ibox->recent_flags_count;

		ret = index_storage_get_status_locked(ctx->ibox,
						      SYNC_STATUS_FLAGS,
						      status_r);
	}

	mail_index_view_unlock(ctx->ibox->view);
	i_free(ctx);
	return ret;
}
