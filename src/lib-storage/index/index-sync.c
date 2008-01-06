/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

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

	ARRAY_TYPE(seq_range) flag_updates;
	const ARRAY_TYPE(seq_range) *expunges;
	unsigned int flag_update_pos, expunge_pos;

	bool failed;
};

void index_mailbox_set_recent_uid(struct index_mailbox *ibox, uint32_t uid)
{
	if (uid <= ibox->recent_flags_prev_uid) {
		i_assert(seq_range_exists(&ibox->recent_flags, uid));
		return;
	}
	ibox->recent_flags_prev_uid = uid;

	seq_range_array_add(&ibox->recent_flags, 64, uid);
	ibox->recent_flags_count++;
}

void index_mailbox_set_recent_seq(struct index_mailbox *ibox,
				  struct mail_index_view *view,
				  uint32_t seq1, uint32_t seq2)
{
	uint32_t uid;

	for (; seq1 <= seq2; seq1++) {
		mail_index_lookup_uid(view, seq1, &uid);
		index_mailbox_set_recent_uid(ibox, uid);
	}
}

bool index_mailbox_is_recent(struct index_mailbox *ibox, uint32_t uid)
{
	return array_is_created(&ibox->recent_flags) &&
		seq_range_exists(&ibox->recent_flags, uid);
}

unsigned int index_mailbox_get_recent_count(struct index_mailbox *ibox)
{
	const struct mail_index_header *hdr;
	const struct seq_range *range;
	unsigned int i, count, recent_count;

	if (!array_is_created(&ibox->recent_flags))
		return 0;

	hdr = mail_index_get_header(ibox->view);
	recent_count = ibox->recent_flags_count;
	range = array_get(&ibox->recent_flags, &count);
	for (i = count; i > 0; ) {
		i--;
		if (range[i].seq2 < hdr->next_uid)
			break;

		if (range[i].seq1 >= hdr->next_uid) {
			/* completely invisible to this view */
			recent_count -= range[i].seq2 - range[i].seq1 + 1;
		} else {
			/* partially invisible */
			recent_count -= range[i].seq2 - hdr->next_uid + 1;
			break;
		}
	}
	return recent_count;
}

static void index_mailbox_expunge_recent(struct index_mailbox *ibox,
					 uint32_t seq1, uint32_t seq2)
{
	uint32_t uid;

	if (!array_is_created(&ibox->recent_flags))
		return;

	for (; seq1 <= seq2; seq1++) {
		mail_index_lookup_uid(ibox->view, seq1, &uid);
		if (seq_range_array_remove(&ibox->recent_flags, uid))
			ibox->recent_flags_count--;
	}
}

static void index_view_sync_recs_get(struct index_mailbox_sync_context *ctx)
{
	struct mail_index_view_sync_rec sync;
	uint32_t seq1, seq2;

	i_array_init(&ctx->flag_updates, 128);
	while (mail_index_view_sync_next(ctx->sync_ctx, &sync)) {
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
			if (mail_index_lookup_seq_range(ctx->ibox->view,
							sync.uid1, sync.uid2,
							&seq1, &seq2)) {
				seq_range_array_add_range(&ctx->flag_updates,
							  seq1, seq2);
			}
			break;
		}
	}

	/* remove expunged messages from flag updates */
	if (ctx->expunges != NULL) {
		seq_range_array_remove_seq_range(&ctx->flag_updates,
						 ctx->expunges);
	}
}

struct mailbox_sync_context *
index_mailbox_sync_init(struct mailbox *box, enum mailbox_sync_flags flags,
			bool failed)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;
        struct index_mailbox_sync_context *ctx;
	enum mail_index_view_sync_flags sync_flags = 0;

	ctx = i_new(struct index_mailbox_sync_context, 1);
	ctx->ctx.box = box;
	ctx->ibox = ibox;

	if (failed) {
		ctx->failed = TRUE;
		return &ctx->ctx;
	}

	if ((flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) != 0)
		sync_flags |= MAIL_INDEX_VIEW_SYNC_FLAG_NOEXPUNGES;

	if ((flags & MAILBOX_SYNC_FLAG_FIX_INCONSISTENT) != 0) {
		sync_flags |= MAIL_INDEX_VIEW_SYNC_FLAG_FIX_INCONSISTENT;
		ctx->messages_count = 0;
	} else {
		ctx->messages_count =
			mail_index_view_get_messages_count(ibox->view);
	}

	if (mail_index_view_sync_begin(ibox->view, sync_flags,
				       &ctx->sync_ctx) < 0) {
		mail_storage_set_index_error(ibox);
		ctx->failed = TRUE;
		return &ctx->ctx;
	}

	if ((flags & MAILBOX_SYNC_FLAG_NO_EXPUNGES) == 0) {
		mail_index_view_sync_get_expunges(ctx->sync_ctx,
						  &ctx->expunges);
		ctx->expunge_pos = array_count(ctx->expunges);
	}
	index_view_sync_recs_get(ctx);
	return &ctx->ctx;
}

static int
index_mailbox_sync_next_expunge(struct index_mailbox_sync_context *ctx,
				struct mailbox_sync_rec *sync_rec_r)
{
	const struct seq_range *range;

	if (ctx->expunge_pos == 0)
		return 0;

	/* expunges is a sorted array of sequences. it's easiest for
	   us to print them from end to beginning. */
	ctx->expunge_pos--;
	range = array_idx(ctx->expunges, ctx->expunge_pos);
	i_assert(range->seq2 <= ctx->messages_count);

	index_mailbox_expunge_recent(ctx->ibox, range->seq1, range->seq2);
	ctx->messages_count -= range->seq2 - range->seq1 + 1;

	sync_rec_r->seq1 = range->seq1;
	sync_rec_r->seq2 = range->seq2;
	sync_rec_r->type = MAILBOX_SYNC_TYPE_EXPUNGE;
	return 1;
}

bool index_mailbox_sync_next(struct mailbox_sync_context *_ctx,
			     struct mailbox_sync_rec *sync_rec_r)
{
	struct index_mailbox_sync_context *ctx =
		(struct index_mailbox_sync_context *)_ctx;
	const struct seq_range *flag_updates;
	unsigned int count;

	if (ctx->failed)
		return FALSE;

	flag_updates = array_get(&ctx->flag_updates, &count);
	if (ctx->flag_update_pos < count) {
		sync_rec_r->type = MAILBOX_SYNC_TYPE_FLAGS;
		sync_rec_r->seq1 = flag_updates[ctx->flag_update_pos].seq1;
		sync_rec_r->seq2 = flag_updates[ctx->flag_update_pos].seq2;
		ctx->flag_update_pos++;
		return 1;
	}

	return index_mailbox_sync_next_expunge(ctx, sync_rec_r);
}

static void
index_mailbox_expunge_unseen_recent(struct index_mailbox_sync_context *ctx)
{
	struct index_mailbox *ibox = ctx->ibox;
	const struct mail_index_header *hdr;
	uint32_t seq, start_uid, uid;

	if (!array_is_created(&ibox->recent_flags))
		return;

	/* expunges array contained expunges for the messages that were already
	   visible in this view, but append+expunge would be invisible.
	   recent_flags may however contain the append UID, so we'll have to
	   remove it separately */
	hdr = mail_index_get_header(ibox->view);
	if (ctx->messages_count == 0)
		uid = 0;
	else if (ctx->messages_count <= hdr->messages_count)
		mail_index_lookup_uid(ibox->view, ctx->messages_count, &uid);
	else {
		i_assert(mail_index_view_is_inconsistent(ibox->view));
		return;
	}

	for (seq = ctx->messages_count + 1; seq <= hdr->messages_count; seq++) {
		start_uid = uid;
		mail_index_lookup_uid(ibox->view, seq, &uid);
		if (start_uid + 1 > uid - 1)
			continue;

		ibox->recent_flags_count -=
			seq_range_array_remove_range(&ibox->recent_flags,
						     start_uid + 1, uid - 1);
	}

	if (uid + 1 < hdr->next_uid) {
		ibox->recent_flags_count -=
			seq_range_array_remove_range(&ibox->recent_flags,
						     uid + 1,
						     hdr->next_uid - 1);
	}
#ifdef DEBUG
	{
		const struct seq_range *range;
		unsigned int i, count;

		range = array_get(&ibox->recent_flags, &count);
		for (i = 0; i < count; i++) {
			for (uid = range[i].seq1; uid <= range[i].seq2; uid++) {
				if (uid >= hdr->next_uid)
					break;
				mail_index_lookup_seq(ibox->view, uid, &seq);
				i_assert(seq != 0);
			}
		}
	}
#endif
}

int index_mailbox_sync_deinit(struct mailbox_sync_context *_ctx,
			      enum mailbox_status_items status_items,
			      struct mailbox_status *status_r)
{
	struct index_mailbox_sync_context *ctx =
		(struct index_mailbox_sync_context *)_ctx;
	struct index_mailbox *ibox = ctx->ibox;
	struct mailbox_sync_rec sync_rec;
	const struct mail_index_header *hdr;
	uint32_t seq1, seq2;
	int ret = ctx->failed ? -1 : 0;

	/* finish handling expunges, so we don't break when updating
	   recent flags */
	while (index_mailbox_sync_next_expunge(ctx, &sync_rec) > 0) ;

	if (ctx->sync_ctx != NULL) {
		if (mail_index_view_sync_commit(&ctx->sync_ctx) < 0) {
			mail_storage_set_index_error(ibox);
			ret = -1;
		}
	}
	index_mailbox_expunge_unseen_recent(ctx);

	if (ibox->keep_recent) {
		/* mailbox syncing didn't necessarily update our recent state */
		hdr = mail_index_get_header(ibox->view);
		if (hdr->first_recent_uid > ibox->recent_flags_prev_uid) {
			mail_index_lookup_seq_range(ibox->view,
						    hdr->first_recent_uid,
						    hdr->next_uid,
						    &seq1, &seq2);
			if (seq1 != 0) {
				index_mailbox_set_recent_seq(ibox, ibox->view,
							     seq1, seq2);
			}
		}
	}

	if (ret == 0 && status_items != 0)
		mailbox_get_status(_ctx->box, status_items, status_r);

	array_free(&ctx->flag_updates);
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

enum mailbox_sync_type index_sync_type_convert(enum mail_index_sync_type type)
{
	enum mailbox_sync_type ret = 0;

	if ((type & MAIL_INDEX_SYNC_TYPE_EXPUNGE) != 0)
		ret |= MAILBOX_SYNC_TYPE_EXPUNGE;
	if ((type & (MAIL_INDEX_SYNC_TYPE_FLAGS |
		     MAIL_INDEX_SYNC_TYPE_KEYWORD_ADD |
		     MAIL_INDEX_SYNC_TYPE_KEYWORD_REMOVE |
		     MAIL_INDEX_SYNC_TYPE_KEYWORD_RESET)) != 0)
		ret |= MAILBOX_SYNC_TYPE_FLAGS;
	return ret;
}
