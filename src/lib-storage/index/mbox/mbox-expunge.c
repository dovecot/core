/* Copyright (C) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "mbox-index.h"
#include "mbox-storage.h"
#include "mbox-lock.h"
#include "index-expunge.h"

#include <fcntl.h>
#include <unistd.h>

struct mbox_expunge_context {
	struct mail_expunge_context *ctx;

        struct index_mailbox *ibox;
	struct istream *input;
	struct ostream *output;
	int failed, expunges;

	uoff_t from_offset, move_offset;
};

struct mail_expunge_context *
mbox_storage_expunge_init(struct mailbox *box,
			  enum mail_fetch_field wanted_fields, int expunge_all)
{
	struct index_mailbox *ibox = (struct index_mailbox *) box;
	struct mbox_expunge_context *ctx;
	struct mail_expunge_context *mctx;
	struct istream *input;

	mctx = index_storage_expunge_init(box, wanted_fields, expunge_all);
	if (mctx == NULL)
		return NULL;

	/* mbox must be already opened, synced and locked at this point.
	   we just want the istream. */
	input = mbox_get_stream(ibox->index, 0, MAIL_LOCK_EXCLUSIVE);
	if (input == NULL)
		return NULL;

	i_assert(ibox->index->mbox_sync_counter ==
		 ibox->index->mbox_lock_counter);

	ctx = i_new(struct mbox_expunge_context, 1);
	ctx->ctx = mctx;
	ctx->ibox = ibox;
	ctx->input = input;
	ctx->output = o_stream_create_file(ibox->index->mbox_fd, default_pool,
					   4096, FALSE);
	ctx->from_offset = (uoff_t)-1;
	ctx->move_offset = (uoff_t)-1;
	o_stream_set_blocking(ctx->output, 60000, NULL, NULL);
	return (struct mail_expunge_context *) ctx;
}

static int mbox_move_data(struct mbox_expunge_context *ctx)
{
	const unsigned char *data;
	size_t size;
	uoff_t old_limit;
	int failed;

	i_assert(ctx->input->v_offset <= ctx->move_offset);
	i_stream_skip(ctx->input, ctx->move_offset - ctx->input->v_offset);

	if (ctx->output->offset == 0) {
		/* we're writing to beginning of mbox, so we
		   don't want the [\r]\n there */
		(void)i_stream_read_data(ctx->input, &data, &size, 1);
		if (size > 0 && data[0] == '\n')
			i_stream_skip(ctx->input, 1);
		else if (size > 1 && data[0] == '\r' &&
			 data[1] == '\n')
			i_stream_skip(ctx->input, 2);
	}

	old_limit = ctx->input->v_limit;
	i_stream_set_read_limit(ctx->input, ctx->from_offset);
	failed = o_stream_send_istream(ctx->output, ctx->input) < 0;
	i_stream_set_read_limit(ctx->input, old_limit);

	if (failed || ctx->input->v_offset != ctx->from_offset)
		return FALSE;
	return TRUE;
}

int mbox_storage_expunge_deinit(struct mail_expunge_context *_ctx)
{
	struct mbox_expunge_context *ctx = (struct mbox_expunge_context *) _ctx;
	int failed = ctx->failed;

	if (ctx->expunges) {
		if (!failed && ctx->move_offset != (uoff_t)-1) {
			ctx->from_offset = ctx->input->v_limit;
			if (!mbox_move_data(ctx))
				failed = TRUE;
		} else if (failed && ctx->output->offset > 0) {
			/* we moved some of the data. move the rest as well
			   so there won't be invalid holes in mbox file */
			(void)o_stream_send_istream(ctx->output, ctx->input);
		}

		if (ftruncate(ctx->ibox->index->mbox_fd,
			      (off_t)ctx->output->offset) < 0) {
			mail_storage_set_error(ctx->ibox->box.storage,
				"ftruncate() failed for mbox file %s: %m",
				ctx->ibox->index->mailbox_path);
			failed = TRUE;
		}
	}

	if (!index_storage_expunge_deinit(ctx->ctx))
		failed = TRUE;

	o_stream_unref(ctx->output);
	i_free(ctx);
	return !failed;
}

static int get_from_offset(struct mail_index *index,
			   struct mail_index_record *rec, uoff_t *offset_r)
{
	uoff_t offset, hdr_size, body_size;

	if (!mbox_mail_get_location(index, rec, &offset,
				    &hdr_size, &body_size))
		return FALSE;

	*offset_r = offset + hdr_size + body_size;
	return TRUE;
}

struct mail *mbox_storage_expunge_fetch_next(struct mail_expunge_context *_ctx)
{
	struct mbox_expunge_context *ctx =
		(struct mbox_expunge_context *) _ctx;
	struct mail_expunge_context *mctx = ctx->ctx;
	struct mail_index *index = ctx->ibox->index;

	if (mctx->rec == NULL)
		return NULL;

	if (mctx->fetch_next) {
                mctx->fetch_next = FALSE;
		do {
			if (!get_from_offset(index, mctx->rec,
					     &ctx->from_offset)) {
				ctx->failed = TRUE;
				return NULL;
			}

			mctx->seq++;
			mctx->rec = index->next(index, mctx->rec);
			if (mctx->rec == NULL)
				return NULL;
		} while ((mctx->rec->msg_flags & MAIL_DELETED) == 0 &&
			 !mctx->expunge_all);
	}

	return index_storage_expunge_fetch_next(ctx->ctx);
}

static int get_prev_from_offset(struct mbox_expunge_context *ctx,
				unsigned int seq)
{
	struct mail_index_record *rec;

	if (seq == 1)
		ctx->from_offset = 0;
	else {
		rec = ctx->ibox->index->lookup(ctx->ibox->index, seq-1);

		if (!get_from_offset(ctx->ibox->index, rec, &ctx->from_offset))
			return FALSE;
	}

	return TRUE;
}

int mbox_storage_expunge(struct mail *mail, struct mail_expunge_context *_ctx,
			 unsigned int *seq_r, int notify)
{
	struct mbox_expunge_context *ctx = (struct mbox_expunge_context *) _ctx;
	struct index_mail *imail = (struct index_mail *) mail;

	if (ctx->from_offset == (uoff_t)-1) {
		if (!get_prev_from_offset(ctx, imail->data.idx_seq))
			return FALSE;
	}

	if (!ctx->expunges) {
		/* first expunged message */
		if (o_stream_seek(ctx->output, ctx->from_offset) < 0)
			return FALSE;
		ctx->expunges = TRUE;
	} else if (ctx->move_offset != ctx->from_offset) {
		if (!mbox_move_data(ctx))
			return FALSE;
	}

	if (!get_from_offset(ctx->ibox->index, imail->data.rec,
			     &ctx->move_offset))
		return FALSE;

	return index_storage_expunge(mail, ctx->ctx, seq_r, notify);
}
