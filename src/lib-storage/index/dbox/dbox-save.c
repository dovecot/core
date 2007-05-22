/* Copyright (C) 2005 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "hex-dec.h"
#include "write-full.h"
#include "ostream.h"
#include "seq-range-array.h"
#include "index-mail.h"
#include "dbox-uidlist.h"
#include "dbox-keywords.h"
#include "dbox-sync.h"
#include "dbox-storage.h"

#include <stddef.h>

struct dbox_save_context {
	struct mail_save_context ctx;

	struct dbox_mailbox *mbox;
	struct mail_index_transaction *trans;
	struct dbox_uidlist_append_ctx *append_ctx;

	struct mail_index_sync_ctx *index_sync_ctx;

	/* updated for each appended mail: */
	uint32_t seq;
	struct istream *input;
	struct ostream *output;
	struct dbox_file *file;
	struct mail *mail;
	uint64_t hdr_offset;
	uint64_t mail_offset;

	unsigned int failed:1;
	unsigned int finished:1;
};

static int
dbox_save_add_keywords(struct dbox_save_context *ctx,
		       const struct mail_keywords *keywords,
		       buffer_t *file_keywords)
{
	ARRAY_TYPE(seq_range) new_keywords;
	const struct seq_range *range;
	unsigned int i, count, file_idx;
	int ret = 0;

	/* Get a list of all new keywords. Using seq_range is the easiest
	   way to do this and should be pretty fast too. */
	t_push();
	t_array_init(&new_keywords, 16);
	for (i = 0; i < keywords->count; i++) {
		/* check if it's already in the file */
		if (dbox_file_lookup_keyword(ctx->mbox, ctx->file,
					     keywords->idx[i], &file_idx)) {
			buffer_write(file_keywords, file_idx, "1", 1);
			continue;
		}

		/* add it. if it already exists, it's handled internally. */
		seq_range_array_add(&new_keywords, 0, keywords->idx[i]);
	}

	/* now, write them to file */
	range = array_get(&new_keywords, &count);
	if (count > 0) {
		if (dbox_file_append_keywords(ctx->mbox, ctx->file,
					      range, count) < 0) {
			ret = -1;
			count = 0;
		}

		/* write the new keywords to file_keywords */
		for (i = 0; i < count; i++) {
			unsigned int kw;

			for (kw = range[i].seq1; kw <= range[i].seq2; kw++) {
				if (!dbox_file_lookup_keyword(ctx->mbox,
							      ctx->file, kw,
							      &file_idx)) {
					/* it should have been found */
					i_unreached();
					continue;
				}

				buffer_write(file_keywords, file_idx, "1", 1);
			}
		}
	}

	t_pop();
	return ret;
}

int dbox_save_init(struct mailbox_transaction_context *_t,
		   enum mail_flags flags, struct mail_keywords *keywords,
		   time_t received_date, int timezone_offset __attr_unused__,
		   const char *from_envelope __attr_unused__,
		   struct istream *input, struct mail *dest_mail,
		   struct mail_save_context **ctx_r)
{
	struct dbox_transaction_context *t =
		(struct dbox_transaction_context *)_t;
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)t->ictx.ibox;
	struct dbox_save_context *ctx = t->save_ctx;
	struct dbox_mail_header hdr;
	const struct stat *st;
	buffer_t *file_keywords = NULL;
	enum mail_flags save_flags;
	unsigned int i, pos, left;
	char buf[128];
	int ret;

	i_assert((t->ictx.flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (received_date == (time_t)-1)
		received_date = ioloop_time;

	if (ctx == NULL) {
		ctx = t->save_ctx = i_new(struct dbox_save_context, 1);
		ctx->ctx.transaction = &t->ictx.mailbox_ctx;
		ctx->mbox = mbox;
		ctx->trans = t->ictx.trans;
		ctx->append_ctx = dbox_uidlist_append_init(mbox->uidlist);

		if ((ret = dbox_sync_is_changed(mbox)) < 0) {
			ctx->failed = TRUE;
			return -1;
		}
		if (ret > 0) {
			if (dbox_sync(mbox, FALSE) < 0) {
				ctx->failed = TRUE;
				return -1;
			}
		}
	}
	ctx->input = input;

	/* get the size of the mail to be saved, if possible */
	st = i_stream_stat(input, TRUE);
	if (st != NULL && st->st_size == -1)
		st = NULL;

	if (dbox_uidlist_append_locked(ctx->append_ctx, &ctx->file,
				       st != NULL ? st->st_size : 0) < 0) {
		ctx->failed = TRUE;
		return -1;
	}
	ctx->hdr_offset = ctx->file->output->offset;

	t_push();
	if (keywords != NULL && keywords->count > 0) {
		uint32_t uid;
		time_t mtime;

		/* uidlist must be locked while we're reading or modifying
		   file's header */
		if (dbox_uidlist_append_get_first_uid(ctx->append_ctx,
						      &uid, &mtime) < 0) {
			ctx->failed = TRUE;
			t_pop();
			return -1;
		}

		/* write keywords to the file */
		file_keywords = buffer_create_dynamic(pool_datastack_create(),
						      DBOX_KEYWORD_COUNT);
		if (dbox_save_add_keywords(ctx, keywords, file_keywords) < 0) {
			ctx->failed = TRUE;
			t_pop();
			return -1;
		}
		o_stream_seek(ctx->file->output, ctx->hdr_offset);
	}

	/* append mail header. UID and mail size are written later. */
	memset(&hdr, '0', sizeof(hdr));
	memcpy(hdr.magic, DBOX_MAIL_HEADER_MAGIC, sizeof(hdr.magic));
	DEC2HEX(hdr.received_time_hex, received_date);
	DEC2HEX(hdr.save_time_hex, ioloop_time);
	hdr.answered = (flags & MAIL_ANSWERED) != 0 ? '1' : '0';
	hdr.flagged = (flags & MAIL_FLAGGED) != 0 ? '1' : '0';
	hdr.deleted = (flags & MAIL_DELETED) != 0 ? '1' : '0';
	hdr.seen = (flags & MAIL_SEEN) != 0 ? '1' : '0';
	hdr.draft = (flags & MAIL_DRAFT) != 0 ? '1' : '0';
	hdr.expunged = '0';
	o_stream_send(ctx->file->output, &hdr, sizeof(hdr));

	/* write keywords */
	if (file_keywords != NULL) {
		unsigned char *keyword_string;
		size_t size;

		keyword_string =
			buffer_get_modifiable_data(file_keywords, &size);

		/* string should be filled with NULs and '1' now.
		   Change NULs to '0'. */
		for (i = 0; i < size; i++) {
			if (keyword_string[i] == '\0')
				keyword_string[i] = '0';
		}
		o_stream_send(ctx->file->output, keyword_string, size);
	}

	/* fill rest of the header with '0' characters */
	pos = ctx->file->output->offset - ctx->hdr_offset;
	i_assert(pos <= ctx->file->mail_header_size);
	left = ctx->file->mail_header_size - pos;
	memset(buf, '0', I_MIN(sizeof(buf), left));
	while (left > sizeof(buf)) {
		o_stream_send(ctx->file->output, buf, sizeof(buf));
		left -= sizeof(buf);
	}
	o_stream_send(ctx->file->output, buf, left);
	ctx->mail_offset = ctx->file->output->offset;

	/* add to index */
	save_flags = (flags & ~MAIL_RECENT) | MAIL_RECENT;
	mail_index_append(ctx->trans, 0, &ctx->seq);
	mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_REPLACE,
				save_flags);
	if (keywords != NULL) {
		mail_index_update_keywords(ctx->trans, ctx->seq,
					   MODIFY_REPLACE, keywords);
	}
	mail_index_update_ext(ctx->trans, ctx->seq, mbox->dbox_file_ext_idx,
			      &ctx->file->file_seq, NULL);
	mail_index_update_ext(ctx->trans, ctx->seq,
			      mbox->dbox_offset_ext_idx, &ctx->hdr_offset,
			      NULL);

	if (dest_mail == NULL) {
		if (ctx->mail == NULL)
			ctx->mail = index_mail_alloc(_t, 0, NULL);
		dest_mail = ctx->mail;
	}
	if (mail_set_seq(dest_mail, ctx->seq) < 0)
		i_unreached();

	if (t->first_saved_mail_seq == 0)
		t->first_saved_mail_seq = ctx->seq;
	t_pop();

	*ctx_r = &ctx->ctx;
	return ctx->failed ? -1 : 0;
}

int dbox_save_continue(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct mail_storage *storage = &ctx->mbox->storage->storage;

	if (ctx->failed)
		return -1;

	if (o_stream_send_istream(ctx->file->output, ctx->input) < 0) {
		if (!mail_storage_set_error_from_errno(storage)) {
			mail_storage_set_critical(storage,
				"o_stream_send_istream(%s) failed: %m",
				ctx->file->path);
		}
		ctx->failed = TRUE;
		return -1;
	}
	return 0;
}

int dbox_save_finish(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct dbox_mail_header hdr;

	ctx->finished = TRUE;

	if (ctx->file != NULL) {
		/* Make sure the file ends here (we could have been overwriting
		   some existing aborted mail). In case we failed, truncate the
		   file to the size before writing. */
		if (ftruncate(ctx->file->fd, ctx->failed ? ctx->hdr_offset :
			      ctx->file->output->offset) < 0) {
			mail_storage_set_critical(&ctx->mbox->storage->storage,
						  "ftruncate(%s) failed: %m",
						  ctx->file->path);
			ctx->failed = TRUE;
		}
	}

	if (!ctx->failed) {
		/* write mail size to header */
		DEC2HEX(hdr.mail_size_hex,
			ctx->file->output->offset - ctx->mail_offset);

		if (pwrite_full(ctx->file->fd, hdr.mail_size_hex,
				sizeof(hdr.mail_size_hex), ctx->hdr_offset +
				offsetof(struct dbox_mail_header,
					 mail_size_hex)) < 0) {
			mail_storage_set_critical(&ctx->mbox->storage->storage,
						  "pwrite_full(%s) failed: %m",
						  ctx->file->path);
			ctx->failed = TRUE;
		}
	}

	if (ctx->failed)
		return -1;

	dbox_uidlist_append_finish_mail(ctx->append_ctx, ctx->file);
	return 0;
}

void dbox_save_cancel(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)dbox_save_finish(_ctx);
}

int dbox_transaction_save_commit_pre(struct dbox_save_context *ctx)
{
	struct dbox_transaction_context *t =
		(struct dbox_transaction_context *)ctx->ctx.transaction;
	struct dbox_mail_header hdr;
	struct dbox_file *file;
	struct mail_index_view *view;
	const struct mail_index_header *idx_hdr;
	uint32_t seq, uid, next_uid, file_seq;
	time_t old_mtime, new_mtime;
	uoff_t offset;
	int ret;

	i_assert(ctx->finished);

	/* uidlist locking is done before index locking. */
	if (dbox_uidlist_append_get_first_uid(ctx->append_ctx,
					      &uid, &old_mtime) < 0) {
		ctx->failed = TRUE;
		dbox_transaction_save_rollback(ctx);
		return -1;
	}
	mail_index_append_assign_uids(ctx->trans, uid, &next_uid);

	*t->ictx.first_saved_uid = uid;
	*t->ictx.last_saved_uid = next_uid - 1;

	/* update UIDs */
	for (seq = t->first_saved_mail_seq; seq <= ctx->seq; seq++, uid++) {
		ret = dbox_mail_lookup_offset(&t->ictx, seq,
					      &file_seq, &offset);
		i_assert(ret > 0); /* it's in memory, shouldn't fail! */

		DEC2HEX(hdr.uid_hex, uid);

		file = dbox_uidlist_append_lookup_file(ctx->append_ctx,
						       file_seq);
		if (pwrite_full(file->fd, hdr.uid_hex,
				sizeof(hdr.uid_hex), offset +
				offsetof(struct dbox_mail_header,
					 uid_hex)) < 0) {
			mail_storage_set_critical(&ctx->mbox->storage->storage,
						  "pwrite_full(%s) failed: %m",
						  file->path);
			ctx->failed = TRUE;
                        dbox_transaction_save_rollback(ctx);
			return -1;
		}
	}

	/* lock index lock before dropping uidlist lock in _append_commit() */
	if (mail_index_sync_begin(ctx->mbox->ibox.index, &ctx->index_sync_ctx,
				  &view, &ctx->trans, (uint32_t)-1, (uoff_t)-1,
				  FALSE, FALSE) < 0) {
		ctx->failed = TRUE;
		dbox_transaction_save_rollback(ctx);
		return -1;
	}

	if (dbox_uidlist_append_commit(ctx->append_ctx, &new_mtime) < 0) {
		mail_index_sync_rollback(&ctx->index_sync_ctx);
		i_free(ctx);
		return -1;
	}

	idx_hdr = mail_index_get_header(view);
	if ((uint32_t)old_mtime == idx_hdr->sync_stamp &&
	    old_mtime != new_mtime) {
		/* index was fully synced. keep it that way. */
		uint32_t sync_stamp = new_mtime;

		mail_index_update_header(ctx->trans,
			offsetof(struct mail_index_header, sync_stamp),
			&sync_stamp, sizeof(sync_stamp), TRUE);
	}

	return 0;
}

void dbox_transaction_save_commit_post(struct dbox_save_context *ctx)
{
	mail_index_sync_rollback(&ctx->index_sync_ctx);
	if (ctx->mail != NULL)
		index_mail_free(ctx->mail);
	i_free(ctx);
}

void dbox_transaction_save_rollback(struct dbox_save_context *ctx)
{
	if (!ctx->finished)
		dbox_save_cancel(&ctx->ctx);

	if (ctx->index_sync_ctx != NULL)
		mail_index_sync_rollback(&ctx->index_sync_ctx);

        dbox_uidlist_append_rollback(ctx->append_ctx);
	if (ctx->mail != NULL)
		index_mail_free(ctx->mail);
	i_free(ctx);
}
