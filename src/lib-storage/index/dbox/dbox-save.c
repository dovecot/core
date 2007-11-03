/* Copyright (c) 2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hex-dec.h"
#include "str.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
#include "write-full.h"
#include "index-mail.h"
#include "dbox-storage.h"
#include "dbox-index.h"
#include "dbox-file.h"
#include "dbox-sync.h"

#include <stdlib.h>

struct dbox_save_mail {
	struct dbox_file *file;
	uint32_t seq;
	uint32_t append_offset;
	uoff_t message_size;
};

struct dbox_save_context {
	struct mail_save_context ctx;

	struct dbox_mailbox *mbox;
	struct mail_index_transaction *trans;

	struct dbox_index_append_context *append_ctx;
	struct dbox_sync_context *sync_ctx;

	/* updated for each appended mail: */
	uint32_t seq;
	struct istream *input;
	struct mail *mail, *cur_dest_mail;
	time_t cur_received_date;
	enum mail_flags cur_flags;
	string_t *cur_keywords;

	struct dbox_file *cur_file;
	struct ostream *cur_output;

	ARRAY_DEFINE(mails, struct dbox_save_mail);

	unsigned int failed:1;
	unsigned int finished:1;
};

static void dbox_save_keywords(struct dbox_save_context *ctx,
			       struct mail_keywords *keywords)
{
	if (ctx->cur_keywords == NULL)
		ctx->cur_keywords = str_new(default_pool, 128);
	else
		str_truncate(ctx->cur_keywords, 0);
	dbox_mail_metadata_keywords_append(ctx->mbox, ctx->cur_keywords,
					   keywords);
}

int dbox_save_init(struct mailbox_transaction_context *_t,
		   enum mail_flags flags, struct mail_keywords *keywords,
		   time_t received_date, int timezone_offset ATTR_UNUSED,
		   const char *from_envelope ATTR_UNUSED,
		   struct istream *input, struct mail *dest_mail,
		   struct mail_save_context **ctx_r)
{
	struct dbox_transaction_context *t =
		(struct dbox_transaction_context *)_t;
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)t->ictx.ibox;
	struct dbox_save_context *ctx = t->save_ctx;
	struct dbox_message_header dbox_msg_hdr;
	struct dbox_save_mail *save_mail;
	struct istream *crlf_input;
	const char *cur_path;
	enum mail_flags save_flags;
	const struct stat *st;
	uoff_t mail_size;

	i_assert((t->ictx.flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (ctx == NULL) {
		ctx = t->save_ctx = i_new(struct dbox_save_context, 1);
		ctx->ctx.transaction = &t->ictx.mailbox_ctx;
		ctx->mbox = mbox;
		ctx->trans = t->ictx.trans;
		ctx->append_ctx = dbox_index_append_begin(mbox->dbox_index);
		i_array_init(&ctx->mails, 32);
	}

	/* get the size of the mail to be saved, if possible */
	st = i_stream_stat(input, TRUE);
	mail_size = st == NULL || st->st_size == -1 ? 0 : st->st_size;

	if (dbox_index_append_next(ctx->append_ctx, mail_size,
				   &ctx->cur_file, &ctx->cur_output) < 0) {
		ctx->failed = TRUE;
		return -1;
	}
	cur_path = dbox_file_get_path(ctx->cur_file);

	/* add to index */
	save_flags = flags & ~MAIL_RECENT;
	mail_index_append(ctx->trans, 0, &ctx->seq);
	mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_REPLACE,
				save_flags);
	if (keywords != NULL) {
		mail_index_update_keywords(ctx->trans, ctx->seq,
					   MODIFY_REPLACE, keywords);
	}

	if (dest_mail == NULL) {
		if (ctx->mail == NULL)
			ctx->mail = mail_alloc(_t, 0, NULL);
		dest_mail = ctx->mail;
	}
	mail_set_seq(dest_mail, ctx->seq);

	ctx->cur_dest_mail = dest_mail;

	crlf_input = i_stream_create_lf(input);
	ctx->input = index_mail_cache_parse_init(dest_mail, crlf_input);
	i_stream_unref(&crlf_input);

	save_mail = array_append_space(&ctx->mails);
	save_mail->file = ctx->cur_file;
	save_mail->seq = ctx->seq;
	i_assert(ctx->cur_output->offset <= (uint32_t)-1);
	save_mail->append_offset = ctx->cur_output->offset;

	/* write a dummy header. it'll get rewritten when we're finished */
	memset(&dbox_msg_hdr, 0, sizeof(dbox_msg_hdr));
	o_stream_cork(ctx->cur_output);
	if (o_stream_send(ctx->cur_output, &dbox_msg_hdr,
			  sizeof(dbox_msg_hdr)) < 0) {
		mail_storage_set_critical(_t->box->storage,
			"o_stream_send(%s) failed: %m", cur_path);
		ctx->failed = TRUE;
	}

	ctx->cur_received_date = received_date != (time_t)-1 ?
		received_date : ioloop_time;
	ctx->cur_flags = flags;
	dbox_save_keywords(ctx, keywords);

	*ctx_r = &ctx->ctx;
	return ctx->failed ? -1 : 0;
}

int dbox_save_continue(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct mail_storage *storage = &ctx->mbox->storage->storage;
	const char *cur_path;

	if (ctx->failed)
		return -1;

	cur_path = dbox_file_get_path(ctx->cur_file);
	do {
		if (o_stream_send_istream(ctx->cur_output, ctx->input) < 0) {
			if (!mail_storage_set_error_from_errno(storage)) {
				mail_storage_set_critical(storage,
					"o_stream_send_istream(%s) failed: %m",
					cur_path);
			}
			ctx->failed = TRUE;
			return -1;
		}
		index_mail_cache_parse_continue(ctx->cur_dest_mail);

		/* both tee input readers may consume data from our primary
		   input stream. we'll have to make sure we don't return with
		   one of the streams still having data in them. */
	} while (i_stream_read(ctx->input) > 0);
	return 0;
}

static void dbox_save_write_metadata(struct dbox_save_context *ctx)
{
	struct dbox_metadata_header metadata_hdr;
	char space[DBOX_EXTRA_SPACE];
	string_t *str;
	uoff_t vsize;

	memset(&metadata_hdr, 0, sizeof(metadata_hdr));
	memcpy(metadata_hdr.magic_post, DBOX_MAGIC_POST,
	       sizeof(metadata_hdr.magic_post));
	o_stream_send(ctx->cur_output, &metadata_hdr, sizeof(metadata_hdr));

	str = t_str_new(256);
	/* write first fields that don't change */
	str_printfa(str, "%c%lx\n", DBOX_METADATA_RECEIVED_TIME,
		    (unsigned long)ctx->cur_received_date);
	str_printfa(str, "%c%lx\n", DBOX_METADATA_SAVE_TIME,
		    (unsigned long)ioloop_time);
	if (mail_get_virtual_size(ctx->cur_dest_mail, &vsize) < 0)
		i_unreached();
	str_printfa(str, "%c%llx\n", DBOX_METADATA_VIRTUAL_SIZE,
		    (unsigned long long)vsize);

	/* flags */
	str_append_c(str, DBOX_METADATA_FLAGS);
	dbox_mail_metadata_flags_append(str, ctx->cur_flags);
	str_append_c(str, '\n');

	/* keywords */
	if (ctx->cur_keywords != NULL && str_len(ctx->cur_keywords) > 0) {
		str_append_c(str, DBOX_METADATA_KEYWORDS);
		str_append_str(str, ctx->cur_keywords);
		str_append_c(str, '\n');
	}

	o_stream_send(ctx->cur_output, str_data(str), str_len(str));
	memset(space, ' ', sizeof(space));
	o_stream_send(ctx->cur_output, space, sizeof(space));
	o_stream_send(ctx->cur_output, "\n", 1);
}

int dbox_save_finish(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct mail_storage *storage = &ctx->mbox->storage->storage;
	struct dbox_save_mail *save_mail;
	const char *cur_path;
	uoff_t offset = 0;
	unsigned int count;

	ctx->finished = TRUE;
	if (ctx->cur_output == NULL)
		return -1;

	index_mail_cache_parse_deinit(ctx->cur_dest_mail,
				      ctx->cur_received_date);

	if (!ctx->failed) {
		cur_path = dbox_file_get_path(ctx->cur_file);
		offset = ctx->cur_output->offset;
		dbox_save_write_metadata(ctx);
		if (o_stream_flush(ctx->cur_output) < 0) {
			mail_storage_set_critical(storage,
				"o_stream_flush(%s) failed: %m", cur_path);
			ctx->failed = TRUE;
		}
	}

	o_stream_unref(&ctx->cur_output);
	i_stream_unref(&ctx->input);

	count = array_count(&ctx->mails);
	save_mail = array_idx_modifiable(&ctx->mails, count - 1);
	if (ctx->failed) {
		dbox_file_cancel_append(save_mail->file,
					save_mail->append_offset);
		dbox_file_unref(&save_mail->file);
		array_delete(&ctx->mails, count - 1, 1);
		return -1;
	} else {
		dbox_file_finish_append(save_mail->file);
		save_mail->message_size = offset - save_mail->append_offset -
			save_mail->file->msg_header_size;
		return 0;
	}
}

void dbox_save_cancel(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;

	ctx->failed = TRUE;
	(void)dbox_save_finish(_ctx);
}

static int
dbox_save_mail_write_header(struct dbox_save_mail *mail, uint32_t uid)
{
	struct dbox_message_header dbox_msg_hdr;
	struct ostream *output = mail->file->output;
	uoff_t orig_offset;
	int ret = 0;

	i_assert(mail->file->msg_header_size == sizeof(dbox_msg_hdr));

	mail->file->last_append_uid = uid;
	dbox_msg_header_fill(&dbox_msg_hdr, uid, mail->message_size);

	orig_offset = output->offset;
	o_stream_seek(output, mail->append_offset);
	if (o_stream_send(output, &dbox_msg_hdr, sizeof(dbox_msg_hdr)) < 0 ||
	    o_stream_flush(output) < 0) {
		dbox_file_set_syscall_error(mail->file, "write");
		ret = -1;
	}
	o_stream_seek(output, orig_offset);
	return ret;
}

static int
dbox_save_file_write_append_offset(struct dbox_file *file, uoff_t append_offset)
{
	char buf[8+1];

	i_assert(append_offset <= (uint32_t)-1);

	i_snprintf(buf, sizeof(buf), "%08x", (unsigned int)append_offset);
	if (pwrite_full(file->fd, buf, sizeof(buf)-1,
			file->append_offset_header_pos) < 0) {
		dbox_file_set_syscall_error(file, "pwrite");
		return -1;
	}
	return 0;
}

static int dbox_save_file_commit_header(struct dbox_save_mail *mail)
{
	uoff_t append_offset;

	append_offset = dbox_file_get_next_append_offset(mail->file);
	return dbox_save_file_write_append_offset(mail->file, append_offset);
}

static void dbox_save_file_uncommit_header(struct dbox_save_mail *mail)
{
	if (mail->file->file_id == 0) {
		/* temporary file, we'll just unlink it later */
		return;
	}
	(void)dbox_save_file_write_append_offset(mail->file,
						 mail->append_offset);
}

static int dbox_save_mail_file_cmp(const void *p1, const void *p2)
{
	const struct dbox_save_mail *m1 = p1, *m2 = p2;
	int ret;

	ret = strcmp(m1->file->fname, m2->file->fname);
	if (ret == 0) {
		/* the oldest sequence is first. this is needed for uncommit
		   to work right. */
		ret = (int)m1->seq - (int)m2->seq;
	}
	return ret;
}

static int dbox_save_commit(struct dbox_save_context *ctx, uint32_t first_uid)
{
	struct dbox_mail_index_record rec;
	struct dbox_save_mail *mails;
	unsigned int i, count;

	/* first write updated mail headers and collect all files we wrote to */
	mails = array_get_modifiable(&ctx->mails, &count);
	for (i = 0; i < count; i++) {
		if (dbox_save_mail_write_header(&mails[i], first_uid++) < 0)
			return -1;
	}

	/* update append offsets in file headers */
	qsort(mails, count, sizeof(*mails), dbox_save_mail_file_cmp);
	for (i = 0; i < count; i++) {
		if (i > 0 && mails[i].file == mails[i-1].file) {
			/* already written */
			continue;
		}

		if (dbox_save_file_commit_header(&mails[i]) < 0) {
			/* have to uncommit all changes so far */
			for (; i > 0; i--) {
				if (i > 1 &&
				    mails[i-2].file == mails[i-1].file)
					continue;
				dbox_save_file_uncommit_header(&mails[i-1]);
			}
			return -1;
		}
	}

	/* set file_id / offsets to records */
	if (dbox_index_append_assign_file_ids(ctx->append_ctx) < 0)
		return -1;

	memset(&rec, 0, sizeof(rec));
	for (i = 0; i < count; i++) {
		rec.file_id = mails[i].file->file_id;
		rec.offset = mails[i].append_offset;

		if ((rec.file_id & DBOX_FILE_ID_FLAG_UID) == 0) {
			mail_index_update_ext(ctx->trans, mails[i].seq,
					      ctx->mbox->dbox_ext_id,
					      &rec, NULL);
		}
	}
	return 0;
}

int dbox_transaction_save_commit_pre(struct dbox_save_context *ctx)
{
	struct dbox_transaction_context *t =
		(struct dbox_transaction_context *)ctx->ctx.transaction;
	const struct mail_index_header *hdr;
	uint32_t uid, next_uid;

	i_assert(ctx->finished);

	if (dbox_sync_begin(ctx->mbox, &ctx->sync_ctx, FALSE) < 0) {
		ctx->failed = TRUE;
		dbox_transaction_save_rollback(ctx);
		return -1;
	}

	hdr = mail_index_get_header(ctx->sync_ctx->sync_view);
	uid = hdr->next_uid;
	mail_index_append_assign_uids(ctx->trans, uid, &next_uid);

	if (dbox_save_commit(ctx, uid) < 0) {
		ctx->failed = TRUE;
		dbox_transaction_save_rollback(ctx);
		return -1;
	}

	*t->ictx.saved_uid_validity = hdr->uid_validity;
	*t->ictx.first_saved_uid = uid;
	*t->ictx.last_saved_uid = next_uid - 1;

	dbox_index_append_commit(&ctx->append_ctx);
	return 0;
}

void dbox_transaction_save_commit_post(struct dbox_save_context *ctx)
{
	ctx->ctx.transaction = NULL; /* transaction is already freed */

	(void)dbox_sync_finish(&ctx->sync_ctx, TRUE);
	dbox_transaction_save_rollback(ctx);
}

void dbox_transaction_save_rollback(struct dbox_save_context *ctx)
{
	if (!ctx->finished)
		dbox_save_cancel(&ctx->ctx);
	if (ctx->append_ctx != NULL)
		dbox_index_append_rollback(&ctx->append_ctx);

	if (ctx->sync_ctx != NULL)
		(void)dbox_sync_finish(&ctx->sync_ctx, FALSE);

	if (ctx->mail != NULL)
		mail_free(&ctx->mail);
	if (ctx->cur_keywords != NULL)
		str_free(&ctx->cur_keywords);
	array_free(&ctx->mails);
	i_free(ctx);
}
