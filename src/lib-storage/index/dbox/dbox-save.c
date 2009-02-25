/* Copyright (c) 2007-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "fdatasync-path.h"
#include "hex-binary.h"
#include "hex-dec.h"
#include "str.h"
#include "istream.h"
#include "istream-crlf.h"
#include "ostream.h"
#include "write-full.h"
#include "index-mail.h"
#include "dbox-storage.h"
#include "dbox-map.h"
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

	struct dbox_map_append_context *append_ctx;
	struct dbox_sync_context *sync_ctx;

	/* updated for each appended mail: */
	uint32_t seq;
	struct istream *input;
	struct mail *mail;

	struct dbox_file *cur_file;
	struct ostream *cur_output;

	ARRAY_DEFINE(mails, struct dbox_save_mail);
	unsigned int single_count;

	unsigned int failed:1;
	unsigned int finished:1;
};

struct mail_save_context *
dbox_save_alloc(struct mailbox_transaction_context *_t)
{
	struct dbox_transaction_context *t =
		(struct dbox_transaction_context *)_t;
	struct dbox_mailbox *mbox = (struct dbox_mailbox *)t->ictx.ibox;
	struct dbox_save_context *ctx;

	i_assert((t->ictx.flags & MAILBOX_TRANSACTION_FLAG_EXTERNAL) != 0);

	if (t->save_ctx != NULL)
		return &t->save_ctx->ctx;

	ctx = t->save_ctx = i_new(struct dbox_save_context, 1);
	ctx->ctx.transaction = &t->ictx.mailbox_ctx;
	ctx->mbox = mbox;
	ctx->trans = t->ictx.trans;
	ctx->append_ctx = dbox_map_append_begin(mbox);
	i_array_init(&ctx->mails, 32);
	return &ctx->ctx;
}

int dbox_save_begin(struct mail_save_context *_ctx, struct istream *input)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct dbox_message_header dbox_msg_hdr;
	struct dbox_save_mail *save_mail;
	struct istream *crlf_input;
	enum mail_flags save_flags;
	const struct stat *st;
	uoff_t mail_size;

	/* get the size of the mail to be saved, if possible */
	st = i_stream_stat(input, TRUE);
	mail_size = st == NULL || st->st_size == -1 ? 0 : st->st_size;

	if (dbox_map_append_next(ctx->append_ctx, mail_size,
				 &ctx->cur_file, &ctx->cur_output) < 0) {
		ctx->failed = TRUE;
		return -1;
	}

	/* add to index */
	save_flags = _ctx->flags & ~MAIL_RECENT;
	mail_index_append(ctx->trans, 0, &ctx->seq);
	mail_index_update_flags(ctx->trans, ctx->seq, MODIFY_REPLACE,
				save_flags);
	if (_ctx->keywords != NULL) {
		mail_index_update_keywords(ctx->trans, ctx->seq,
					   MODIFY_REPLACE, _ctx->keywords);
	}

	if (_ctx->dest_mail == NULL) {
		if (ctx->mail == NULL)
			ctx->mail = mail_alloc(_ctx->transaction, 0, NULL);
		_ctx->dest_mail = ctx->mail;
	}
	mail_set_seq(_ctx->dest_mail, ctx->seq);

	crlf_input = i_stream_create_lf(input);
	ctx->input = index_mail_cache_parse_init(_ctx->dest_mail, crlf_input);
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
		mail_storage_set_critical(_ctx->transaction->box->storage,
			"o_stream_send(%s) failed: %m", 
			ctx->cur_file->current_path);
		ctx->failed = TRUE;
	}

	if (_ctx->received_date == (time_t)-1)
		_ctx->received_date = ioloop_time;
	return ctx->failed ? -1 : 0;
}

int dbox_save_continue(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct mail_storage *storage = &ctx->mbox->storage->storage;

	if (ctx->failed)
		return -1;

	do {
		if (o_stream_send_istream(ctx->cur_output, ctx->input) < 0) {
			if (!mail_storage_set_error_from_errno(storage)) {
				mail_storage_set_critical(storage,
					"o_stream_send_istream(%s) failed: %m",
					ctx->cur_file->current_path);
			}
			ctx->failed = TRUE;
			return -1;
		}
		index_mail_cache_parse_continue(_ctx->dest_mail);

		/* both tee input readers may consume data from our primary
		   input stream. we'll have to make sure we don't return with
		   one of the streams still having data in them. */
	} while (i_stream_read(ctx->input) > 0);
	return 0;
}

static void dbox_save_write_metadata(struct dbox_save_context *ctx)
{
	struct dbox_metadata_header metadata_hdr;
	uint8_t guid_128[16];
	const char *guid;
	string_t *str;
	buffer_t *guid_buf;
	uoff_t vsize;

	memset(&metadata_hdr, 0, sizeof(metadata_hdr));
	memcpy(metadata_hdr.magic_post, DBOX_MAGIC_POST,
	       sizeof(metadata_hdr.magic_post));
	o_stream_send(ctx->cur_output, &metadata_hdr, sizeof(metadata_hdr));

	str = t_str_new(256);
	str_printfa(str, "%c%lx\n", DBOX_METADATA_RECEIVED_TIME,
		    (unsigned long)ctx->ctx.received_date);
	str_printfa(str, "%c%lx\n", DBOX_METADATA_SAVE_TIME,
		    (unsigned long)ioloop_time);
	if (mail_get_virtual_size(ctx->ctx.dest_mail, &vsize) < 0)
		i_unreached();
	str_printfa(str, "%c%llx\n", DBOX_METADATA_VIRTUAL_SIZE,
		    (unsigned long long)vsize);

	/* we can use user-given GUID if
	   a) we're not saving to a multi-file,
	   b) it's 128 bit hex-encoded */
	guid = ctx->ctx.guid;
	if (ctx->ctx.guid != NULL && ctx->cur_file->single_mbox == NULL) {
		guid_buf = buffer_create_dynamic(pool_datastack_create(),
						 sizeof(guid_128));
		if (strlen(guid) != sizeof(guid_128)*2 ||
		    hex_to_binary(guid, guid_buf) < 0 ||
		    guid_buf->used != sizeof(guid_128))
			guid = NULL;
		else
			memcpy(guid_128, guid_buf->data, sizeof(guid_128));
	}

	if (guid == NULL) {
		mail_generate_guid_128(guid_128);
		guid = binary_to_hex(guid_128, sizeof(guid_128));
	}
	if (ctx->cur_file->single_mbox == NULL) {
		/* multi-file: save the 128bit GUID to index so if the map
		   index gets corrupted we can still find the message */
		mail_index_update_ext(ctx->trans, ctx->seq,
				      ctx->mbox->guid_ext_id,
				      guid_128, NULL);
	}
	str_printfa(str, "%c%s\n", DBOX_METADATA_GUID, guid);

	str_append_c(str, '\n');
	o_stream_send(ctx->cur_output, str_data(str), str_len(str));
}

static int dbox_save_mail_write_header(struct dbox_save_mail *mail)
{
	struct dbox_message_header dbox_msg_hdr;

	i_assert(mail->file->msg_header_size == sizeof(dbox_msg_hdr));

	dbox_msg_header_fill(&dbox_msg_hdr, mail->message_size);
	if (pwrite_full(mail->file->fd, &dbox_msg_hdr,
			sizeof(dbox_msg_hdr), mail->append_offset) < 0) {
		dbox_file_set_syscall_error(mail->file, "write()");
		return -1;
	}
	/* we're done writing to single-files now, so fsync them here. */
	if ((mail->file->storage->storage.flags &
	     MAIL_STORAGE_FLAG_FSYNC_DISABLE) == 0 &&
	    mail->file->single_mbox != NULL) {
		if (fdatasync(mail->file->fd) < 0) {
			dbox_file_set_syscall_error(mail->file, "fdatasync()");
			return -1;
		}
	}
	return 0;
}

static int dbox_save_finish_write(struct mail_save_context *_ctx)
{
	struct dbox_save_context *ctx = (struct dbox_save_context *)_ctx;
	struct mail_storage *storage = &ctx->mbox->storage->storage;
	struct dbox_save_mail *save_mail;
	uoff_t metadata_offset = 0;
	unsigned int count;

	ctx->finished = TRUE;
	if (ctx->cur_output == NULL)
		return -1;

	index_mail_cache_parse_deinit(_ctx->dest_mail,
				      _ctx->received_date, !ctx->failed);

	if (!ctx->failed) T_BEGIN {
		metadata_offset = ctx->cur_output->offset;
		dbox_save_write_metadata(ctx);
		if (o_stream_flush(ctx->cur_output) < 0) {
			mail_storage_set_critical(storage,
				"o_stream_flush(%s) failed: %m",
				ctx->cur_file->current_path);
			ctx->failed = TRUE;
		}
	} T_END;

	o_stream_unref(&ctx->cur_output);
	i_stream_unref(&ctx->input);

	count = array_count(&ctx->mails);
	save_mail = array_idx_modifiable(&ctx->mails, count - 1);
	if (!ctx->failed) {
		dbox_file_finish_append(save_mail->file);
		save_mail->message_size = metadata_offset -
			save_mail->append_offset -
			save_mail->file->msg_header_size;
		if (dbox_save_mail_write_header(save_mail) < 0)
			ctx->failed = TRUE;
	}
	if (ctx->failed) {
		dbox_file_cancel_append(save_mail->file,
					save_mail->append_offset);
		array_delete(&ctx->mails, count - 1, 1);
		return -1;
	}

	if (save_mail->file->single_mbox != NULL) {
		dbox_file_close(save_mail->file);
		ctx->single_count++;
	}
	return 0;
}

int dbox_save_finish(struct mail_save_context *ctx)
{
	int ret;

	ret = dbox_save_finish_write(ctx);
	index_save_context_free(ctx);
	return ret;
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
	const struct mail_index_header *hdr;
	uint32_t uid, first_map_uid, last_map_uid, next_uid;

	i_assert(ctx->finished);

	/* get map UIDs for messages saved to multi-files */
	if (dbox_map_append_assign_map_uids(ctx->append_ctx, &first_map_uid,
					    &last_map_uid) < 0) {
		dbox_transaction_save_rollback(ctx);
		return -1;
	}

	/* lock the mailbox */
	if (dbox_sync_begin(ctx->mbox, TRUE, &ctx->sync_ctx) < 0) {
		dbox_transaction_save_rollback(ctx);
		return -1;
	}

	/* assign UIDs for new messages */
	hdr = mail_index_get_header(ctx->sync_ctx->sync_view);
	uid = hdr->next_uid;
	mail_index_append_assign_uids(ctx->trans, uid, &next_uid);

	/* if we saved any single-files, rename the files to contain UIDs */
	if (ctx->single_count > 0) {
		uint32_t last_uid = uid + ctx->single_count - 1;

		if (dbox_map_append_assign_uids(ctx->append_ctx, uid,
						last_uid) < 0) {
			dbox_transaction_save_rollback(ctx);
			return -1;
		}
	}

	/* add map_uids for all messages saved to multi-files */
	if (first_map_uid != 0) {
		struct dbox_mail_index_record rec;
		const struct dbox_save_mail *mails;
		unsigned int i, count;
		uint32_t next_map_uid = first_map_uid;

		memset(&rec, 0, sizeof(rec));
		mails = array_get(&ctx->mails, &count);
		for (i = 0; i < count; i++) {
			if (mails[i].file->single_mbox != NULL)
				continue;

			rec.map_uid = next_map_uid++;
			mail_index_update_ext(ctx->trans, mails[i].seq,
					      ctx->mbox->dbox_ext_id,
					      &rec, NULL);
		}
		i_assert(next_map_uid == last_map_uid + 1);
	}

	dbox_map_append_commit(&ctx->append_ctx);
	if (ctx->mail != NULL)
		mail_free(&ctx->mail);

	*t->ictx.saved_uid_validity = hdr->uid_validity;
	*t->ictx.first_saved_uid = uid;
	*t->ictx.last_saved_uid = next_uid - 1;
	return 0;
}

void dbox_transaction_save_commit_post(struct dbox_save_context *ctx)
{
	ctx->ctx.transaction = NULL; /* transaction is already freed */

	(void)dbox_sync_finish(&ctx->sync_ctx, TRUE);

	if (!ctx->mbox->ibox.fsync_disable) {
		if (fdatasync_path(ctx->mbox->path) < 0) {
			i_error("fdatasync_path(%s) failed: %m",
				ctx->mbox->path);
		}
	}
	dbox_transaction_save_rollback(ctx);
}

void dbox_transaction_save_rollback(struct dbox_save_context *ctx)
{
	if (!ctx->finished)
		dbox_save_cancel(&ctx->ctx);
	if (ctx->append_ctx != NULL)
		dbox_map_append_rollback(&ctx->append_ctx);

	if (ctx->sync_ctx != NULL)
		(void)dbox_sync_finish(&ctx->sync_ctx, FALSE);

	if (ctx->mail != NULL)
		mail_free(&ctx->mail);
	array_free(&ctx->mails);
	i_free(ctx);
}
