/* Copyright (C) 2004 Timo Sirainen */

/*
   Modifying mbox can be slow, so we try to do it all at once minimizing the
   required disk I/O. We may need to:

   - Update message flags in Status, X-Status and X-Keywords headers
   - Write missing X-UID and X-IMAPbase headers
   - Write missing or broken Content-Length header if there's space
   - Expunge specified messages

   Here's how we do it:

   - Start reading the mails mail headers from the beginning
   - X-Keywords and X-UID headers may contain extra spaces at the end of them,
     remember how much extra each message has and offset to beginning of the
     spaces
   - If message flags are dirty and there's enough space to write them, do it
   - If we didn't have enough space, remember how much was missing and keep
     the total amount of them
   - When we encounter expunged message, check if the amount of empty space in
     previous messages plus size of expunged message is enough to cover the
     missing space. If yes,
       - execute the rewrite plan
       - forget all the messages before the expunged message. only remember
         how much data we still have to move to cover the expunged message
   - If we encounter end of file, grow the file and execute the rewrite plan

   Rewrite plan goes:

   - Start from the first message that needs more space
   - If there's expunged messages before us, we have to write over them.
       - Move all messages after it backwards to fill it
       - Each moved message's X-Keywords header should have n bytes extra
         space, unless there's not enough space to do it.
   - If there's no expunged messages, we can move data either forward or
     backward to get it. Calculate which requires less moving. Forward
     counting may encounter more messages which require extra space, count
     that too.
       - If we decide to move forwards and we had to go through dirty
         messages, do the moving from last to first dirty message
   - If we encounter end of file, grow the file enough to get the required
     amount of space plus enough space to fill X-Keywords headers full of
     spaces.
*/

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "istream.h"
#include "file-set-size.h"
#include "str.h"
#include "write-full.h"
#include "istream-raw-mbox.h"
#include "mbox-storage.h"
#include "mbox-file.h"
#include "mbox-sync-private.h"

#include <sys/stat.h>

static int mbox_sync_grow_file(struct mbox_sync_context *sync_ctx,
			       struct mbox_sync_mail *mail, uoff_t body_offset,
			       uoff_t grow_size)
{
	char spaces[1024];
	uoff_t offset, size;

	i_assert(grow_size > 0);

	memset(spaces, ' ', sizeof(spaces));

	size = sync_ctx->input->v_offset + grow_size;
	if (file_set_size(sync_ctx->fd, size) < 0)
		return -1;

	if (mail->space_offset == 0) {
		/* no X-Keywords header - place it at the end. */
		grow_size += 13;

		offset = body_offset-1;
		if (mbox_move(sync_ctx, body_offset-1 + size,
			      offset, (uoff_t)-1) < 0)
			return -1;
		if (pwrite_full(sync_ctx->fd, "X-Keywords: ", 12, offset) < 0)
			return -1;
		if (pwrite_full(sync_ctx->fd, "\n", 1,
				offset + grow_size-1) < 0)
			return -1;
		grow_size -= 13; offset += 12;

		/* FIXME: can this break anything? X-Keywords text might
		   have been already included in space calculation. now we
		   have more.. */
		mail->space_offset = offset;
		mail->space += grow_size;
	} else {
		offset = mail->space_offset;
		if (mbox_move(sync_ctx, mail->space_offset + grow_size,
			      offset, (uoff_t)-1) < 0)
			return -1;
	}

	while (grow_size >= sizeof(spaces)) {
		if (pwrite_full(sync_ctx->fd, spaces,
				sizeof(spaces), offset) < 0)
			return -1;
		grow_size -= sizeof(spaces);
		offset += sizeof(spaces);
	}

	if (grow_size > 0) {
		if (pwrite_full(sync_ctx->fd, spaces, grow_size, offset) < 0)
			return -1;
	}

	istream_raw_mbox_flush(sync_ctx->input);
	return 0;
}

int mbox_sync(struct index_mailbox *ibox, int last_commit)
{
	struct mbox_sync_context sync_ctx;
	struct mbox_sync_mail_context mail_ctx;
	struct mbox_sync_mail mail;
	struct mail_index_sync_ctx *index_sync_ctx;
	struct mail_index_view *sync_view;
	const struct mail_index_header *hdr;
	struct istream *input;
	uint32_t seq, need_space_seq;
	off_t space_diff;
	uoff_t from_offset, offset;
	buffer_t *mails;
	string_t *header;
	struct stat st;
	int readonly, ret = 0;

	if (last_commit) {
		seq = ibox->commit_log_file_seq;
		offset = ibox->commit_log_file_offset;
	} else {
		seq = 0;
		offset = 0;
	}

	ret = mail_index_sync_begin(ibox->index, &index_sync_ctx, &sync_view,
				    seq, offset);
	if (ret <= 0)
		return ret;

	if (mbox_file_open_stream(ibox) < 0)
		return -1;

	if (mail_index_get_header(sync_view, &hdr) < 0)
		return -1;

	if (ibox->mbox_data_buf == NULL) {
		ibox->mbox_data_buf =
			buffer_create_dynamic(default_pool, 512, (size_t)-1);
	} else {
		buffer_set_used_size(ibox->mbox_data_buf, 0);
	}

	readonly = TRUE; // FIXME

	// FIXME: lock the file

	mails = buffer_create_dynamic(default_pool, 4096, (size_t)-1);

	memset(&sync_ctx, 0, sizeof(sync_ctx));
	sync_ctx.file_input = ibox->mbox_file_stream;
	sync_ctx.input = ibox->mbox_stream;
	sync_ctx.fd = ibox->mbox_fd;
	sync_ctx.hdr = hdr;

	input = sync_ctx.input;
	header = str_new(default_pool, 4096);

	space_diff = 0; need_space_seq = 0; seq = 1;
	for (seq = 1; !input->eof; seq++) {
		from_offset = input->v_offset;

		memset(&mail, 0, sizeof(mail));
		memset(&mail_ctx, 0, sizeof(mail_ctx));
		mail_ctx.sync_ctx = &sync_ctx;
		mail_ctx.mail = &mail;
		mail_ctx.seq = seq;
		mail_ctx.header = header;

		mbox_sync_parse_next_mail(input, &mail_ctx);
		if (input->v_offset == from_offset) {
			/* this was the last mail */
			break;
		}

		mail.body_size =
			istream_raw_mbox_get_size(input,
						  mail_ctx.content_length);
		buffer_append(mails, &mail, sizeof(mail));

		/* save the offset permanently with recent flag state */
		from_offset <<= 1;
		if ((mail.flags & MBOX_NONRECENT) != 0)
			from_offset |= 1;
		buffer_append(ibox->mbox_data_buf,
			      &from_offset, sizeof(from_offset));

		if (mail_ctx.need_rewrite && !readonly) {
			mbox_sync_update_header(&mail_ctx, NULL);
			if ((ret = mbox_sync_try_rewrite(&mail_ctx)) < 0)
				break;
		} else {
			ret = 1;
		}

		if (ret == 0 && need_space_seq == 0) {
			/* didn't have space to write it */
			need_space_seq = seq;
			space_diff = mail.space;
		} else if (need_space_seq != 0) {
			space_diff += mail.space;
			if (space_diff >= 0) {
				/* we have enough space now */
				if (mbox_sync_rewrite(&sync_ctx, mails,
						      need_space_seq, seq,
						      space_diff) < 0) {
					ret = -1;
					break;
				}
				need_space_seq = 0;
			}
		}

		istream_raw_mbox_next(input, mail.body_size);
	}

	if (need_space_seq != 0) {
		i_assert(space_diff < 0);
		if (mbox_sync_grow_file(&sync_ctx, &mail, mail_ctx.body_offset,
					-space_diff) < 0)
			ret = -1;
		else if (mbox_sync_rewrite(&sync_ctx, mails, need_space_seq,
					   seq-1, space_diff) < 0)
			ret = -1;
	}

	if (fstat(ibox->mbox_fd, &st) < 0) {
		mbox_set_syscall_error(ibox, "fstat()");
		ret = -1;
	}

	if (ret < 0) {
		st.st_mtime = 0;
		st.st_size = 0;
	}

	if (mail_index_sync_end(index_sync_ctx, st.st_mtime, st.st_size) < 0)
		ret = -1;

	str_free(header);
	return ret < 0 ? -1 : 0;
}

int mbox_storage_sync(struct mailbox *box, enum mailbox_sync_flags flags)
{
	struct index_mailbox *ibox = (struct index_mailbox *)box;

	if ((flags & MAILBOX_SYNC_FLAG_FAST) == 0 ||
	    ibox->sync_last_check + MAILBOX_FULL_SYNC_INTERVAL <= ioloop_time) {
		ibox->sync_last_check = ioloop_time;

		if (mbox_sync(ibox, FALSE) < 0)
			return -1;
	}

	return index_storage_sync(box, flags);
}
