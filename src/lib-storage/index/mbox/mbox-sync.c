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
#include "buffer.h"
#include "istream.h"
#include "file-set-size.h"
#include "str.h"
#include "write-full.h"
#include "istream-raw-mbox.h"
#include "mbox-sync-private.h"

static int mbox_sync_grow_file(struct mbox_sync_context *sync_ctx,
			       struct mbox_mail *mail, uoff_t body_offset,
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

int mbox_sync(struct istream *input)
{
	struct mbox_sync_context sync_ctx;
	struct mbox_sync_mail_context mail_ctx;
	struct mbox_mail mail;
	uint32_t seq, need_space_seq;
	off_t space_diff;
	buffer_t *mails;
	int ret = 0;

	mails = buffer_create_dynamic(default_pool, 4096, (size_t)-1);

	memset(&sync_ctx, 0, sizeof(sync_ctx));
	sync_ctx.file_input = input;
	sync_ctx.input = i_stream_create_raw_mbox(default_pool, input);
	sync_ctx.fd = i_stream_get_fd(input);
	//sync_ctx.hdr = ;

	input = sync_ctx.input;

	space_diff = 0; need_space_seq = 0; seq = 1;
	for (seq = 1; !input->eof; seq++) {
		memset(&mail, 0, sizeof(mail));
		memset(&mail_ctx, 0, sizeof(mail_ctx));
		mail_ctx.sync_ctx = &sync_ctx;
		mail_ctx.mail = &mail;
		mail_ctx.seq = seq;

		mbox_sync_parse_next_mail(input, &mail_ctx);
		mail.body_size =
			istream_raw_mbox_get_size(input,
						  mail_ctx.content_length);
		buffer_append(mails, &mail, sizeof(mail));

		if (mail_ctx.need_rewrite) {
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

	i_stream_unref(input);
	return ret < 0 ? -1 : 0;
}

#if 0
int mbox_sync(void)
{
	struct mail_index_view *sync_view;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_sync_rec sync_rec;
	struct mbox_sync_context ctx;
	struct mbox_sync_mail_context mail_ctx;
	struct mbox_mail mail;
	string_t *header;
	uint32_t seq;
	unsigned int need_space_seq;
	uoff_t missing_space;
	buffer_t *mails;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	/*ctx.index = storage->index;
	ctx.input = storage->input;*/
	ctx.fd = i_stream_get_fd(ctx.input);

	header = str_new(default_pool, 4096);

	if (mail_index_sync_begin(ctx.index, &sync_ctx, &sync_view, 0, 0) < 0)
		return -1;

	ctx.hdr = mail_index_get_header(sync_view);
	ctx.next_uid = ctx.hdr->next_uid;

	seq = 1;
	while ((ret = mail_index_sync_next(sync_ctx, &sync_rec)) > 0) {
		while (seq < sync_rec.seq1) {
			seq++;
		}
		switch (sync_rec.type) {
		case MAIL_INDEX_SYNC_TYPE_EXPUNGE:
			break;
		case MAIL_INDEX_SYNC_TYPE_FLAGS:
			break;
		}
	}

	while (!ctx.input->eof) {
		memset(&mail_ctx, 0, sizeof(mail_ctx));
		mail_ctx.parent = &ctx;
		mail_ctx.header = header;
		mail_ctx.seq = seq;

		mail_ctx.hdr_offset = ctx.input->v_offset;
		mbox_sync_mail_parse_headers(&mail_ctx);
		mail_ctx.body_offset = ctx.input->v_offset;
		mail_ctx.body_size =
			istream_raw_mbox_get_size(ctx.input,
						  mail_ctx.content_length);

                mbox_sync_mail_add_missing_headers(&mail_ctx);

		ret = mbox_sync_try_rewrite_headers(&mail_ctx, &missing_space);
		if (ret < 0)
			break;
		if (missing_space != 0) {
			ctx.space_diff -= missing_space;
		} else {
			ctx.space_diff += mail_ctx.extra_space;
		}

		if (ctx.first_spacy_msg_offset == 0)
                        ctx.first_spacy_msg_offset = mail_ctx.hdr_offset;

		ctx.prev_msg_uid = mail_ctx.uid;
		istream_raw_mbox_next(ctx.input, mail_ctx.content_length);
	}
	str_free(header);
	return 0;
}
#endif
