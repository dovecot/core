#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "write-full.h"
#include "message-parser.h"
#include "mbox-storage.h"
#include "mbox-sync-private.h"
#include "istream-raw-mbox.h"

int mbox_move(struct mbox_sync_context *sync_ctx,
	      uoff_t dest, uoff_t source, uoff_t size)
{
	struct istream *input;
	struct ostream *output;
	off_t ret;

	i_assert(size < OFF_T_MAX);

	if (size == 0 || source == dest)
		return 0;

	istream_raw_mbox_flush(sync_ctx->input);

	output = o_stream_create_file(sync_ctx->fd, default_pool, 4096, FALSE);
	i_stream_seek(sync_ctx->file_input, source);
	o_stream_seek(output, dest);

	if (size == (uoff_t)-1) {
		input = sync_ctx->file_input;
		ret = o_stream_send_istream(output, input) < 0 ? -1 : 0;
	} else {
		input = i_stream_create_limit(default_pool,
					      sync_ctx->file_input,
					      source, size);
		ret = o_stream_send_istream(output, input);
		i_stream_unref(input);
		ret = ret == (off_t)size ? 0 : -1;
	}

	if (ret < 0) {
		errno = output->stream_errno;
		mbox_set_syscall_error(sync_ctx->ibox,
				       "o_stream_send_istream()");
	}

	o_stream_unref(output);
	return (int)ret;
}

static int mbox_fill_space(struct mbox_sync_context *sync_ctx,
			   uoff_t offset, uoff_t size)
{
	unsigned char space[1024];

	memset(space, ' ', sizeof(space));
	while (size > sizeof(space)) {
		if (pwrite_full(sync_ctx->fd, space,
				sizeof(space), offset) < 0) {
			mbox_set_syscall_error(sync_ctx->ibox, "pwrite_full()");
			return -1;
		}
		size -= sizeof(space);
	}

	if (pwrite_full(sync_ctx->fd, space, size, offset) < 0) {
		mbox_set_syscall_error(sync_ctx->ibox, "pwrite_full()");
		return -1;
	}
	return 0;
}

static void mbox_sync_headers_add_space(struct mbox_sync_mail_context *ctx,
					size_t size)
{
	size_t data_size, pos, start_pos;
	const unsigned char *data;
	void *p;

	i_assert(size < SSIZE_T_MAX);

	/* Append at the end of X-Keywords header,
	   or X-UID if it doesn't exist */
	start_pos = ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] != (size_t)-1 ?
		ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] :
		ctx->hdr_pos[MBOX_HDR_X_UID];

	data = str_data(ctx->header);
	data_size = str_len(ctx->header);

	for (pos = start_pos; pos < data_size; pos++) {
		if (data[pos] == '\n') {
			/* possibly continues in next line */
			if (pos+1 == data_size || !IS_LWSP(data[pos+1]))
				break;
			start_pos = pos+1;
		} else if (!IS_LWSP(data[pos])) {
			start_pos = pos+1;
		}
	}

	/* pos points to end of headers now, and start_pos to beginning
	   of whitespace. */
	buffer_copy(ctx->header, pos + size,
		    ctx->header, pos, (size_t)-1);
	p = buffer_get_space_unsafe(ctx->header, pos, size);
	memset(p, ' ', size);

	ctx->mail.offset = ctx->hdr_offset + start_pos;
	ctx->mail.space = (pos - start_pos) + size;

	if (ctx->header_first_change > pos)
		ctx->header_first_change = pos;
	ctx->header_last_change = (size_t)-1;
}

static void mbox_sync_header_remove_space(struct mbox_sync_mail_context *ctx,
					  size_t start_pos, size_t *size)
{
	const unsigned char *data;
	size_t data_size, pos, last_line_pos;

	/* find the end of the LWSP */
	data = str_data(ctx->header);
	data_size = str_len(ctx->header);

	for (pos = last_line_pos = start_pos; pos < data_size; pos++) {
		if (data[pos] == '\n') {
			/* possibly continues in next line */
			if (pos+1 == data_size || !IS_LWSP(data[pos+1])) {
				data_size = pos;
				break;
			}
                        last_line_pos = pos+1;
		} else if (!IS_LWSP(data[pos])) {
			start_pos = last_line_pos = pos+1;
		}
	}

	if (start_pos == data_size)
		return;

	/* and remove what we can */
	if (ctx->header_first_change > start_pos)
		ctx->header_first_change = start_pos;
	ctx->header_last_change = (size_t)-1;

	if (data_size - start_pos <= *size) {
		/* remove it all */
		str_delete(ctx->header, start_pos, data_size - start_pos);
		*size -= data_size - start_pos;
		return;
	}

	/* we have more space than needed. since we're removing from
	   the beginning of header instead of end, we don't have to
	   worry about multiline-headers. */
	str_delete(ctx->header, start_pos, *size);
	last_line_pos = last_line_pos <= *size ?
		start_pos : last_line_pos - *size;

	data_size -= *size;
	*size = 0;

	if (ctx->mail.space < data_size - last_line_pos) {
		ctx->mail.space = data_size - last_line_pos;
		ctx->mail.offset = ctx->hdr_offset + last_line_pos;
	}
}

static void mbox_sync_headers_remove_space(struct mbox_sync_mail_context *ctx,
					   size_t size)
{
	static enum header_position space_positions[] = {
                MBOX_HDR_X_UID,
                MBOX_HDR_X_KEYWORDS,
                MBOX_HDR_X_IMAPBASE
	};
        enum header_position pos;
	int i;

	ctx->mail.space = 0;
	ctx->mail.offset = ctx->hdr_offset;

	for (i = 0; i < 3 && size > 0; i++) {
		pos = space_positions[i];
		if (ctx->hdr_pos[pos] != (size_t)-1) {
			mbox_sync_header_remove_space(ctx, ctx->hdr_pos[pos],
						      &size);
		}
	}

	/* FIXME: see if we could remove X-Keywords header completely */
}

int mbox_sync_try_rewrite(struct mbox_sync_mail_context *ctx, off_t move_diff)
{
	size_t old_hdr_size, new_hdr_size;

	i_assert(ctx->sync_ctx->ibox->mbox_lock_type == F_WRLCK);

	old_hdr_size = ctx->body_offset - ctx->hdr_offset;
	new_hdr_size = str_len(ctx->header);

	if (new_hdr_size <= old_hdr_size) {
		/* add space. note that we must call add_space() even if we're
		   not adding anything so mail.offset gets fixed. */
		mbox_sync_headers_add_space(ctx, old_hdr_size - new_hdr_size);
	} else if (new_hdr_size > old_hdr_size) {
		/* try removing the space where we can */
		mbox_sync_headers_remove_space(ctx,
					       new_hdr_size - old_hdr_size);
		new_hdr_size = str_len(ctx->header);

		if (new_hdr_size <= old_hdr_size) {
			/* good, we removed enough. */
			i_assert(new_hdr_size == old_hdr_size);
			ctx->mail.space =
				-(ssize_t)(new_hdr_size - old_hdr_size);
		} else if (move_diff < 0 &&
			   new_hdr_size - old_hdr_size <= -move_diff) {
			/* moving backwards - we can use the extra space from
			   it, just update expunged_space accordingly */
			i_assert(ctx->mail.space == 0);
			i_assert(ctx->sync_ctx->expunged_space >=
				 new_hdr_size - old_hdr_size);
			ctx->sync_ctx->expunged_space -=
				new_hdr_size - old_hdr_size;
		} else {
			/* couldn't get enough space */
			i_assert(ctx->mail.space == 0);
			ctx->mail.space =
				-(ssize_t)(new_hdr_size - old_hdr_size);
			return 0;
		}
	}

	i_assert(ctx->mail.space >= 0);

	if (ctx->header_first_change == (size_t)-1 && move_diff == 0) {
		/* no changes actually. we get here if index sync record told
		   us to do something that was already there */
		return 1;
	}

	if (move_diff != 0 || ctx->no_partial_rewrite) {
		/* forget about partial write optimizations */
		ctx->header_first_change = 0;
		ctx->header_last_change = 0;
	}

	if (ctx->header_last_change != (size_t)-1 &&
	    ctx->header_last_change != 0)
		str_truncate(ctx->header, ctx->header_last_change);

	if (pwrite_full(ctx->sync_ctx->fd,
			str_data(ctx->header) + ctx->header_first_change,
			str_len(ctx->header) - ctx->header_first_change,
			ctx->hdr_offset + move_diff +
			ctx->header_first_change) < 0) {
		mbox_set_syscall_error(ctx->sync_ctx->ibox, "pwrite_full()");
		return -1;
	}
	istream_raw_mbox_flush(ctx->sync_ctx->input);
	return 1;
}

static int mbox_sync_read_and_move(struct mbox_sync_context *sync_ctx,
				   struct mbox_sync_mail *mails,
				   uint32_t seq, uint32_t idx,
				   uoff_t space_diff, uoff_t end_offset)
{
	struct mbox_sync_mail_context mail_ctx;
	uint32_t old_prev_msg_uid;
	uoff_t hdr_offset, offset, dest_offset;
	size_t old_hdr_size, need_space;

	if (mbox_sync_seek(sync_ctx, mails[idx].from_offset) < 0)
		return -1;

	memset(&mail_ctx, 0, sizeof(mail_ctx));
	mail_ctx.sync_ctx = sync_ctx;
	mail_ctx.seq = seq;
	mail_ctx.header = sync_ctx->header;

	hdr_offset = mails[idx].offset;
	mail_ctx.mail.offset = mails[idx].offset;
	mail_ctx.mail.body_size = mails[idx].body_size;

	/* mbox_sync_parse_next_mail() checks that UIDs are growing,
	   so we have to fool it. */
	old_prev_msg_uid = sync_ctx->prev_msg_uid;
	sync_ctx->prev_msg_uid = mails[idx].uid-1;
	sync_ctx->dest_first_mail = seq == 1;

	mbox_sync_parse_next_mail(sync_ctx->input, &mail_ctx, TRUE);
	if (mails[idx].space != 0)
		mbox_sync_update_header_from(&mail_ctx, &mails[idx]);
	else {
		/* updating might just try to add headers and mess up our
		   calculations completely. so only add the EOH here. */
		if (mail_ctx.have_eoh)
			str_append_c(mail_ctx.header, '\n');
	}

	sync_ctx->prev_msg_uid = old_prev_msg_uid;
	sync_ctx->dest_first_mail = FALSE;

	old_hdr_size = mail_ctx.body_offset - mail_ctx.hdr_offset;
	need_space = str_len(mail_ctx.header) - mail_ctx.mail.space -
		old_hdr_size;
	i_assert(need_space == -mails[idx].space);
	i_assert(space_diff >= need_space);

	if (space_diff - need_space < (uoff_t)mail_ctx.mail.space) {
		mbox_sync_headers_remove_space(&mail_ctx, mail_ctx.mail.space -
					       (space_diff - need_space));
	} else {
		mbox_sync_headers_add_space(&mail_ctx, space_diff - need_space -
					    mail_ctx.mail.space);
	}
	mails[idx].offset = mail_ctx.mail.offset;
	mails[idx].space = mail_ctx.mail.space;

	/* move the body of this message and headers of next message forward,
	   then write the headers */
	offset = sync_ctx->input->v_offset;
	dest_offset = offset + space_diff;
	if (mbox_move(sync_ctx, dest_offset, offset,
		      end_offset - dest_offset) < 0)
		return -1;

	if (pwrite_full(sync_ctx->fd, str_data(mail_ctx.header),
			str_len(mail_ctx.header), hdr_offset) < 0) {
		mbox_set_syscall_error(sync_ctx->ibox, "pwrite_full()");
		return -1;
	}

	return 0;
}

/* extra_space specifies how many bytes from last_seq's space will be left
   over after all the rewrites. */
int mbox_sync_rewrite(struct mbox_sync_context *sync_ctx, uoff_t extra_space,
		      uint32_t first_seq, uint32_t last_seq)
{
	struct mbox_sync_mail *mails;
	uoff_t offset, end_offset, dest_offset, space_diff;
	uint32_t idx, extra_per_mail;
	size_t size;
	int ret = 0;

	i_assert(first_seq != last_seq);
	i_assert(sync_ctx->ibox->mbox_lock_type == F_WRLCK);

	mails = buffer_get_modifyable_data(sync_ctx->mails, &size);
	i_assert(size / sizeof(*mails) == last_seq - first_seq + 1);

	/* if there's expunges in mails[], we would get more correct balancing
	   by counting only them here. however, that might make us overwrite
	   data which hasn't yet been copied backwards. to avoid too much
	   complexity, we just leave all the rest of the extra space to first
	   mail */
	idx = last_seq - first_seq;
	extra_per_mail = extra_space / (idx + 1);

	/* after expunge the next mail must have been missing space, or we
	   would have moved it backwards already */
	i_assert(mails[0].space < 0 || mails[0].uid == 0);

	/* start moving backwards. */
	do {
		/* this message's body is always moved space_diff bytes
		   forward along with next message's headers, so current
		   message gets temporarily space_diff amount of extra
		   whitespace.

		   the moving stops at next message's beginning of extra
		   space. each message gets left extra_per_mail bytes of
		   space. what gets left over is given to first message */
		i_assert(mails[idx].space > 0);
		space_diff = mails[idx].space;
		end_offset = mails[idx].offset + mails[idx].space;

		if (mails[idx].uid != 0) {
			space_diff -= extra_per_mail;
			end_offset -= extra_per_mail;
			mails[idx].space = extra_per_mail;
		}

		idx--;
		if (mails[idx].space <= 0 && mails[idx].uid != 0) {
			/* offset points to beginning of headers. read the
			   header again, update it and give enough space to
			   fill space_diff */
			if (mbox_sync_read_and_move(sync_ctx, mails,
						    first_seq + idx, idx,
						    space_diff,
						    end_offset) < 0) {
				ret = -1;
				break;
			}
		} else {
			/* X-Keywords: xx    [offset]\n
			   ...
			   X-Keywords: xx    [end_offset]   \n

			   move data forward so mails before us gets the extra
			   space (ie. we temporarily get more space to us) */
			offset = mails[idx].offset + mails[idx].space;
			dest_offset = offset + space_diff;
			if (mbox_move(sync_ctx, dest_offset, offset,
				      end_offset - dest_offset) < 0) {
				ret = -1;
				break;
			}

			if (mbox_fill_space(sync_ctx, offset,
					    dest_offset - offset) < 0) {
				ret = -1;
				break;
			}

			mails[idx].space += space_diff;
 		}

		mails[idx+1].from_offset += space_diff;
	} while (idx > 0);

	istream_raw_mbox_flush(sync_ctx->input);
	return ret;
}
