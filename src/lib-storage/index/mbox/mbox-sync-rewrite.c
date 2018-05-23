/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
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
	struct mbox_mailbox *mbox = sync_ctx->mbox;
	struct istream *input;
	struct ostream *output;
	int ret;

	i_assert(source > 0 || (dest != 1 && dest != 2));
	i_assert(size < OFF_T_MAX);

	if (size == 0 || source == dest)
		return 0;

	i_stream_sync(sync_ctx->input);

	output = o_stream_create_fd_file(sync_ctx->write_fd, (uoff_t)-1, FALSE);
	i_stream_seek(sync_ctx->file_input, source);
	if (o_stream_seek(output, dest) < 0) {
		mbox_set_syscall_error(sync_ctx->mbox,
				       "o_stream_seek()");
		o_stream_unref(&output);
		return -1;
	}

	/* we're moving data within a file. it really shouldn't be failing at
	   this point or we're corrupted. */
	input = i_stream_create_limit(sync_ctx->file_input, size);
	o_stream_nsend_istream(output, input);
	if (input->stream_errno != 0) {
		mailbox_set_critical(&mbox->box,
			"read() failed with mbox: %s",
			i_stream_get_error(input));
		ret = -1;
	} else if (output->stream_errno != 0) {
		mailbox_set_critical(&mbox->box,
			"write() failed with mbox: %s",
			o_stream_get_error(output));
		ret = -1;
	} else if (input->v_offset != size) {
		mbox_sync_set_critical(sync_ctx,
			"mbox_move(%"PRIuUOFF_T", %"PRIuUOFF_T", %"PRIuUOFF_T
			") moved only %"PRIuUOFF_T" bytes",
			dest, source, size, input->v_offset);
		ret = -1;
	} else {
		ret = 0;
	}
	i_stream_unref(&input);

	mbox_sync_file_updated(sync_ctx, FALSE);
	o_stream_destroy(&output);
	return ret;
}

static int mbox_fill_space(struct mbox_sync_context *sync_ctx,
			   uoff_t offset, uoff_t size)
{
	unsigned char space[1024];

	memset(space, ' ', sizeof(space));
	while (size > sizeof(space)) {
		if (pwrite_full(sync_ctx->write_fd, space,
				sizeof(space), offset) < 0) {
			mbox_set_syscall_error(sync_ctx->mbox, "pwrite_full()");
			return -1;
		}
		size -= sizeof(space);
	}

	if (pwrite_full(sync_ctx->write_fd, space, size, offset) < 0) {
		mbox_set_syscall_error(sync_ctx->mbox, "pwrite_full()");
		return -1;
	}
	mbox_sync_file_updated(sync_ctx, TRUE);
	return 0;
}

void mbox_sync_headers_add_space(struct mbox_sync_mail_context *ctx,
				 size_t size)
{
	size_t data_size, pos, start_pos;
	const unsigned char *data;
	void *p;

	i_assert(size < SSIZE_T_MAX);

	if (ctx->mail.pseudo)
		start_pos = ctx->hdr_pos[MBOX_HDR_X_IMAPBASE];
	else if (ctx->mail.space > 0) {
		/* update the header using the existing offset.
		   otherwise we might chose wrong header and just decrease
		   the available space */
		start_pos = ctx->mail.offset - ctx->hdr_offset;
	} else {
		/* Append at the end of X-Keywords header,
		   or X-UID if it doesn't exist */
		start_pos = ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] != (size_t)-1 ?
			ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] :
			ctx->hdr_pos[MBOX_HDR_X_UID];
	}

	data = str_data(ctx->header);
	data_size = str_len(ctx->header);
	i_assert(start_pos < data_size);

	for (pos = start_pos; pos < data_size; pos++) {
		if (data[pos] == '\n') {
			/* possibly continues in next line */
			if (pos+1 == data_size || !IS_LWSP(data[pos+1]))
				break;
			start_pos = pos+1;
		} else if (!IS_LWSP(data[pos]) && data[pos] != '\r') {
			start_pos = pos+1;
		}
	}

	/* pos points to end of header now, and start_pos to beginning
	   of whitespace. */
	mbox_sync_move_buffer(ctx, pos, size, 0);

	p = buffer_get_space_unsafe(ctx->header, pos, size);
	memset(p, ' ', size);

	if (ctx->header_first_change > pos)
		ctx->header_first_change = pos;
	ctx->header_last_change = (size_t)-1;

	ctx->mail.space = (pos - start_pos) + size;
	ctx->mail.offset = ctx->hdr_offset;
	if (ctx->mail.space > 0)
		ctx->mail.offset += start_pos;
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
		} else if (!IS_LWSP(data[pos]) && data[pos] != '\r') {
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
		mbox_sync_move_buffer(ctx, start_pos, 0, data_size - start_pos);
		*size -= data_size - start_pos;
		return;
	}

	/* we have more space than needed. since we're removing from
	   the beginning of header instead of end, we don't have to
	   worry about multiline-headers. */
	mbox_sync_move_buffer(ctx, start_pos, 0, *size);
	if (last_line_pos <= start_pos + *size)
		last_line_pos = start_pos;
	else
		last_line_pos -= *size;
	data_size -= *size;

	*size = 0;

	if (ctx->mail.space < (off_t)(data_size - last_line_pos)) {
		ctx->mail.space = data_size - last_line_pos;
		ctx->mail.offset = ctx->hdr_offset;
		if (ctx->mail.space > 0)
			ctx->mail.offset += last_line_pos;
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

static void mbox_sync_first_mail_written(struct mbox_sync_mail_context *ctx,
					 uoff_t hdr_offset)
{
	/* we wrote the first mail. update last-uid offset so we can find
	   it later */
	i_assert(ctx->last_uid_value_start_pos != 0);
	i_assert(ctx->hdr_pos[MBOX_HDR_X_IMAPBASE] != (size_t)-1);

	ctx->sync_ctx->base_uid_last_offset = hdr_offset +
		ctx->hdr_pos[MBOX_HDR_X_IMAPBASE] +
		ctx->last_uid_value_start_pos;

	if (ctx->imapbase_updated) {
		/* update so a) we don't try to update it later needlessly,
		   b) if we do actually update it, we see the correct value */
		ctx->sync_ctx->base_uid_last = ctx->last_uid_updated_value;
	}
}

int mbox_sync_try_rewrite(struct mbox_sync_mail_context *ctx, off_t move_diff)
{
        struct mbox_sync_context *sync_ctx = ctx->sync_ctx;
	size_t old_hdr_size, new_hdr_size;

	i_assert(sync_ctx->mbox->mbox_lock_type == F_WRLCK);

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
		} else if (move_diff < 0 &&
			   new_hdr_size - old_hdr_size <= (uoff_t)-move_diff) {
			/* moving backwards - we can use the extra space from
			   it, just update expunged_space accordingly */
			i_assert(ctx->mail.space == 0);
			i_assert(sync_ctx->expunged_space >=
				 (off_t)(new_hdr_size - old_hdr_size));
			sync_ctx->expunged_space -= new_hdr_size - old_hdr_size;
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

	if (move_diff != 0) {
		/* forget about partial write optimizations */
		ctx->header_first_change = 0;
		ctx->header_last_change = 0;
	}

	if (ctx->header_last_change != (size_t)-1 &&
	    ctx->header_last_change != 0)
		str_truncate(ctx->header, ctx->header_last_change);

	if (pwrite_full(sync_ctx->write_fd,
			str_data(ctx->header) + ctx->header_first_change,
			str_len(ctx->header) - ctx->header_first_change,
			ctx->hdr_offset + ctx->header_first_change +
			move_diff) < 0) {
		mbox_set_syscall_error(sync_ctx->mbox, "pwrite_full()");
		return -1;
	}

	if (sync_ctx->dest_first_mail &&
	    (ctx->imapbase_updated || ctx->sync_ctx->base_uid_last != 0)) {
		/* the position might have moved as a result of moving
		   whitespace */
		mbox_sync_first_mail_written(ctx, ctx->hdr_offset + move_diff);
	}

	mbox_sync_file_updated(sync_ctx, FALSE);
	return 1;
}

static int mbox_sync_read_next(struct mbox_sync_context *sync_ctx,
			       struct mbox_sync_mail_context *mail_ctx,
			       struct mbox_sync_mail *mails,
			       uint32_t seq, uint32_t idx,
			       uoff_t expunged_space)
{
	unsigned int first_mail_expunge_extra;
	uint32_t orig_next_uid;

	i_zero(mail_ctx);
	mail_ctx->sync_ctx = sync_ctx;
	mail_ctx->seq = seq;
	mail_ctx->header = sync_ctx->header;

	if (istream_raw_mbox_get_header_offset(sync_ctx->input,
					       &mail_ctx->mail.offset) < 0) {
		mbox_sync_set_critical(sync_ctx,
			"Couldn't get header offset for seq=%u", seq);
		return -1;
	}
	mail_ctx->mail.body_size = mails[idx].body_size;

	orig_next_uid = sync_ctx->next_uid;
	if (mails[idx].uid != 0) {
		/* This will force the UID to be the one that we originally
		   assigned to it, regardless of whether it's broken or not in
		   the file. */
		sync_ctx->next_uid = mails[idx].uid;
		sync_ctx->prev_msg_uid = mails[idx].uid - 1;
	} else {
		/* Pseudo mail shouldn't have X-UID header at all */
		i_assert(mails[idx].pseudo);
		sync_ctx->prev_msg_uid = 0;
	}

	first_mail_expunge_extra = 1 +
		(sync_ctx->first_mail_crlf_expunged ? 1 : 0);
	if (mails[idx].from_offset +
	    first_mail_expunge_extra - expunged_space != 0) {
		sync_ctx->dest_first_mail = mails[idx].from_offset == 0;
	} else {
		/* we need to skip over the initial \n (it's already counted in
		   expunged_space) */
		sync_ctx->dest_first_mail = TRUE;
		mails[idx].from_offset += first_mail_expunge_extra;
	}

	if (mbox_sync_parse_next_mail(sync_ctx->input, mail_ctx) < 0)
		return -1;
	i_assert(mail_ctx->mail.pseudo == mails[idx].pseudo);

	/* set next_uid back before updating the headers. this is important
	   if we're updating the first message to make X-IMAP[base] header
	   have the correct value. */
	sync_ctx->next_uid = orig_next_uid;

	if (mails[idx].space != 0) {
		if (mails[idx].space < 0) {
			/* remove all possible spacing before updating */
			mbox_sync_headers_remove_space(mail_ctx, (size_t)-1);
		}
		mbox_sync_update_header_from(mail_ctx, &mails[idx]);
	} else {
		/* updating might just try to add headers and mess up our
		   calculations completely. so only add the EOH here. */
		if (mail_ctx->have_eoh)
			str_append_c(mail_ctx->header, '\n');
	}
	return 0;
}

static int mbox_sync_read_and_move(struct mbox_sync_context *sync_ctx,
                                   struct mbox_sync_mail_context *mail_ctx,
				   struct mbox_sync_mail *mails,
				   uint32_t seq, uint32_t idx, uint32_t padding,
				   off_t move_diff, uoff_t expunged_space,
				   uoff_t end_offset, bool first_nonexpunged)
{
	struct mbox_sync_mail_context new_mail_ctx;
	uoff_t offset, dest_offset;
	size_t need_space;

	if (mail_ctx == NULL) {
		if (mbox_sync_seek(sync_ctx, mails[idx].from_offset) < 0)
			return -1;

		if (mbox_sync_read_next(sync_ctx, &new_mail_ctx, mails, seq, idx,
					expunged_space) < 0)
			return -1;
		mail_ctx = &new_mail_ctx;
	} else {
		i_assert(seq == mail_ctx->seq);
		if (mail_ctx->mail.space < 0)
			mail_ctx->mail.space = 0;
		i_stream_seek(sync_ctx->input, mail_ctx->body_offset);
	}

	if (mail_ctx->mail.space <= 0) {
		need_space = str_len(mail_ctx->header) - mail_ctx->mail.space -
			(mail_ctx->body_offset - mail_ctx->hdr_offset);
		if (need_space != (uoff_t)-mails[idx].space) {
			/* this check works only if we're doing the first
			   write, or if the file size was changed externally */
			mbox_sync_file_update_ext_modified(sync_ctx);

			mbox_sync_set_critical(sync_ctx,
				"seq=%u uid=%u uid_broken=%d "
				"originally needed %"PRIuUOFF_T
				" bytes, now needs %"PRIuSIZE_T" bytes",
				seq, mails[idx].uid, mails[idx].uid_broken ? 1 : 0,
				(uoff_t)-mails[idx].space, need_space);
			return -1;
		}
	}

	if (first_nonexpunged && expunged_space > 0) {
		/* move From-line (after parsing headers so we don't
		   overwrite them) */
		i_assert(mails[idx].from_offset >= expunged_space);
		if (mbox_move(sync_ctx, mails[idx].from_offset - expunged_space,
			      mails[idx].from_offset,
			      mails[idx].offset - mails[idx].from_offset) < 0)
			return -1;
	}

	if (mails[idx].space == 0) {
		/* don't touch spacing */
	} else if (padding < (uoff_t)mail_ctx->mail.space) {
		mbox_sync_headers_remove_space(mail_ctx, mail_ctx->mail.space -
					       padding);
	} else {
		mbox_sync_headers_add_space(mail_ctx, padding -
					    mail_ctx->mail.space);
	}

	/* move the body of this message and headers of next message forward,
	   then write the headers */
	offset = sync_ctx->input->v_offset;
	dest_offset = offset + move_diff;
	i_assert(offset <= end_offset);
	if (mbox_move(sync_ctx, dest_offset, offset, end_offset - offset) < 0)
		return -1;

	/* the header may actually be moved backwards if there was expunged
	   space which we wanted to remove */
	i_assert(dest_offset >= str_len(mail_ctx->header));
	dest_offset -= str_len(mail_ctx->header);
	i_assert(dest_offset >= mails[idx].from_offset - expunged_space);
	if (pwrite_full(sync_ctx->write_fd, str_data(mail_ctx->header),
			str_len(mail_ctx->header), dest_offset) < 0) {
		mbox_set_syscall_error(sync_ctx->mbox, "pwrite_full()");
		return -1;
	}
	mbox_sync_file_updated(sync_ctx, TRUE);

	if (sync_ctx->dest_first_mail) {
		mbox_sync_first_mail_written(mail_ctx, dest_offset);
		sync_ctx->dest_first_mail = FALSE;
	}

	mails[idx].offset = dest_offset +
		(mail_ctx->mail.offset - mail_ctx->hdr_offset);
	mails[idx].space = mail_ctx->mail.space;
	return 0;
}

int mbox_sync_rewrite(struct mbox_sync_context *sync_ctx,
		      struct mbox_sync_mail_context *mail_ctx,
		      uoff_t end_offset, off_t move_diff, uoff_t extra_space,
		      uint32_t first_seq, uint32_t last_seq)
{
	struct mbox_sync_mail *mails;
	uoff_t offset, dest_offset, next_end_offset, next_move_diff;
	uoff_t start_offset, expunged_space;
	uint32_t idx, first_nonexpunged_idx, padding_per_mail;
	uint32_t orig_prev_msg_uid;
	unsigned int count;
	int ret = 0;

	i_assert(extra_space < OFF_T_MAX);
	i_assert(sync_ctx->mbox->mbox_lock_type == F_WRLCK);

	mails = array_get_modifiable(&sync_ctx->mails, &count);
	i_assert(count == last_seq - first_seq + 1);

	/* if there's expunges in mails[], we would get more correct balancing
	   by counting only them here. however, that might make us overwrite
	   data which hasn't yet been copied backwards. to avoid too much
	   complexity, we just leave all the rest of the extra space to first
	   mail */
	idx = last_seq - first_seq + 1;
	padding_per_mail = extra_space / idx;

	/* after expunge the next mail must have been missing space, or we
	   would have moved it backwards already */
	expunged_space = 0;
	start_offset = mails[0].from_offset;
	for (first_nonexpunged_idx = 0;; first_nonexpunged_idx++) {
		i_assert(first_nonexpunged_idx != idx);
		if (!mails[first_nonexpunged_idx].expunged)
			break;
                expunged_space += mails[first_nonexpunged_idx].space;
	}
	i_assert(mails[first_nonexpunged_idx].space < 0);

	orig_prev_msg_uid = sync_ctx->prev_msg_uid;

	/* start moving backwards. */
	while (idx > first_nonexpunged_idx) {
		idx--;
		if (idx == first_nonexpunged_idx) {
			/* give the rest of the extra space to first mail.
			   we might also have to move the mail backwards to
			   fill the expunged space */
			padding_per_mail = move_diff + expunged_space +
				mails[idx].space;
		}

		next_end_offset = mails[idx].offset;

		if (mails[idx].space <= 0 && !mails[idx].expunged) {
			/* give space to this mail. end_offset is left to
			   contain this message's From-line (ie. below we
			   move only headers + body). */
			bool first_nonexpunged = idx == first_nonexpunged_idx;

			next_move_diff = -mails[idx].space;
			if (mbox_sync_read_and_move(sync_ctx, mail_ctx, mails,
						    first_seq + idx, idx,
						    padding_per_mail,
						    move_diff, expunged_space,
						    end_offset,
						    first_nonexpunged) < 0) {
				ret = -1;
				break;
			}
			move_diff -= next_move_diff + mails[idx].space;
		} else {
			/* this mail provides more space. just move it forward
			   from the extra space offset and set end_offset to
			   point to beginning of extra space. that way the
			   header will be moved along with previous mail's
			   body.

			   if this is expunged mail, we're moving following
			   mail's From-line and maybe headers. */
			offset = mails[idx].offset + mails[idx].space;
			dest_offset = offset + move_diff;
			i_assert(offset <= end_offset);
			if (mbox_move(sync_ctx, dest_offset, offset,
				      end_offset - offset) < 0) {
				ret = -1;
				break;
			}

			move_diff += mails[idx].space;
			if (!mails[idx].expunged) {
				move_diff -= padding_per_mail;
				mails[idx].space = padding_per_mail;

				if (mbox_fill_space(sync_ctx, move_diff +
						    mails[idx].offset,
						    padding_per_mail) < 0) {
					ret = -1;
					break;
				}
			}
			mails[idx].offset += move_diff;
		}
		mail_ctx = NULL;

		i_assert(move_diff >= 0 || idx == first_nonexpunged_idx);
		i_assert(next_end_offset <= end_offset);

		end_offset = next_end_offset;
		mails[idx].from_offset += move_diff;
	}

	if (ret == 0) {
		i_assert(mails[idx].from_offset == start_offset);
		i_assert(move_diff + (off_t)expunged_space >= 0);
	}

	mbox_sync_file_updated(sync_ctx, FALSE);
	sync_ctx->prev_msg_uid = orig_prev_msg_uid;
	return ret;
}
