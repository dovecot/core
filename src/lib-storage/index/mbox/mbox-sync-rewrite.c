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

	o_stream_unref(output);
	return (int)ret;
}

static void mbox_sync_headers_add_space(struct mbox_sync_mail_context *ctx,
					size_t size)
{
	size_t data_size, pos;
	const unsigned char *data;
	void *p;

	/* Append at the end of X-Keywords header,
	   or X-UID if it doesn't exist */
	pos = ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] != (size_t)-1 ?
		ctx->hdr_pos[MBOX_HDR_X_KEYWORDS] :
		ctx->hdr_pos[MBOX_HDR_X_UID];

	data = buffer_get_data(ctx->header, &data_size);
	while (pos < data_size && data[pos] != '\n')
		pos++;

	buffer_copy(ctx->header, pos + size,
		    ctx->header, pos, (size_t)-1);
	p = buffer_get_space_unsafe(ctx->header, pos, size);
	memset(p, ' ', size);

	ctx->mail.offset = ctx->hdr_offset + pos;
	if (ctx->mail.space < 0)
		ctx->mail.space = size;
	else
		ctx->mail.space += size;

	if (ctx->header_first_change > pos)
		ctx->header_first_change = pos;
	ctx->header_last_change = (size_t)-1;
}

static void mbox_sync_header_remove_space(struct mbox_sync_mail_context *ctx,
					  size_t pos, size_t *size)
{
	const unsigned char *data;
	size_t data_size, end, nonspace;

	/* find the end of the lwsp */
	nonspace = pos-1;
	data = str_data(ctx->header);
	data_size = str_len(ctx->header);
	for (end = pos; end < data_size; end++) {
		if (data[end] == '\n') {
			if (end+1 == data_size || !IS_LWSP(data[end+1]))
				break;
		} else {
			if (!IS_LWSP(data[end]))
				nonspace = end;
		}
	}

	/* and remove what we can */
	nonspace++;
	if (end-nonspace < *size) {
		str_delete(ctx->header, nonspace, end-nonspace);
		*size -= end-nonspace;
	} else {
		str_delete(ctx->header, nonspace, *size);
		end -= *size;
		*size = 0;

		if (ctx->mail.space < end-nonspace) {
			ctx->mail.space = end-nonspace;
			ctx->mail.offset = ctx->hdr_offset + nonspace;
		}
	}
}

static void mbox_sync_headers_remove_space(struct mbox_sync_mail_context *ctx,
					   size_t size)
{
	static enum header_position space_positions[] = {
                MBOX_HDR_X_KEYWORDS,
                MBOX_HDR_X_UID,
                MBOX_HDR_X_IMAPBASE
	};
        enum header_position pos;
	int i;

	ctx->header_last_change = (size_t)-1;

	ctx->mail.space = 0;
	ctx->mail.offset = ctx->hdr_offset;

	for (i = 0; i < 3 && size > 0; i++) {
		pos = space_positions[i];
		if (ctx->hdr_pos[pos] != (size_t)-1) {
			if (ctx->header_first_change > ctx->hdr_pos[pos])
                                ctx->header_first_change = ctx->hdr_pos[pos];
			mbox_sync_header_remove_space(ctx, ctx->hdr_pos[pos],
						      &size);
		}
	}

	i_assert(size == 0);
}

int mbox_sync_try_rewrite(struct mbox_sync_mail_context *ctx, off_t move_diff)
{
	size_t old_hdr_size, new_hdr_size;
	const unsigned char *data;

	i_assert(ctx->sync_ctx->ibox->mbox_lock_type == F_WRLCK);

	old_hdr_size = ctx->body_offset - ctx->hdr_offset;
	new_hdr_size = str_len(ctx->header);

	/* do we have enough space? */
	if (new_hdr_size < old_hdr_size) {
		mbox_sync_headers_add_space(ctx, old_hdr_size - new_hdr_size);
	} else if (new_hdr_size > old_hdr_size) {
		size_t needed = new_hdr_size - old_hdr_size;

		if (ctx->mail.space >= 0)
			mbox_sync_headers_remove_space(ctx, needed);
		else if (move_diff < 0 && needed <= -move_diff) {
			/* moving backwards - we can use the extra space from
			   it, just update expunged_space accordingly */
			i_assert(ctx->sync_ctx->expunged_space >= needed);
			ctx->sync_ctx->expunged_space -= needed;
		} else {
			return 0;
		}
	}

	i_assert(ctx->header_first_change != (size_t)-1 || move_diff != 0);

	if (move_diff != 0) {
		/* we're moving the header, forget about partial write
		   optimizations */
		ctx->header_first_change = 0;
		ctx->header_last_change = 0;
	}

	/* FIXME: last_change should rather just tell if we want to truncate
	   to beginning of extra whitespace */
	if (ctx->header_last_change != (size_t)-1 &&
	    ctx->header_last_change != 0)
		str_truncate(ctx->header, ctx->header_last_change);

	data = str_data(ctx->header);
	new_hdr_size = str_len(ctx->header);
	if (pwrite_full(ctx->sync_ctx->fd, data + ctx->header_first_change,
			new_hdr_size - ctx->header_first_change,
			ctx->hdr_offset + move_diff +
			ctx->header_first_change) < 0) {
		// FIXME: error handling
		return -1;
	}
	istream_raw_mbox_flush(ctx->sync_ctx->input);
	return 1;
}

static int mbox_sync_read_and_move(struct mbox_sync_context *sync_ctx,
				   struct mbox_sync_mail *mails,
				   uint32_t seq, uint32_t idx,
				   uint32_t extra_per_mail,
				   uoff_t *end_offset)
{
	struct mbox_sync_mail_context mail_ctx;
	uint32_t old_prev_msg_uid;
	uoff_t offset;

	i_stream_seek(sync_ctx->file_input, mails[idx].offset);

	memset(&mail_ctx, 0, sizeof(mail_ctx));
	mail_ctx.sync_ctx = sync_ctx;
	mail_ctx.seq = seq;
	mail_ctx.header = sync_ctx->header;

	mail_ctx.mail.offset = mails[idx].offset;
	mail_ctx.mail.body_size = mails[idx].body_size;

	/* mbox_sync_parse_next_mail() checks that UIDs are growing,
	   so we have to fool it. */
        old_prev_msg_uid = sync_ctx->prev_msg_uid;
        sync_ctx->prev_msg_uid = mails[idx].uid-1;

	mbox_sync_parse_next_mail(sync_ctx->file_input, &mail_ctx, TRUE);
	if (mails[idx].space != 0)
		mbox_sync_update_header_from(&mail_ctx, &mails[idx]);
	else {
		/* updating might just try to add headers and mess up our
		   calculations completely. so only add the EOH here. */
		if (mail_ctx.have_eoh)
			str_append_c(mail_ctx.header, '\n');
	}

	i_assert(mail_ctx.mail.space == mails[idx].space);
        sync_ctx->prev_msg_uid = old_prev_msg_uid;

	if (mail_ctx.mail.space <= 0)
		mbox_sync_headers_add_space(&mail_ctx, extra_per_mail);
	else if (mail_ctx.mail.space <= extra_per_mail) {
		mbox_sync_headers_add_space(&mail_ctx, extra_per_mail -
					    mail_ctx.mail.space);
	} else {
		mbox_sync_headers_remove_space(&mail_ctx, mail_ctx.mail.space -
					       extra_per_mail);
	}

	/* now we have to move it. first move the body of the message,
	   then write the header and leave the extra space to beginning of
	   headers. */
	offset = sync_ctx->file_input->v_offset;
	if (mbox_move(sync_ctx, offset + mails[idx+1].space, offset,
		      *end_offset - offset - mails[idx+1].space) < 0) {
		// FIXME: error handling
		return -1;
	}
	mails[idx+1].from_offset += mails[idx+1].space;

	*end_offset = offset + mails[idx+1].space - str_len(mail_ctx.header);

	if (pwrite_full(sync_ctx->fd, str_data(mail_ctx.header),
			str_len(mail_ctx.header), *end_offset) < 0) {
		// FIXME: error handling
		return -1;
	}

	mails[idx].offset = *end_offset;
	mails[idx].space += mails[idx+1].space - extra_per_mail;
	return 0;
}

static int mbox_sync_fill_leftover(struct mbox_sync_context *sync_ctx,
				   struct mbox_sync_mail *mails,
				   uint32_t seq, uint32_t idx,
				   uoff_t start_offset, uoff_t end_offset)
{
	struct mbox_sync_mail_context mail_ctx;
	uint32_t old_prev_msg_uid;

	i_stream_seek(sync_ctx->file_input, mails[idx].offset);

	memset(&mail_ctx, 0, sizeof(mail_ctx));
	mail_ctx.sync_ctx = sync_ctx;
	mail_ctx.seq = seq;
	mail_ctx.header = sync_ctx->header;

	mail_ctx.mail.offset = mails[idx].offset;
	mail_ctx.mail.body_size = mails[idx].body_size;

	/* mbox_sync_parse_next_mail() checks that UIDs are growing,
	   so we have to fool it. */
        old_prev_msg_uid = sync_ctx->prev_msg_uid;
        sync_ctx->prev_msg_uid = mails[idx].uid-1;

	mbox_sync_parse_next_mail(sync_ctx->file_input, &mail_ctx, TRUE);
	mbox_sync_update_header_from(&mail_ctx, &mails[idx]);

        sync_ctx->prev_msg_uid = old_prev_msg_uid;

	mbox_sync_headers_add_space(&mail_ctx, end_offset - start_offset);

	if (pwrite_full(sync_ctx->fd, str_data(mail_ctx.header),
			str_len(mail_ctx.header), start_offset) < 0) {
		// FIXME: error handling
		return -1;
	}

	mails[idx].offset = start_offset;
	return 0;
}

int mbox_sync_rewrite(struct mbox_sync_context *sync_ctx, buffer_t *mails_buf,
		      uint32_t first_seq, uint32_t last_seq, off_t extra_space)
{
	struct mbox_sync_mail *mails;
	size_t size;
	uoff_t offset, start_offset, end_offset, dest_offset;
	uint32_t idx, extra_per_mail;
	int ret = 0;

	i_assert(first_seq != last_seq);
	i_assert(sync_ctx->ibox->mbox_lock_type == F_WRLCK);

	mails = buffer_get_modifyable_data(mails_buf, &size);
	i_assert(size / sizeof(*mails) == last_seq - first_seq + 1);

	/* if there's expunges in mails[], we would get more correct balancing
	   by counting only them here. however, that might make us overwrite
	   data which hasn't yet been copied backwards. to avoid too much
	   complexity, we just leave all the rest of the extra space to first
	   mail */
	extra_per_mail = extra_space / (last_seq - first_seq + 1);
	idx = last_seq - first_seq;

	if (mails[idx].uid != 0)
		mails[idx].space -= extra_per_mail;
	i_assert(mails[idx].space >= 0);
	end_offset = mails[idx].offset + mails[idx].space;

	i_assert(mails[0].space < 0 || mails[0].uid == 0);
	start_offset = mails[0].offset;

	/* after expunge the next mail must have been missing space, or we
	   would have moved it backwards already */
	i_assert(mails[0].uid != 0 || mails[1].space < 0);

	/* start moving backwards */
	do {
		idx--;
		if (mails[idx].space <= 0 && mails[idx].uid != 0) {
			/* offset points to beginning of headers. read the
			   header again, update it and give enough space to
			   it */
			if (mbox_sync_read_and_move(sync_ctx, mails,
						    first_seq + idx, idx,
						    extra_per_mail,
						    &end_offset) < 0) {
				ret = -1;
				break;
			}
		} else {
			/* X-Keywords: xx [offset]     \n
			   ...
			   X-Keywords: xx    [end_offset] \n

			   move data forward so mails before us gets the extra
			   space (ie. we temporarily get more space to us) */
			offset = mails[idx].offset + mails[idx].space;
			dest_offset = offset + mails[idx+1].space;
			if (mbox_move(sync_ctx, dest_offset, offset,
				      end_offset - dest_offset) < 0) {
				// FIXME: error handling
				ret = -1;
				break;
			}

			mails[idx+1].from_offset += mails[idx+1].space;

			mails[idx].space += mails[idx+1].space;
			if (mails[idx].uid != 0)
				mails[idx].space -= extra_per_mail;
			i_assert(mails[idx].space > 0);
			end_offset = mails[idx].offset + mails[idx].space;
		}
	} while (idx > 0);

	if (end_offset != start_offset) {
		/* some space was left over - give it to first message. */
		if (mails[0].uid == 0) {
			/* "body" start_offset .. end_offset "\nFrom .."
			   we need to move From-line to start_offset */
			offset = mails[1].offset;
			if (mbox_move(sync_ctx, start_offset, end_offset,
				      offset - end_offset) < 0) {
				// FIXME: error handling
				ret = -1;
			}
			mails[1].from_offset -= end_offset - start_offset;
			idx++;

			start_offset += offset - end_offset;
			end_offset = offset;
		} else {
			/* "\nFrom ..\n" start_offset .. end_offset "hdr.." */
		}

		/* now parse it again and give it more space */
		mails[idx].space = extra_per_mail;
		mails[idx+1].space = 0; /* from_offset doesn't move.. */
		if (mbox_sync_fill_leftover(sync_ctx, mails,
					    first_seq + idx, idx,
					    start_offset, end_offset) < 0)
			ret = -1;
	}

	istream_raw_mbox_flush(sync_ctx->input);
	return ret;
}
