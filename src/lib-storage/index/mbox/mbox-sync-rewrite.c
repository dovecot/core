#include "lib.h"
#include "buffer.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "write-full.h"
#include "message-parser.h"
#include "mbox-sync-private.h"
#include "istream-raw-mbox.h"

int mbox_move(struct mbox_sync_context *sync_ctx,
	      uoff_t dest, uoff_t source, uoff_t size)
{
	struct istream *input;
	struct ostream *output;
	off_t ret;

	output = o_stream_create_file(sync_ctx->fd, default_pool, 4096, FALSE);
	i_stream_seek(sync_ctx->file_input, source);
	o_stream_seek(output, dest);

	istream_raw_mbox_flush(sync_ctx->file_input);

	if (size == (uoff_t)-1) {
		input = sync_ctx->file_input;
		return o_stream_send_istream(output, input) < 0 ? -1 : 0;
	} else {
		input = i_stream_create_limit(default_pool,
					      sync_ctx->file_input,
					      source, size);
		ret = o_stream_send_istream(output, input);
		i_stream_unref(input);
		return ret == (off_t)size ? 0 : -1;
	}
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
	nonspace = pos;
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
		*size = 0;
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

	for (i = 0; i < 3 && size > 0; i++) {
		pos = space_positions[i];
		if (ctx->hdr_pos[pos] != (size_t)-1) {
			mbox_sync_header_remove_space(ctx, ctx->hdr_pos[pos],
						      &size);
		}
	}

	i_assert(size == 0);
}

int mbox_sync_try_rewrite(struct mbox_sync_mail_context *ctx)
{
	size_t old_hdr_size, new_hdr_size;
	const unsigned char *data;

	old_hdr_size = ctx->body_offset - ctx->hdr_offset;
	new_hdr_size = str_len(ctx->header);

	/* do we have enough space? */
	if (new_hdr_size < old_hdr_size) {
		mbox_sync_headers_add_space(ctx, old_hdr_size - new_hdr_size);
		ctx->mail->space += old_hdr_size - new_hdr_size;
	} else if (new_hdr_size > old_hdr_size) {
		size_t needed = new_hdr_size - old_hdr_size;
		if (ctx->mail->space < needed) {
			ctx->mail->space -= needed;
			return 0;
		}

		ctx->mail->space -= needed;
		mbox_sync_headers_remove_space(ctx, needed);
	}

	i_assert(ctx->header_first_change != (size_t)-1);

	if (ctx->header_last_change != (size_t)-1)
		str_truncate(ctx->header, ctx->header_last_change);

	data = str_data(ctx->header);
        new_hdr_size = str_len(ctx->header);
	if (pwrite_full(ctx->sync_ctx->fd, data + ctx->header_first_change,
			new_hdr_size,
			ctx->hdr_offset + ctx->header_first_change) < 0) {
		// FIXME: error handling
		return -1;
	}
	istream_raw_mbox_flush(ctx->sync_ctx->input);
	return 1;
}

int mbox_sync_rewrite(struct mbox_sync_context *sync_ctx, buffer_t *mails_buf,
		      uint32_t first_seq, uint32_t last_seq, off_t extra_space)
{
	struct mbox_sync_mail *mails;
	size_t size;
	uint32_t first_idx, last_idx, extra_per_mail;

	first_idx = first_seq-1;
	last_idx = last_seq-1;

	mails = buffer_get_modifyable_data(mails_buf, &size);
	size /= sizeof(*mails);

	/* FIXME: see if we can be faster by going back a few mails
	   (update first_seq and last_seq) */
	/*while (mails[last_idx].space > 0) {
	}*/

#if 0
	/* start moving backwards */
	extra_per_mail = (extra_space / (last_seq - first_seq + 1)) + 1;
	space_diff = 0;
	while (last_seq > first_seq) {
		dest = mails[last_seq].space_offset + mails[last_seq].space
	}
#endif
}
