/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "hex-binary.h"
#include "md5.h"
#include "mbox-index.h"
#include "mail-index-util.h"
#include "mail-cache.h"

static int mbox_index_append_next(struct mail_index *index,
				  struct mail_cache_transaction_ctx *trans_ctx,
				  struct istream *input)
{
	struct mail_index_record *rec;
	struct mbox_header_context ctx;
	struct istream *hdr_stream;
	enum mail_index_record_flag index_flags;
	time_t received_date;
	uoff_t hdr_offset, body_offset, end_offset;
	const unsigned char *data;
	unsigned char md5_digest[16];
	size_t size, pos;
	int dirty, save_md5 = FALSE;

	/* get the From-line */
	pos = 0;
	while (i_stream_read_data(input, &data, &size, pos) > 0) {
		for (; pos < size; pos++) {
			if (data[pos] == '\n')
				break;
		}

		if (pos < size)
			break;
	}

	if (size == 0)
		return -1;

	if (pos == size || size <= 5 || memcmp(data, "From ", 5) != 0) {
		/* a) no \n found, or line too long
		   b) not a From-line */
		index_set_error(index, "Error indexing mbox file %s: "
				"From-line not found where expected",
				index->mailbox_path);
		index->set_flags |= MAIL_INDEX_HDR_FLAG_FSCK;
		return -1;
	}

	/* parse the From-line */
	received_date = mbox_from_parse_date(data + 5, size - 5);
	if (received_date == (time_t)-1)
		received_date = ioloop_time;

	i_stream_skip(input, pos+1);
	hdr_offset = input->v_offset;

	/* now, find the end of header. also stops at "\nFrom " if it's
	   found (broken messages) */
	mbox_skip_header(input);
	body_offset = input->v_offset;

	index_flags = 0;

	/* parse the header and cache wanted fields. get the message flags
	   from Status and X-Status fields. temporarily limit the stream length
	   so the message body is parsed properly.

	   the stream length limit is raised again by mbox_header_cb after
	   reading the headers. it uses Content-Length if available or finds
	   the next From-line. */
	mbox_header_init_context(&ctx, index, input);

	hdr_stream = i_stream_create_limit(default_pool, input,
					   hdr_offset,
					   body_offset - hdr_offset);
	i_stream_seek(hdr_stream, 0);
	message_parse_header(NULL, hdr_stream, NULL, mbox_header_cb, &ctx);
	i_stream_unref(hdr_stream);

	dirty = FALSE;

	/* try Content-Length */
	end_offset = body_offset + ctx.content_length;
	if (ctx.content_length == (uoff_t)-1 ||
	    !mbox_verify_end_of_body(input, end_offset)) {
		/* failed, search for From-line */
		if (ctx.content_length != (uoff_t)-1) {
			/* broken, rewrite it */
			dirty = TRUE;
		}

		i_stream_seek(input, body_offset);
		mbox_skip_message(input);
		ctx.content_length = input->v_offset - body_offset;
	}

	if (index->header->messages_count == 0 &&
	    ctx.uid_validity != index->header->uid_validity) {
		/* UID validity is different */
		if (ctx.uid_validity != 0) {
			/* change it in index */
			index->header->uid_validity = ctx.uid_validity;
			index->header->next_uid = 1;
			index->header->last_nonrecent_uid = 0;
			index->inconsistent = TRUE;
		} else if (!index->mailbox_readonly) {
			/* we have to write it to mbox */
			if (index->mbox_lock_type != MAIL_LOCK_EXCLUSIVE) {
				/* try again */
				return 0;
			}

			dirty = TRUE;
		}
	}

	if (ctx.uid >= index->header->next_uid) {
		/* X-UID header looks ok */
		index->header->next_uid = ctx.uid;
	} else if (!index->mailbox_readonly) {
		/* Write X-UID for it */
		dirty = TRUE;
	} else {
		/* save MD5 */
                save_md5 = TRUE;
	}

	if (dirty && !index->mailbox_readonly) {
		if (index->mbox_lock_type != MAIL_LOCK_EXCLUSIVE) {
			/* try again */
			return 0;
		}

		index->header->flags |= MAIL_INDEX_HDR_FLAG_DIRTY_MESSAGES;
		index_flags |= MAIL_INDEX_FLAG_DIRTY;
	}

	/* add message to index */
	rec = index->append(index);
	if (rec == NULL)
		return -1;

	/* save message flags */
	rec->msg_flags = ctx.flags;
	mail_index_mark_flag_changes(index, rec, 0, rec->msg_flags);

	if (!mail_cache_add(trans_ctx, rec, MAIL_CACHE_INDEX_FLAGS,
			    &index_flags, sizeof(index_flags)))
		return -1;

	/* location offset = beginning of headers in message */
	if (!mail_cache_add(trans_ctx, rec, MAIL_CACHE_LOCATION_OFFSET,
			    &hdr_offset, sizeof(hdr_offset)))
		return -1;

	if (!mail_cache_add(trans_ctx, rec, MAIL_CACHE_RECEIVED_DATE,
			    &received_date, sizeof(received_date)))
		return -1;

	if (!mail_cache_add(trans_ctx, rec, MAIL_CACHE_PHYSICAL_BODY_SIZE,
			    &ctx.content_length, sizeof(ctx.content_length)))
		return -1;

	if (save_md5) {
		md5_final(&ctx.md5, md5_digest);

		if (!mail_cache_add(trans_ctx, rec, MAIL_CACHE_MD5,
				    md5_digest, sizeof(md5_digest)))
			return -1;
	}

	return 1;
}

int mbox_index_append_stream(struct mail_index *index, struct istream *input)
{
	struct mail_cache_transaction_ctx *trans_ctx;
	uoff_t offset;
	int ret;

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	if (mail_cache_transaction_begin(index->cache, TRUE, &trans_ctx) <= 0)
		return FALSE;

	do {
		offset = input->v_offset;
		if (input->v_offset != 0) {
			/* we're at the [\r]\n before the From-line,
			   skip it */
			if (!mbox_skip_crlf(input)) {
				index_set_error(index,
						"Error indexing mbox file %s: "
						"LF not found where expected",
						index->mailbox_path);

				index->set_flags |= MAIL_INDEX_HDR_FLAG_FSCK;
				ret = -1;
				break;
			}
		}

		if (input->eof) {
			ret = 1;
			break;
		}

		t_push();
		ret = mbox_index_append_next(index, trans_ctx, input);
		t_pop();

		if (ret == 0) {
			/* we want to rescan this message with exclusive
			   locking */
			i_stream_seek(input, offset);
		}
	} while (ret > 0);

	if (ret >= 0 && index->mbox_lock_type == MAIL_LOCK_EXCLUSIVE) {
		/* Write missing X-IMAPbase and new/changed X-UID headers */
		if (!mbox_index_rewrite(index))
			ret = -1;
	}

	if (ret >= 0) {
		if (!mail_cache_transaction_commit(trans_ctx))
			ret = -1;
	}
	if (!mail_cache_transaction_end(trans_ctx))
		ret = -1;

	return ret >= 0;
}
