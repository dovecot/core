/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "hex-binary.h"
#include "md5.h"
#include "mbox-index.h"
#include "mail-index-util.h"

static int mbox_index_append_next(struct mail_index *index,
				  struct istream *input)
{
	struct mail_index_record *rec;
	struct mail_index_update *update;
        struct mbox_header_context ctx;
	time_t internal_date;
	uoff_t abs_start_offset, eoh_offset;
	const unsigned char *data;
	unsigned char md5_digest[16];
	size_t size, pos;
	int ret, dirty;

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

	if (pos == size || size <= 5 ||
	    strncmp((const char *) data, "From ", 5) != 0) {
		/* a) no \n found, or line too long
		   b) not a From-line */
		index_set_error(index, "Error indexing mbox file %s: "
				"From-line not found where expected",
				index->mailbox_path);
		index->set_flags |= MAIL_INDEX_FLAG_FSCK;
		return -1;
	}

	/* parse the From-line */
	internal_date = mbox_from_parse_date(data + 5, size - 5);
	if (internal_date == (time_t)-1)
		internal_date = ioloop_time;

	i_stream_skip(input, pos+1);
	abs_start_offset = input->start_offset + input->v_offset;

	/* now, find the end of header. also stops at "\nFrom " if it's
	   found (broken messages) */
	mbox_skip_header(input);
	eoh_offset = input->v_offset;

	/* add message to index */
	rec = index->append_begin(index);
	if (rec == NULL)
		return -1;

	update = index->update_begin(index, rec);

	index->update_field_raw(update, DATA_HDR_INTERNAL_DATE,
				&internal_date, sizeof(internal_date));

	/* location = offset to beginning of headers in message */
	index->update_field_raw(update, DATA_FIELD_LOCATION,
				&abs_start_offset, sizeof(uoff_t));

	/* parse the header and cache wanted fields. get the message flags
	   from Status and X-Status fields. temporarily limit the stream length
	   so the message body is parsed properly.

	   the stream length limit is raised again by mbox_header_cb after
	   reading the headers. it uses Content-Length if available or finds
	   the next From-line. */
	mbox_header_init_context(&ctx, index, input);
        ctx.set_read_limit = TRUE;

	i_stream_seek(input, abs_start_offset - input->start_offset);

	i_stream_set_read_limit(input, eoh_offset);
	mail_index_update_headers(update, input, 0, mbox_header_cb, &ctx);

	i_stream_seek(input, input->v_limit);
	i_stream_set_read_limit(input, 0);

	ret = 1;
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
				ret = 0;
			} else {
				index->header->flags |=
					MAIL_INDEX_FLAG_DIRTY_MESSAGES;
				rec->index_flags |= INDEX_MAIL_FLAG_DIRTY;
			}
		}
	}

	if (ctx.uid >= index->header->next_uid) {
		/* X-UID header looks ok */
		if (ret != 0)
			index->header->next_uid = ctx.uid;
		dirty = ctx.content_length_broken;
	} else if (!index->mailbox_readonly) {
		/* Write X-UID for it */
		dirty = TRUE;
	} else {
		/* save MD5 */
		md5_final(&ctx.md5, md5_digest);
		index->update_field_raw(update, DATA_FIELD_MD5,
					md5_digest, sizeof(md5_digest));
		dirty = FALSE;
	}

	if (dirty && !index->mailbox_readonly) {
		if (index->mbox_lock_type != MAIL_LOCK_EXCLUSIVE) {
			/* try again */
			ret = 0;
		} else {
			index->header->flags |= MAIL_INDEX_FLAG_DIRTY_MESSAGES;
			rec->index_flags |= INDEX_MAIL_FLAG_DIRTY;
		}
	}

	if (ret <= 0) {
		index->update_abort(update);
		index->append_abort(index, rec);
	} else {
		if (!index->update_end(update)) {
			index->append_abort(index, rec);
			ret = -1;
		} else {
			/* save message flags */
			rec->msg_flags = ctx.flags;
			mail_index_mark_flag_changes(index, rec, 0,
						     rec->msg_flags);
			ret = 1;

			if (!index->append_end(index, rec))
				ret = -1;
		}
	}

	mbox_header_free_context(&ctx);
	return ret;
}

int mbox_index_append(struct mail_index *index, struct istream *input)
{
	uoff_t offset;
	int ret;

	if (input->v_offset == input->v_size) {
		/* no new data */
		return TRUE;
	}

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	do {
		offset = input->v_offset;
		if (input->start_offset + input->v_offset != 0) {
			/* we're at the [\r]\n before the From-line,
			   skip it */
			if (!mbox_skip_crlf(input)) {
				index_set_error(index,
						"Error indexing mbox file %s: "
						"LF not found where expected",
						index->mailbox_path);

				index->set_flags |= MAIL_INDEX_FLAG_FSCK;
				return FALSE;
			}
		}

		if (input->v_offset == input->v_size) {
			ret = 1;
			break;
		}

		t_push();
		ret = mbox_index_append_next(index, input);
		t_pop();

		if (ret == 0) {
			/* we want to rescan this message with exclusive
			   locking */
			i_stream_seek(input, offset);
		}
	} while (ret > 0);

	if (index->mbox_lock_type == MAIL_LOCK_EXCLUSIVE) {
		/* Write missing X-IMAPbase and new/changed X-UID headers */
		return mbox_index_rewrite(index);
	}

	return ret >= 0;
}
