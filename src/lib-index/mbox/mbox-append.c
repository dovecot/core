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
	int failed;

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
		return FALSE;
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
		return FALSE;

	update = index->update_begin(index, rec);

	index->update_field_raw(update, DATA_HDR_INTERNAL_DATE,
				&internal_date, sizeof(internal_date));

	/* location = offset to beginning of headers in message */
	index->update_field_raw(update, DATA_FIELD_LOCATION,
				&abs_start_offset, sizeof(uoff_t));

	/* parse the header and cache wanted fields. get the message flags
	   from Status and X-Status fields. temporarily limit the stream length
	   so the message body is parsed properly.

	   the stream length limit is raised again by mbox_header_func after
	   reading the headers. it uses Content-Length if available or finds
	   the next From-line. */
	mbox_header_init_context(&ctx, index, input);
        ctx.set_read_limit = TRUE;

	i_stream_seek(input, abs_start_offset - input->start_offset);

	i_stream_set_read_limit(input, eoh_offset);
	mail_index_update_headers(update, input, 0, mbox_header_func, &ctx);

	i_stream_seek(input, input->v_limit);
	i_stream_set_read_limit(input, 0);

	/* save MD5 */
	md5_final(&ctx.md5, md5_digest);
	index->update_field_raw(update, DATA_FIELD_MD5,
				md5_digest, sizeof(md5_digest));

	if (!index->update_end(update))
		failed = TRUE;
	else {
		/* save message flags */
		rec->msg_flags = ctx.flags;
		mail_index_mark_flag_changes(index, rec, 0, rec->msg_flags);
		failed = FALSE;

		if (!index->append_end(index, rec))
			failed = TRUE;
	}

	mbox_header_free_context(&ctx);

	return !failed;
}

int mbox_index_append(struct mail_index *index, struct istream *input)
{
	int ret;

	if (input->v_offset == input->v_size) {
		/* no new data */
		return TRUE;
	}

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	for (;;) {
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

		if (input->v_offset == input->v_size)
			break;

		t_push();
		ret = mbox_index_append_next(index, input);
		t_pop();

		if (!ret)
			return FALSE;
	}

	return TRUE;
}
