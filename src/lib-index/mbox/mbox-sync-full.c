/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "hex-binary.h"
#include "message-parser.h"
#include "message-part-serialize.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"

#include <unistd.h>
#include <fcntl.h>

static void skip_line(IBuffer *inbuf)
{
	const unsigned char *msg;
	size_t i, size;

	while (i_buffer_read_data(inbuf, &msg, &size, 0) > 0) {
		for (i = 0; i < size; i++) {
			if (msg[i] == '\n') {
				i_buffer_skip(inbuf, i+1);
				return;
			}
		}

		i_buffer_skip(inbuf, i);
	}
}

static int verify_header_md5sum(MailIndex *index, MailIndexRecord *rec,
				unsigned char current_digest[16])
{
	const unsigned char *old_digest;
	size_t size;

	/* MD5 sums must match */
	old_digest = index->lookup_field_raw(index, rec, FIELD_TYPE_MD5, &size);
	return old_digest != NULL && size >= 16 &&
                memcmp(old_digest, current_digest, 16) == 0;
}

static int mail_update_header_size(MailIndex *index, MailIndexRecord *rec,
				   MailIndexUpdate *update,
				   MessageSize *hdr_size)
{
	const void *part_data;
	void *part_data_copy;
	size_t size;

	/* update index record */
	rec->header_size = hdr_size->physical_size;

	if ((rec->cached_fields & FIELD_TYPE_MESSAGEPART) == 0)
		return TRUE;

	/* update FIELD_TYPE_MESSAGEPART */
	part_data = index->lookup_field_raw(index, rec, FIELD_TYPE_MESSAGEPART,
					    &size);
	if (part_data == NULL) {
		/* well, this wasn't expected but don't bother failing */
		return TRUE;
	}

	t_push();

	/* copy & update the part data */
	part_data_copy = t_malloc(size);
	memcpy(part_data_copy, part_data, size);

	if (!message_part_serialize_update_header(part_data_copy, size,
						  hdr_size)) {
		t_pop();
		return FALSE;
	}

	t_pop();

	index->update_field_raw(update, FIELD_TYPE_MESSAGEPART,
				part_data_copy, size);
	return TRUE;
}

static int match_next_record(MailIndex *index, MailIndexRecord *rec,
			     unsigned int seq, IBuffer *inbuf,
			     MailIndexRecord **next_rec, int *dirty)
{
        MailIndexUpdate *update;
	MessageSize hdr_size;
	MboxHeaderContext ctx;
	uoff_t header_offset, body_offset, offset;
	unsigned char current_digest[16];

	*next_rec = NULL;

	/* skip the From-line */
	skip_line(inbuf);

	header_offset = inbuf->v_offset;

	if (rec->body_size == 0) {
		/* possibly broken message, find the next From-line and make
		   sure header parser won't pass it. */
		mbox_skip_header(inbuf);
		i_buffer_set_read_limit(inbuf, inbuf->v_offset);
		i_buffer_seek(inbuf, header_offset);
	}

	/* get the MD5 sum of fixed headers and the current message flags
	   in Status and X-Status fields */
        mbox_header_init_context(&ctx, index, inbuf);
	message_parse_header(NULL, inbuf, &hdr_size, mbox_header_func, &ctx);
	md5_final(&ctx.md5, current_digest);

	mbox_header_free_context(&ctx);
	i_buffer_set_read_limit(inbuf, 0);

	body_offset = inbuf->v_offset;
	do {
		if (verify_header_md5sum(index, rec, current_digest) &&
		    mbox_verify_end_of_body(inbuf,
					    body_offset + rec->body_size)) {
			/* valid message */
			update = index->update_begin(index, rec);

			/* update flags, unless we've changed them */
			if ((rec->index_flags & INDEX_MAIL_FLAG_DIRTY) == 0) {
				if (!index->update_flags(index, rec, seq,
							 ctx.flags, TRUE))
					return FALSE;

				/* update_flags() sets dirty flag, remove it */
				rec->index_flags &= ~INDEX_MAIL_FLAG_DIRTY;
			} else {
				if (rec->msg_flags != ctx.flags)
					*dirty = TRUE;
			}

			/* update location */
			if (!mbox_mail_get_start_offset(index, rec, &offset))
				return FALSE;
			if (offset != header_offset) {
				index->update_field_raw(update,
							FIELD_TYPE_LOCATION,
							&header_offset,
							sizeof(uoff_t));
			}

			/* update size */
			if (rec->header_size != hdr_size.physical_size ) {
				if (!mail_update_header_size(index, rec,
							     update, &hdr_size))
					return FALSE;
			}

			if (!index->update_end(update))
				return FALSE;

			*next_rec = rec;
			break;
		}

		/* try next message */
		(void)index->expunge(index, rec, seq, TRUE);
		rec = index->next(index, rec);
	} while (rec != NULL);

	return TRUE;
}

static int mbox_sync_buf(MailIndex *index, IBuffer *inbuf)
{
	MailIndexRecord *rec;
	uoff_t from_offset;
	const unsigned char *data;
	size_t size;
	unsigned int seq;
	int dirty;

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	mbox_skip_empty_lines(inbuf);

	/* first make sure we start with a "From " line. If file is too
	   small, we'll just treat it as empty mbox file. */
	if (i_buffer_read_data(inbuf, &data, &size, 5) > 0 &&
	    strncmp((const char *) data, "From ", 5) != 0) {
		index_set_error(index, "File isn't in mbox format: %s",
				index->mbox_path);
		return FALSE;
	}

	/* we'll go through the mailbox and index in order matching the
	   messages by their size and Message-ID. old mails aren't remembered,
	   so we handle well only the cases when mail has been deleted. if
	   mails have been reordered (eg. sorted by someone) most of the mails
	   will show up as being new. if we really wanted to support that well,
	   we could save the message-ids into hash but I don't know if it's
	   worth the trouble. */

	seq = 1;
	rec = index->lookup(index, 1);

	dirty = FALSE;
	while (rec != NULL) {
		from_offset = inbuf->v_offset;
		if (inbuf->v_offset != 0) {
			/* we're at the [\r]\n before the From-line,
			   skip it */
			if (!mbox_skip_crlf(inbuf)) {
				/* they just went and broke it, even while
				   we had it locked. */
				return FALSE;
			}
		}

		if (inbuf->v_offset == inbuf->v_size)
			break;

		if (!match_next_record(index, rec, seq, inbuf, &rec, &dirty))
			return FALSE;

		if (rec == NULL) {
			/* Get back to line before From */
			i_buffer_seek(inbuf, from_offset);
			break;
		}

		seq++;
		rec = index->next(index, rec);
	}

	/* delete the rest of the records */
	while (rec != NULL) {
		(void)index->expunge(index, rec, seq, TRUE);

		rec = index->next(index, rec);
	}

	if (!dirty && (index->header->flags & MAIL_INDEX_FLAG_DIRTY_MESSAGES)) {
		/* no flags were dirty anymore, no need to rewrite */
		index->header->flags &= ~MAIL_INDEX_FLAG_DIRTY_MESSAGES;
	}

	if (inbuf->v_offset == inbuf->v_size)
		return TRUE;
	else
		return mbox_index_append(index, inbuf);
}

int mbox_sync_full(MailIndex *index)
{
	IBuffer *inbuf;
	int failed, unlock;

	unlock = index->mbox_lock_type == MAIL_LOCK_UNLOCK;
	inbuf = mbox_get_inbuf(index, 0, MAIL_LOCK_SHARED);
	if (inbuf == NULL)
		return FALSE;

	failed = !mbox_sync_buf(index, inbuf);
	i_buffer_unref(inbuf);

	if (unlock)
		(void)mbox_unlock(index);

	return !failed;
}
