/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "hex-binary.h"
#include "message-parser.h"
#include "mbox-index.h"
#include "mbox-lock.h"
#include "mail-index-util.h"

#include <unistd.h>
#include <fcntl.h>

static void skip_line(IOBuffer *inbuf)
{
	unsigned char *msg;
	unsigned int i, size;

	while (io_buffer_read_data(inbuf, &msg, &size, 0) >= 0) {
		for (i = 0; i < size; i++) {
			if (msg[i] == '\n')
				break;
		}

		if (i < size) {
			io_buffer_skip(inbuf, i+1);
			break;
		}

		io_buffer_skip(inbuf, i);
	}
}

static MailIndexRecord *
match_next_record(MailIndex *index, MailIndexRecord *rec, unsigned int *seq,
		  IOBuffer *inbuf)
{
	MessageSize hdr_size;
	MboxHeaderContext ctx;
	off_t body_offset;
	unsigned char *data, current_digest[16], old_digest[16];
	unsigned int size;
	const char *md5sum;

	/* skip the From-line */
	skip_line(inbuf);

	/* get the MD5 sum of fixed headers and the current message flags
	   in Status and X-Status fields */
        mbox_header_init_context(&ctx);
	message_parse_header(NULL, inbuf, &hdr_size, mbox_header_func, &ctx);
	md5_final(&ctx.md5, current_digest);

	body_offset = inbuf->offset;
	do {
		do {
			/* MD5 sums must match */
			md5sum = index->lookup_field(index, rec,
						     FIELD_TYPE_MD5);
			if (md5sum == NULL || strlen(md5sum) != 32 ||
			    hex_to_binary(md5sum, old_digest) <= 0)
				break;

			if (memcmp(old_digest, current_digest, 16) != 0)
				break;

			/* don't bother parsing the whole body, just make
			   sure it ends properly */
			io_buffer_seek(inbuf, body_offset + rec->body_size);

			if (inbuf->offset == inbuf->size) {
				/* last message */
			} else {
				/* read forward a bit */
				if (io_buffer_read_data(inbuf, &data,
							&size, 6) <= 0 ||
				    size < 7)
					break;

				if (data[0] == '\r')
					data++;
				if (strncmp(data, "\nFrom ", 6) != 0)
					break;
			}

			/* valid message, update flags */
			if ((rec->msg_flags & ctx.flags) != ctx.flags)
				rec->msg_flags |= ctx.flags;
			return rec;
		} while (0);

		/* try next message */
		(*seq)++;
		(void)index->expunge(index, rec, *seq, TRUE);
		rec = index->next(index, rec);
	} while (rec != NULL);

	return NULL;
}

static int mbox_index_fsck_buf(MailIndex *index, IOBuffer *inbuf)
{
	MailIndexRecord *rec;
	off_t from_offset;
	unsigned char *data;
	unsigned int seq, size;

	if (!index->set_lock(index, MAIL_LOCK_EXCLUSIVE))
		return FALSE;

	/* first make sure we start with a "From " line. */
	while (io_buffer_read_data(inbuf, &data, &size, 5) >= 0) {
		if (size > 5)
			break;
	}

	if (size <= 5 || strncmp(data, "From ", 5) != 0) {
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

	while (rec != NULL) {
		from_offset = inbuf->offset;
		if (inbuf->offset != 0) {
			/* we're at the [\r]\n before the From-line,
			   skip it */
			if (!mbox_skip_crlf(inbuf)) {
				/* they just went and broke it, even while
				   we had it locked. */
				return FALSE;
			}
		}

		if (inbuf->offset == inbuf->size)
			break;

		rec = match_next_record(index, rec, &seq, inbuf);
		if (rec == NULL) {
			/* Get back to line before From */
			io_buffer_seek(inbuf, from_offset);
			break;
		}

		seq++;
		rec = index->next(index, rec);
	}

	if (inbuf->offset == inbuf->size)
		return TRUE;
	else
		return mbox_index_append(index, inbuf);
}

int mbox_index_fsck(MailIndex *index)
{
	IOBuffer *inbuf;
	int fd, failed;

	/* open the mbox file. we don't really need to open it read-write,
	   but fcntl() locking requires it. */
	fd = open(index->mbox_path, O_RDWR);
	if (fd == -1) {
		index_set_error(index, "Can't open mbox file %s: %m",
				index->mbox_path);
		return FALSE;
	}

	inbuf = io_buffer_create_mmap(fd, default_pool,
				      MAIL_MMAP_BLOCK_SIZE, -1);

	/* lock the mailbox so we can be sure no-one interrupts us.
	   we are trying to repair our index after all. */
	if (!mbox_lock(index, index->mbox_path, fd))
		failed = TRUE;
	else {
		failed = !mbox_index_fsck_buf(index, inbuf);
		(void)mbox_unlock(index, index->mbox_path, fd);
	}

	(void)close(fd);
	io_buffer_destroy(inbuf);

	if (failed)
		return FALSE;

	/* check the header */
	return mail_index_fsck(index);
}
