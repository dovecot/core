/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "mbox-index.h"
#include "mbox-storage.h"
#include "mbox-lock.h"

#include <fcntl.h>
#include <unistd.h>

static int expunge_real(IndexMailbox *ibox, MailIndexRecord *rec,
			unsigned int seq, IOBuffer *inbuf, IOBuffer *outbuf,
			MailExpungeFunc expunge_func, void *context)
{
	uoff_t offset, end_offset, from_offset, copy_size;
	unsigned int uid;
	unsigned char *data;
	size_t size;
	int expunges;

	if (seq == 1)
		end_offset = 0;
	else {
		/* we need to find offset to beginning of From-line.
		   not the fastest way maybe, but easiest.. */
		rec = ibox->index->lookup(ibox->index, seq-1);
		
		if (!mbox_mail_get_start_offset(ibox->index, rec, &offset))
			return FALSE;
		end_offset = offset + rec->header_size + rec->body_size;

		/* get back to the deleted record */
		rec = ibox->index->next(ibox->index, rec);
	}

	expunges = FALSE;
	while (rec != NULL) {
		if (!mbox_mail_get_start_offset(ibox->index, rec, &offset))
			return FALSE;

		from_offset = end_offset;
		end_offset = offset + rec->header_size + rec->body_size;

		if (rec->msg_flags & MAIL_DELETED) {
			/* save UID before deletion */
			uid = rec->uid;

			if (!ibox->index->expunge(ibox->index, rec,
						  seq, FALSE))
				return FALSE;

			if (expunge_func != NULL)
				expunge_func(&ibox->box, seq, uid, context);
			seq--;

			if (!expunges) {
				/* first expunged record, seek to position
				   where we want to begin writing */
				if (!io_buffer_seek(outbuf, from_offset))
					return FALSE;
				expunges = TRUE;
			}
		} else if (expunges) {
			/* seek to wanted input position, and copy
			   this messages */
			i_assert(inbuf->offset <= from_offset);
			io_buffer_skip(inbuf, from_offset - inbuf->offset);

			if (outbuf->offset == 0) {
				/* we're writing to beginning of mbox, so we
				   don't want the [\r]\n there */
				(void)io_buffer_read_data_blocking(inbuf, &data,
								   &size, 1);
				if (size > 0 && data[0] == '\n')
					io_buffer_skip(inbuf, 1);
				else if (size > 1 && data[0] == '\r' &&
					 data[1] == '\n')
					io_buffer_skip(inbuf, 2);
			}

                        copy_size = end_offset - inbuf->offset;
			if (io_buffer_send_iobuffer(outbuf, inbuf,
						    copy_size) < 0)
				return FALSE;
		}

		rec = ibox->index->next(ibox->index, rec);
		seq++;
	}

	io_buffer_skip(inbuf, end_offset - inbuf->offset);

	/* copy the rest as well, should be only \n but someone might
	   as well just appended more data.. but if we've deleted all mail,
	   don't write the only \n there. */
	copy_size = inbuf->size - inbuf->offset;
	if (outbuf->offset == 0 && copy_size == 1)
		return TRUE;
	else
		return io_buffer_send_iobuffer(outbuf, inbuf, copy_size) > 0;
}

int mbox_expunge_locked(IndexMailbox *ibox,
			MailExpungeFunc expunge_func, void *context)
{
	MailIndexRecord *rec;
	IOBuffer *inbuf, *outbuf;
	unsigned int seq;
	int fd, failed;

	if (!index_expunge_seek_first(ibox, &seq, &rec))
		return FALSE;

	if (rec == NULL) {
		/* no deleted messages */
		return TRUE;
	}

	fd = open(ibox->index->mbox_path, O_RDWR);
	if (fd == -1) {
		mail_storage_set_error(ibox->box.storage,
				       "Error opening mbox file %s: %m",
				       ibox->index->mbox_path);
		return FALSE;
	}

	if (!mbox_lock(ibox->index, ibox->index->mbox_path, fd)) {
		(void)close(fd);
		return FALSE;
	}

	inbuf = io_buffer_create_mmap(fd, default_pool,
				      MAIL_MMAP_BLOCK_SIZE, 0);
	outbuf = io_buffer_create_file(fd, default_pool, 4096);

	failed = !expunge_real(ibox, rec, seq, inbuf, outbuf,
			       expunge_func, context);

	if (failed && outbuf->offset > 0) {
		/* we moved some of the data. move the rest as well so there
		   won't be invalid holes in mbox file */
		i_assert(inbuf->offset <= inbuf->size);
		(void)io_buffer_send_iobuffer(outbuf, inbuf,
					      inbuf->size - inbuf->offset);
	}

	if (ftruncate(outbuf->fd, outbuf->offset) < 0) {
		mail_storage_set_error(ibox->box.storage, "ftruncate() failed "
				       "for mbox file %s: %m",
				       ibox->index->mbox_path);
		failed = TRUE;
	}

	(void)mbox_unlock(ibox->index, ibox->index->mbox_path, fd);
	(void)close(fd);
	io_buffer_destroy(inbuf);
	io_buffer_destroy(outbuf);

	return !failed;
}
