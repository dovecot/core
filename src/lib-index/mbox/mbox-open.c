/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "mbox-index.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

IOBuffer *mbox_open_mail(MailIndex *index, MailIndexRecord *rec)
{
	IOBuffer *inbuf;
	uoff_t offset, stop_offset;
	unsigned char *data;
	size_t size;
	int failed;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	/* check for inconsistency here, to avoid extra error messages */
	if (index->inconsistent)
		return NULL;

	if (!mbox_mail_get_start_offset(index, rec, &offset))
		return NULL;

	stop_offset = offset + rec->header_size + rec->body_size;

	inbuf = mbox_file_open(index, offset, FALSE);
	if (inbuf == NULL)
		return NULL;

	/* make sure message size is valid - it must end with
	   either EOF or "\nFrom "*/
	if (!io_buffer_seek(inbuf, stop_offset - offset)) {
		mbox_set_syscall_error(index, "io_buffer_seek()");
		io_buffer_unref(inbuf);
		return NULL;
	}

	(void)io_buffer_read_data_blocking(inbuf, &data, &size, 6);
	if (size >= 6) {
		/* "[\r]\nFrom " expected */
		if (data[0] == '\r') {
			data++;
			size--;
		}

		failed = size < 6 || strncmp((char *) data, "\nFrom ", 6) != 0;
	} else {
		if (size > 0 && data[0] == '\r') {
			data++;
			size--;
		}
		if (size > 0 && data[0] == '\n')
			size--;

                /* we should be at end of file now */
		failed = size != 0;
	}

	if (!io_buffer_seek(inbuf, 0)) {
		mbox_set_syscall_error(index, "io_buffer_seek()");
		failed = TRUE;
	}

	if (failed) {
		/* file has been updated, rescan it */
		index->set_flags |= MAIL_INDEX_FLAG_FSCK;

		index_set_error(index, "mbox file %s was modified "
				"unexpectedly, fscking", index->mbox_path);
		io_buffer_unref(inbuf);
		return NULL;
	}

	io_buffer_set_read_limit(inbuf, stop_offset - offset);
	return inbuf;
}
