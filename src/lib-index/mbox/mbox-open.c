/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "mbox-index.h"
#include "mail-index-util.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

IBuffer *mbox_open_mail(MailIndex *index, MailIndexRecord *rec, int *deleted)
{
	IBuffer *inbuf;
	uoff_t offset, v_stop_offset;
	const unsigned char *data;
	size_t size;
	int failed;

	i_assert(index->lock_type != MAIL_LOCK_UNLOCK);

	*deleted = FALSE;

	/* check for inconsistency here, to avoid extra error messages */
	if (index->inconsistent)
		return NULL;

	if (!mbox_mail_get_start_offset(index, rec, &offset))
		return NULL;

	v_stop_offset = rec->header_size + rec->body_size;

	inbuf = mbox_file_open(index, offset, FALSE);
	if (inbuf == NULL)
		return NULL;

	/* make sure message size is valid - it must end with
	   either EOF or "\nFrom "*/
	if (!i_buffer_seek(inbuf, v_stop_offset)) {
		errno = inbuf->buf_errno;
		mbox_set_syscall_error(index, "i_buffer_seek()");
		i_buffer_unref(inbuf);
		return NULL;
	}

	(void)i_buffer_read_data(inbuf, &data, &size, 6);
	if (size >= 6) {
		/* "[\r]\nFrom " expected */
		if (data[0] == '\r') {
			data++;
			size--;
		}

		failed = size < 6 ||
			strncmp((const char *) data, "\nFrom ", 6) != 0;
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

	if (!i_buffer_seek(inbuf, 0)) {
		errno = inbuf->buf_errno;
		mbox_set_syscall_error(index, "i_buffer_seek()");
		failed = TRUE;
	}

	if (failed) {
		/* file has been updated, rescan it */
		index->set_flags |= MAIL_INDEX_FLAG_FSCK;

		index_set_error(index,
			"mbox file %s was modified unexpectedly, fscking",
			index->mbox_path);
		i_buffer_unref(inbuf);
		return NULL;
	}

	i_buffer_set_read_limit(inbuf, v_stop_offset);
	return inbuf;
}
