/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "maildir-index.h"

int maildir_record_update(MailIndexUpdate *update, int fd, off_t file_size)
{
	IOBuffer *inbuf;

	t_push();
	inbuf = io_buffer_create_mmap(fd, data_stack_pool,
				      MAIL_MMAP_BLOCK_SIZE, 0, file_size, 0);
	mail_index_update_headers(update, inbuf, 0, NULL, NULL);
	io_buffer_unref(inbuf);
	t_pop();
	return TRUE;
}
