/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "maildir-index.h"

int maildir_record_update(MailIndexUpdate *update, int fd, off_t file_size)
{
	IBuffer *inbuf;

	t_push();
	inbuf = i_buffer_create_mmap(fd, data_stack_pool, MAIL_MMAP_BLOCK_SIZE,
				     0, file_size, FALSE);
	mail_index_update_headers(update, inbuf, 0, NULL, NULL);
	i_buffer_unref(inbuf);
	t_pop();
	return TRUE;
}
