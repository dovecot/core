/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "maildir-index.h"

int maildir_record_update(MailIndexUpdate *update, int fd, const char *path)
{
	IOBuffer *inbuf;

	i_assert(path != NULL);

	inbuf = io_buffer_create_mmap(fd, default_pool,
				      MAIL_MMAP_BLOCK_SIZE, 0);
	mail_index_update_headers(update, inbuf, 0, NULL, NULL);
	io_buffer_destroy(inbuf);
	return TRUE;
}
