/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "maildir-index.h"

int maildir_record_update(MailIndex *index, MailIndexUpdate *update,
			  int fd, off_t file_size)
{
	IBuffer *inbuf;
        MailField cache_fields;

	/* don't even bother opening the file if we're not going to do
	   anything */
	cache_fields = index->header->cache_fields & ~FIELD_TYPE_LOCATION;
	if (cache_fields == 0)
		return TRUE;

	t_push();
	inbuf = i_buffer_create_mmap(fd, data_stack_pool, MAIL_MMAP_BLOCK_SIZE,
				     0, file_size, FALSE);
	mail_index_update_headers(update, inbuf, cache_fields, NULL, NULL);
	i_buffer_unref(inbuf);
	t_pop();
	return TRUE;
}
