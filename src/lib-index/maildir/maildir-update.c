/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "maildir-index.h"

int maildir_record_update(MailIndex *index, MailIndexUpdate *update, int fd)
{
	IBuffer *inbuf;
        MailDataField cache_fields;

	/* don't even bother opening the file if we're not going to do
	   anything */
	cache_fields = index->header->cache_fields & ~DATA_FIELD_LOCATION;
	if (cache_fields == 0)
		return TRUE;

	t_push();
	if (index->mail_read_mmaped) {
		inbuf = i_buffer_create_mmap(fd, data_stack_pool,
					     MAIL_MMAP_BLOCK_SIZE, 0, 0, FALSE);
	} else {
		inbuf = i_buffer_create_file(fd, data_stack_pool,
					     MAIL_READ_BLOCK_SIZE, FALSE);
	}
	mail_index_update_headers(update, inbuf, cache_fields, NULL, NULL);
	i_buffer_unref(inbuf);
	t_pop();
	return TRUE;
}
