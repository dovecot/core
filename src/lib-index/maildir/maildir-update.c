/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "maildir-index.h"

int maildir_record_update(struct mail_index *index,
			  struct mail_index_update *update, int fd)
{
	struct istream *input;
        enum mail_data_field cache_fields;

	/* don't even bother opening the file if we're not going to do
	   anything */
	cache_fields = index->header->cache_fields & ~DATA_FIELD_LOCATION;
	if (cache_fields == 0)
		return TRUE;

	t_push();
	if (index->mail_read_mmaped) {
		input = i_stream_create_mmap(fd, data_stack_pool,
					     MAIL_MMAP_BLOCK_SIZE, 0, 0, FALSE);
	} else {
		input = i_stream_create_file(fd, data_stack_pool,
					     MAIL_READ_BLOCK_SIZE, FALSE);
	}
	mail_index_update_headers(update, input, cache_fields, NULL, NULL);
	i_stream_unref(input);
	t_pop();
	return TRUE;
}
