/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "write-full.h"
#include "index-storage.h"

#include <stdlib.h>
#include <unistd.h>

static int write_with_crlf(int fd, const unsigned char *data,
			   unsigned int size, unsigned int *last_cr)
{
	int i, cr;

	i_assert(size < INT_MAX);

	cr = *last_cr ? -1 : -2;
	for (i = 0; i < (int)size; i++) {
		if (data[i] == '\r')
			cr = i;
		else if (data[i] == '\n' && cr != i-1) {
			/* missing CR */
			if (write_full(fd, data, (unsigned int) i) < 0)
				return FALSE;
			if (write_full(fd, "\r", 1) < 0)
				return FALSE;

			/* skip the data so far. \n is left into buffer and
			   we'll continue from the next character. */
			data += i;
			size -= i;
			i = 0; cr = -2;
		}
	}

	return write_full(fd, data, size) < 0;
}

int index_storage_save_into_fd(MailStorage *storage, int fd, const char *path,
			       IOBuffer *buf, size_t data_size)
{
	unsigned char *data;
	unsigned int size, last_cr;
	int ret;

	last_cr = FALSE;

	while (data_size > 0) {
		ret = io_buffer_read_blocking(buf, (unsigned int)-1);
		if (ret < 0) {
			mail_storage_set_critical(storage,
						  "Error reading mail: %m");
			return FALSE;
		}

		data = io_buffer_get_data(buf, &size);
		if (size == 0)
			continue;

		if (size > data_size)
			size = data_size;
		data_size -= size;

		if (write_with_crlf(fd, data, size, &last_cr)) {
			mail_storage_set_critical(storage, "write() failed "
						  "for file %s: %m", path);
			return FALSE;
		}

		io_buffer_skip(buf, size);
	}

	return TRUE;
}
