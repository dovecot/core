/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "write-full.h"
#include "index-storage.h"

#include <stdlib.h>
#include <unistd.h>

static int write_with_crlf(OStream *output, const unsigned char *data,
			   size_t size)
{
	size_t i, start;

	i_assert(size > 0 && size <= SSIZE_T_MAX);

	start = 0;
	for (i = 0; i < size; i++) {
		if (data[i] == '\n' && (i == 0 || data[i-1] != '\r')) {
			/* missing CR */
			if (o_stream_send(output, data + start, i - start) < 0)
				return -1;
			if (o_stream_send(output, "\r", 1) < 0)
				return -1;

			/* \n is written next time */
			start = i;
		}
	}

	/* if last char is \r, leave it to buffer */
	if (data[size-1] == '\r')
		size--;

	if (o_stream_send(output, data + start, size - start) < 0)
		return -1;

	return size;
}

static int write_with_lf(OStream *output, const unsigned char *data,
			 size_t size)
{
	size_t i, start;

	i_assert(size > 0 && size <= SSIZE_T_MAX);

	start = 0;
	for (i = 0; i < size; i++) {
		if (data[i] == '\n' && i > 0 && data[i-1] == '\r') {
			/* \r\n - skip \r */
			if (o_stream_send(output, data + start,
					   i - start - 1) < 0)
				return -1;

			/* \n is written next time */
			start = i;
		}
	}

	/* if last char is \r, leave it to buffer */
	if (data[size-1] == '\r')
		size--;

	if (o_stream_send(output, data + start, size - start) < 0)
		return -1;

	return size;
}

int index_storage_save(MailStorage *storage, const char *path,
		       IStream *input, OStream *output, uoff_t data_size)
{
	int (*write_func)(OStream *, const unsigned char *, size_t);
	const unsigned char *data;
	size_t size;
	ssize_t ret;
	int failed;

	write_func = getenv("MAIL_SAVE_CRLF") ? write_with_crlf : write_with_lf;

	failed = FALSE;
	while (data_size > 0) {
		ret = i_stream_read(input);
		if (ret < 0) {
			errno = input->stream_errno;
			if (errno == 0) {
				mail_storage_set_error(storage,
					"Client disconnected");
			} else if (errno == EAGAIN) {
				mail_storage_set_error(storage,
					"Timeout while waiting for input");
			} else {
				mail_storage_set_critical(storage,
					"Error reading mail from client: %m");
			}
			return FALSE;
		}

		data = i_stream_get_data(input, &size);
		if (size > data_size)
			size = (size_t)data_size;

		if (!failed) {
			ret = write_func(output, data, size);
			if (ret < 0) {
				errno = output->stream_errno;
				if (errno == ENOSPC) {
					mail_storage_set_error(storage,
						"Not enough disk space");
				} else {
					mail_storage_set_critical(storage,
						"write_full() failed for file "
						"%s: %m", path);
				}
				failed = TRUE;
			} else {
				size = ret;
			}
		}

		data_size -= size;
		i_stream_skip(input, size);
	}

	return !failed;
}
