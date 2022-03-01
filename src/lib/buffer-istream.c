/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "eacces-error.h"
#include "istream.h"

enum buffer_append_result
buffer_append_full_istream(buffer_t *buf, struct istream *is, size_t max_read_size,
			   const char **error_r)
{
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	while ((ret = i_stream_read_more(is, &data, &size)) > 0) {
		if (max_read_size == 0)
			return BUFFER_APPEND_READ_MAX_SIZE;
		size = I_MIN(max_read_size, size);
		buffer_append(buf, data, size);
		i_stream_skip(is, size);
		max_read_size -= size;
	}

	if (ret == 0)
		return BUFFER_APPEND_READ_MORE;

	i_assert(is->eof);

	if (is->stream_errno != 0) {
		*error_r = i_stream_get_error(is);
		return BUFFER_APPEND_READ_ERROR;
	}
	return BUFFER_APPEND_OK;
}

enum buffer_append_result
buffer_append_full_file(buffer_t *buf, const char *file, size_t max_read_size,
			const char **error_r)
{
	struct istream *is = i_stream_create_file(file, IO_BLOCK_SIZE);
	enum buffer_append_result res =
		buffer_append_full_istream(buf, is, max_read_size, error_r);
	if (is->stream_errno == EACCES)
		*error_r = eacces_error_get("open", file);
	i_stream_unref(&is);
	i_assert(res != BUFFER_APPEND_READ_MORE);
	return res;
}
