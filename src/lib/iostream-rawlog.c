/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "ioloop.h"
#include "buffer.h"
#include "str.h"
#include "write-full.h"
#include "time-util.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-private.h"
#include "iostream-rawlog-private.h"
#include "istream-rawlog.h"
#include "ostream-rawlog.h"
#include "iostream-rawlog.h"

#include <unistd.h>
#include <fcntl.h>

#define RAWLOG_MAX_LINE_LEN 8192

static int
rawlog_write(struct rawlog_iostream *rstream, const void *data, size_t size)
{
	if (rstream->rawlog_fd == -1)
		return -1;

	if (write_full(rstream->rawlog_fd, data, size) < 0) {
		i_error("rawlog_istream.write(%s) failed: %m",
			rstream->rawlog_path);
		iostream_rawlog_close(rstream);
		return -1;
	}
	return 0;
}

static int
rawlog_write_timestamp(struct rawlog_iostream *rstream, bool line_ends)
{
	unsigned char data[MAX_INT_STRLEN + 6 + 1 + 3];
	buffer_t buf;

	buffer_create_from_data(&buf, data, sizeof(data));
	str_printfa(&buf, "%lu.%06u ",
		    (unsigned long)ioloop_timeval.tv_sec,
		    (unsigned int)ioloop_timeval.tv_usec);
	if ((rstream->flags & IOSTREAM_RAWLOG_FLAG_BUFFERED) != 0) {
		str_append_c(&buf, rstream->input ? 'I' : 'O');
		str_append_c(&buf, line_ends ? ':' : '>');
		str_append_c(&buf, ' ');
	}
	return rawlog_write(rstream, buf.data, buf.used);
}

void iostream_rawlog_init(struct rawlog_iostream *rstream,
			  enum iostream_rawlog_flags flags, bool input)
{
	rstream->flags = flags;
	rstream->input = input;
	if ((rstream->flags & IOSTREAM_RAWLOG_FLAG_BUFFERED) != 0)
		rstream->buffer = buffer_create_dynamic(default_pool, 1024);
}

static void
iostream_rawlog_write_unbuffered(struct rawlog_iostream *rstream,
				 const unsigned char *data, size_t size)
{
	size_t i, start;

	if (!rstream->line_continued) {
		if (rawlog_write_timestamp(rstream, TRUE) < 0)
			return;
	}

	for (start = 0, i = 1; i < size; i++) {
		if (data[i-1] == '\n') {
			if (rawlog_write(rstream, data + start, i - start) < 0 ||
			    rawlog_write_timestamp(rstream, TRUE) < 0)
				return;
			start = i;
		}
	}
	if (start != size) {
		if (rawlog_write(rstream, data + start, size - start) < 0)
			return;
	}
	rstream->line_continued = data[size-1] != '\n';
}

void iostream_rawlog_write(struct rawlog_iostream *rstream,
			   const unsigned char *data, size_t size)
{
	const unsigned char *p;
	size_t pos;
	bool line_ends;

	if (size == 0)
		return;

	io_loop_time_refresh();
	if ((rstream->flags & IOSTREAM_RAWLOG_FLAG_BUFFERED) == 0) {
		iostream_rawlog_write_unbuffered(rstream, data, size);
		return;
	}

	while (rstream->rawlog_fd != -1 && size > 0) {
		p = memchr(data, '\n', size);
		if (p != NULL) {
			line_ends = TRUE;
			pos = p-data + 1;
		} else if (rstream->buffer->used + size < RAWLOG_MAX_LINE_LEN) {
			buffer_append(rstream->buffer, data, size);
			return;
		} else {
			line_ends = FALSE;
			pos = size;
		}

		if (rawlog_write_timestamp(rstream, line_ends) < 0)
			break;
		if (rstream->buffer->used > 0) {
			if (rawlog_write(rstream, rstream->buffer->data,
					 rstream->buffer->used) < 0)
				break;
			buffer_set_used_size(rstream->buffer, 0);
		}
		if (rawlog_write(rstream, data, pos) < 0)
			break;

		data += pos;
		size -= pos;
	}
}

void iostream_rawlog_close(struct rawlog_iostream *rstream)
{
	if ((rstream->flags & IOSTREAM_RAWLOG_FLAG_AUTOCLOSE) != 0 &&
	    rstream->rawlog_fd != -1) {
		if (close(rstream->rawlog_fd) < 0) {
			i_error("rawlog_istream.close(%s) failed: %m",
				rstream->rawlog_path);
		}
	}
	rstream->rawlog_fd = -1;
	i_free_and_null(rstream->rawlog_path);
	if (rstream->buffer != NULL)
		buffer_free(&rstream->buffer);
}

int iostream_rawlog_create(const char *dir, struct istream **input,
			   struct ostream **output)
{
	static unsigned int counter = 0;
	const char *timestamp, *prefix;

	timestamp = t_strflocaltime("%Y%m%d-%H%M%S", ioloop_time);

	counter++;
	prefix = t_strdup_printf("%s/%s.%s.%u", dir, timestamp, my_pid, counter);
	return iostream_rawlog_create_prefix(prefix, input, output);
}

int iostream_rawlog_create_prefix(const char *prefix, struct istream **input,
				  struct ostream **output)
{
	const char *in_path, *out_path;
	struct istream *old_input;
	struct ostream *old_output;
	int in_fd, out_fd;

	in_path = t_strdup_printf("%s.in", prefix);
	in_fd = open(in_path, O_CREAT | O_APPEND | O_WRONLY, 0600);
	if (in_fd == -1) {
		i_error("creat(%s) failed: %m", in_path);
		return -1;
	}

	out_path = t_strdup_printf("%s.out", prefix);
	out_fd = open(out_path, O_CREAT | O_APPEND | O_WRONLY, 0600);
	if (out_fd == -1) {
		i_error("creat(%s) failed: %m", out_path);
		i_close_fd(&in_fd);
		(void)unlink(in_path);
		return -1;
	}

	old_input = *input;
	old_output = *output;
	*input = i_stream_create_rawlog(old_input, in_path, in_fd,
					IOSTREAM_RAWLOG_FLAG_AUTOCLOSE);
	*output = o_stream_create_rawlog(old_output, out_path, out_fd,
					 IOSTREAM_RAWLOG_FLAG_AUTOCLOSE);
	i_stream_unref(&old_input);
	o_stream_unref(&old_output);
	return 0;
}

int iostream_rawlog_create_path(const char *path, struct istream **input,
				struct ostream **output)
{
	struct istream *old_input;
	struct ostream *old_output;
	int fd;

	fd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0600);
	if (fd == -1) {
		i_error("creat(%s) failed: %m", path);
		return -1;
	}

	old_input = *input;
	old_output = *output;
	*input = i_stream_create_rawlog(old_input, path, fd,
					IOSTREAM_RAWLOG_FLAG_BUFFERED);
	*output = o_stream_create_rawlog(old_output, path, fd,
					 IOSTREAM_RAWLOG_FLAG_AUTOCLOSE |
					 IOSTREAM_RAWLOG_FLAG_BUFFERED);
	i_stream_unref(&old_input);
	o_stream_unref(&old_output);
	return 0;
}
