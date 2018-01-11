/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "ioloop.h"
#include "buffer.h"
#include "str.h"
#include "net.h"
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

static void
rawlog_write_timestamp(struct rawlog_iostream *rstream, bool line_ends)
{
	unsigned char data[MAX_INT_STRLEN + 6 + 1 + 3];
	buffer_t buf;

	if ((rstream->flags & IOSTREAM_RAWLOG_FLAG_TIMESTAMP) == 0)
		return;

	buffer_create_from_data(&buf, data, sizeof(data));
	str_printfa(&buf, "%"PRIdTIME_T".%06u ",
		    ioloop_timeval.tv_sec,
		    (unsigned int)ioloop_timeval.tv_usec);
	if ((rstream->flags & IOSTREAM_RAWLOG_FLAG_BUFFERED) != 0) {
		str_append_c(&buf, rstream->input ? 'I' : 'O');
		str_append_c(&buf, line_ends ? ':' : '>');
		str_append_c(&buf, ' ');
	}
	o_stream_nsend(rstream->rawlog_output, buf.data, buf.used);
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
iostream_rawlog_write_buffered(struct rawlog_iostream *rstream,
			       const unsigned char *data, size_t size)
{
	const unsigned char *p;
	size_t pos;
	bool line_ends;

	while (size > 0) {
		p = memchr(data, '\n', size);
		if (p != NULL) {
			line_ends = TRUE;
			pos = p-data + 1;
		} else if (rstream->buffer->used + size < RAWLOG_MAX_LINE_LEN) {
			buffer_append(rstream->buffer, data, size);
			break;
		} else {
			line_ends = FALSE;
			pos = size;
		}

		rawlog_write_timestamp(rstream, line_ends);
		if (rstream->buffer->used > 0) {
			o_stream_nsend(rstream->rawlog_output,
				       rstream->buffer->data,
				       rstream->buffer->used);
			buffer_set_used_size(rstream->buffer, 0);
		}
		o_stream_nsend(rstream->rawlog_output, data, pos);

		data += pos;
		size -= pos;
	}
}

static void
iostream_rawlog_write_unbuffered(struct rawlog_iostream *rstream,
				 const unsigned char *data, size_t size)
{
	size_t i, start;

	if (!rstream->line_continued)
		rawlog_write_timestamp(rstream, TRUE);

	for (start = 0, i = 1; i < size; i++) {
		if (data[i-1] == '\n') {
			o_stream_nsend(rstream->rawlog_output,
				       data + start, i - start);
			rawlog_write_timestamp(rstream, TRUE);
			start = i;
		}
	}
	if (start != size) {
		o_stream_nsend(rstream->rawlog_output,
			       data + start, size - start);
	}
	rstream->line_continued = data[size-1] != '\n';
}

void iostream_rawlog_write(struct rawlog_iostream *rstream,
			   const unsigned char *data, size_t size)
{
	if (size == 0 || rstream->rawlog_output == NULL)
		return;

	io_loop_time_refresh();

	o_stream_cork(rstream->rawlog_output);
	if ((rstream->flags & IOSTREAM_RAWLOG_FLAG_BUFFERED) != 0)
		iostream_rawlog_write_buffered(rstream, data, size);
	else
		iostream_rawlog_write_unbuffered(rstream, data, size);
	o_stream_uncork(rstream->rawlog_output);

	if (o_stream_flush(rstream->rawlog_output) < 0) {
		i_error("write(%s) failed: %s",
			o_stream_get_name(rstream->rawlog_output),
			o_stream_get_error(rstream->rawlog_output));
		iostream_rawlog_close(rstream);
	}
}

void iostream_rawlog_close(struct rawlog_iostream *rstream)
{
	o_stream_unref(&rstream->rawlog_output);
	buffer_free(&rstream->buffer);
}

static void
iostream_rawlog_create_fd(int fd, const char *path, struct istream **input,
			  struct ostream **output)
{
	struct istream *old_input;
	struct ostream *old_output;

	old_input = *input;
	old_output = *output;
	*input = i_stream_create_rawlog(old_input, path, fd,
					IOSTREAM_RAWLOG_FLAG_BUFFERED |
					IOSTREAM_RAWLOG_FLAG_TIMESTAMP);
	*output = o_stream_create_rawlog(old_output, path, fd,
					 IOSTREAM_RAWLOG_FLAG_AUTOCLOSE |
					 IOSTREAM_RAWLOG_FLAG_BUFFERED |
					 IOSTREAM_RAWLOG_FLAG_TIMESTAMP);
	i_stream_unref(&old_input);
	o_stream_unref(&old_output);
}

static int
iostream_rawlog_try_create_tcp(const char *path,
			       struct istream **input, struct ostream **output)
{
	const char *host;
	struct ip_addr *ips;
	unsigned int ips_count;
	in_port_t port;
	int ret, fd;

	/* tcp:host:port */
	if (!str_begins(path, "tcp:"))
		return 0;
	path += 4;

	if (strchr(path, '/') != NULL)
		return 0;
	if (net_str2hostport(path, 0, &host, &port) < 0 || port == 0)
		return 0;

	ret = net_gethostbyname(host, &ips, &ips_count);
	if (ret != 0) {
		i_error("net_gethostbyname(%s) failed: %s", host,
			net_gethosterror(ret));
		return -1;
	}
	fd = net_connect_ip_blocking(&ips[0], port, NULL);
	if (fd == -1) {
		i_error("connect(%s:%u) failed: %m", net_ip2addr(&ips[0]), port);
		return -1;
	}
	iostream_rawlog_create_fd(fd, path, input, output);
	return 1;
}

int iostream_rawlog_create(const char *dir, struct istream **input,
			   struct ostream **output)
{
	static unsigned int counter = 0;
	const char *timestamp, *prefix;
	struct stat st;
	int ret;

	if ((ret = iostream_rawlog_try_create_tcp(dir, input, output)) != 0)
		return ret < 0 ? -1 : 0;
	if (stat(dir, &st) < 0) {
		if (errno != ENOENT && errno != EACCES)
			i_error("rawlog: stat(%s) failed: %m", dir);
		return -1;
	}

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
		i_unlink(in_path);
		return -1;
	}

	old_input = *input;
	old_output = *output;

	*input = i_stream_create_rawlog(old_input, in_path, in_fd,
					IOSTREAM_RAWLOG_FLAG_AUTOCLOSE |
					IOSTREAM_RAWLOG_FLAG_TIMESTAMP);
	*output = o_stream_create_rawlog(old_output, out_path, out_fd,
					 IOSTREAM_RAWLOG_FLAG_AUTOCLOSE |
					 IOSTREAM_RAWLOG_FLAG_TIMESTAMP);
	i_stream_unref(&old_input);
	o_stream_unref(&old_output);
	return 0;
}

int iostream_rawlog_create_path(const char *path, struct istream **input,
				struct ostream **output)
{
	int ret, fd;

	if ((ret = iostream_rawlog_try_create_tcp(path, input, output)) != 0)
		return ret < 0 ? -1 : 0;
	fd = open(path, O_CREAT | O_APPEND | O_WRONLY, 0600);
	if (fd == -1) {
		i_error("creat(%s) failed: %m", path);
		return -1;
	}
	iostream_rawlog_create_fd(fd, path, input, output);
	return 0;
}

void iostream_rawlog_create_from_stream(struct ostream *rawlog_output,
					struct istream **input,
					struct ostream **output)
{
	const enum iostream_rawlog_flags rawlog_flags =
		IOSTREAM_RAWLOG_FLAG_BUFFERED |
		IOSTREAM_RAWLOG_FLAG_TIMESTAMP;
	struct istream *old_input;
	struct ostream *old_output;

	if (input != NULL) {
		old_input = *input;
		*input = i_stream_create_rawlog_from_stream(old_input,
				rawlog_output, rawlog_flags);
		i_stream_unref(&old_input);
	}
	if (output != NULL) {
		old_output = *output;
		*output = o_stream_create_rawlog_from_stream(old_output,
				rawlog_output, rawlog_flags);
		o_stream_unref(&old_output);
	}
	if (input != NULL && output != NULL)
		o_stream_ref(rawlog_output);
}
