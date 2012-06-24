/* Copyright (c) 2011-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hostpid.h"
#include "ioloop.h"
#include "write-full.h"
#include "time-util.h"
#include "istream.h"
#include "ostream.h"
#include "istream-rawlog.h"
#include "ostream-rawlog.h"
#include "iostream-private.h"
#include "iostream-rawlog-private.h"
#include "iostream-rawlog.h"

#include <unistd.h>
#include <fcntl.h>

static void
rawlog_write(struct rawlog_iostream *rstream, const void *data, size_t size)
{
	if (rstream->rawlog_fd == -1)
		return;

	if (write_full(rstream->rawlog_fd, data, size) < 0) {
		i_error("rawlog_istream.write(%s) failed: %m",
			rstream->rawlog_path);
		iostream_rawlog_close(rstream);
	}
}

static void rawlog_write_timestamp(struct rawlog_iostream *rstream)
{
	char buf[MAX_INT_STRLEN + 6 + 2];

	if (i_snprintf(buf, sizeof(buf), "%lu.%06u ",
		       (unsigned long)ioloop_timeval.tv_sec,
		       (unsigned int)ioloop_timeval.tv_usec) < 0)
		i_unreached();
	rawlog_write(rstream, buf, strlen(buf));
}

void iostream_rawlog_write(struct rawlog_iostream *rstream,
			   const unsigned char *data, size_t size)
{
	size_t i, start;

	i_assert(size > 0);

	io_loop_time_refresh();
	if (rstream->write_timestamp)
		rawlog_write_timestamp(rstream);

	for (start = 0, i = 1; i < size; i++) {
		if (data[i-1] == '\n') {
			rawlog_write(rstream, data + start, i - start);
			rawlog_write_timestamp(rstream);
			start = i;
		}
	}
	if (start != size)
		rawlog_write(rstream, data + start, size - start);
	rstream->write_timestamp = data[size-1] == '\n';
}

void iostream_rawlog_close(struct rawlog_iostream *rstream)
{
	if (rstream->autoclose_fd && rstream->rawlog_fd != -1) {
		if (close(rstream->rawlog_fd) < 0) {
			i_error("rawlog_istream.close(%s) failed: %m",
				rstream->rawlog_path);
		}
	}
	rstream->rawlog_fd = -1;
	i_free_and_null(rstream->rawlog_path);
}

int iostream_rawlog_create(const char *dir, struct istream **input,
			   struct ostream **output)
{
	static unsigned int counter = 0;
	const char *timestamp, *in_path, *out_path;
	struct istream *old_input;
	struct ostream *old_output;
	int in_fd, out_fd;

	timestamp = t_strflocaltime("%Y%m%d-%H%M%S", ioloop_time);

	counter++;
	in_path = t_strdup_printf("%s/%s.%s.%u.in",
				  dir, timestamp, my_pid, counter);
	out_path = t_strdup_printf("%s/%s.%s.%u.out",
				   dir, timestamp, my_pid, counter);

	in_fd = open(in_path, O_CREAT | O_APPEND | O_WRONLY, 0600);
	if (in_fd == -1) {
		i_error("creat(%s) failed: %m", in_path);
		return -1;
	}

	out_fd = open(out_path, O_CREAT | O_APPEND | O_WRONLY, 0600);
	if (out_fd == -1) {
		i_error("creat(%s) failed: %m", out_path);
		i_close_fd(in_fd);
		(void)unlink(in_path);
		return -1;
	}

	old_input = *input;
	old_output = *output;
	*input = i_stream_create_rawlog(old_input, in_path, in_fd, TRUE);
	*output = o_stream_create_rawlog(old_output, out_path, out_fd, TRUE);
	i_stream_unref(&old_input);
	o_stream_unref(&old_output);
	return 0;
}
