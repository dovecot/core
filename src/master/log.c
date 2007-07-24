/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "fd-set-nonblock.h"
#include "fd-close-on-exec.h"
#include "log.h"

#include <unistd.h>

struct log_io {
	struct log_io *prev, *next;
	int refcount;

	struct io *io;
	struct istream *stream;

	time_t log_stamp;
	unsigned int log_counter;
        unsigned int max_lines_per_sec;

	char *prefix;
	char next_log_type;
	unsigned int throttle_msg:1;
	unsigned int destroying:1;
};

static struct log_io *log_ios;
static struct timeout *to;
static unsigned int throttle_count;

static int log_it(struct log_io *log_io, const char *line, bool continues);
static int log_read(struct log_io *log_io);
static void log_throttle_timeout(void *context);

static bool log_write_pending(struct log_io *log_io)
{
	const char *line;

	if (log_io->log_stamp != ioloop_time) {
		log_io->log_stamp = ioloop_time;
		log_io->log_counter = 0;
	}

	while ((line = i_stream_next_line(log_io->stream)) != NULL) {
		if (!log_it(log_io, line, FALSE))
			return FALSE;
	}

	return TRUE;
}

static void log_throttle(struct log_io *log_io)
{
	if (!log_io->throttle_msg) {
                log_io->throttle_msg = TRUE;
		log_it(log_io, "Sending log messages too fast, throttling..",
		       FALSE);
	}

	if (log_io->io == NULL) {
		i_assert(to != NULL);
		return;
	}

	io_remove(&log_io->io);
        throttle_count++;

	if (to == NULL)
		to = timeout_add(1000, log_throttle_timeout, NULL);
}

static void log_read_callback(struct log_io *log_io)
{
	(void)log_read(log_io);
}

static void log_unthrottle(struct log_io *log_io)
{
	if (log_io->io != NULL)
		return;

	if (--throttle_count == 0 && to != NULL)
		timeout_remove(&to);
	log_io->io = io_add(i_stream_get_fd(log_io->stream),
			    IO_READ, log_read_callback, log_io);
}

static int log_it(struct log_io *log_io, const char *line, bool continues)
{
	const char *prefix;

	if (log_io->next_log_type == '\0') {
		if (line[0] == 1 && line[1] != '\0') {
			/* our internal protocol.
			   \001 + log_type */
			log_io->next_log_type = line[1];
			line += 2;
		} else {
			log_io->next_log_type = 'E';
		}
	}

	t_push();
	prefix = log_io->prefix != NULL ? log_io->prefix : "";
	switch (log_io->next_log_type) {
	case 'I':
		i_info("%s%s", prefix, line);
		break;
	case 'W':
		i_warning("%s%s", prefix, line);
		break;
	default:
		i_error("%s%s", prefix, line);
		break;
	}
	t_pop();

	if (!continues)
		log_io->next_log_type = '\0';

	if (++log_io->log_counter > log_io->max_lines_per_sec &&
	    !log_io->destroying) {
		log_throttle(log_io);
		return 0;
	}
	return 1;
}

static int log_read(struct log_io *log_io)
{
	const unsigned char *data;
	const char *line;
	size_t size;
	int ret;

	if (!log_write_pending(log_io))
		return 0;

	ret = i_stream_read(log_io->stream);
	if (ret < 0) {
		if (ret == -1) {
			/* closed */
			log_unref(log_io);
			return -1;
		}

		/* buffer full. treat it as one line */
		data = i_stream_get_data(log_io->stream, &size);
		line = t_strndup(data, size);
		i_stream_skip(log_io->stream, size);

		if (!log_it(log_io, line, TRUE))
			return 0;
	}

	if (!log_write_pending(log_io))
		return 0;

	if (log_io->log_counter < log_io->max_lines_per_sec)
		log_unthrottle(log_io);
	return 0;
}

int log_create_pipe(struct log_io **log_r, unsigned int max_lines_per_sec)
{
	struct log_io *log_io;
	int fd[2];

	if (pipe(fd) < 0) {
		i_error("pipe() failed: %m");
		return -1;
	}

	fd_set_nonblock(fd[0], TRUE);
	fd_close_on_exec(fd[0], TRUE);
	fd_close_on_exec(fd[1], TRUE);

	log_io = i_new(struct log_io, 1);
	log_io->refcount = 1;
	log_io->stream = i_stream_create_file(fd[0], 1024, TRUE);
	log_io->max_lines_per_sec =
		max_lines_per_sec != 0 ? max_lines_per_sec : (unsigned int)-1;

	throttle_count++;
        log_unthrottle(log_io);

	if (log_ios != NULL)
		log_ios->prev = log_io;
	log_io->next = log_ios;
	log_ios = log_io;

	if (log_r != NULL)
		*log_r = log_io;
	return fd[1];
}

void log_set_prefix(struct log_io *log, const char *prefix)
{
	i_free(log->prefix);
	log->prefix = i_strdup(prefix);
}

void log_ref(struct log_io *log_io)
{
	log_io->refcount++;
}

static void log_close(struct log_io *log_io)
{
	const unsigned char *data;
	size_t size;

	if (log_io->destroying)
		return;

	/* if there was something in buffer, write it */
	log_io->destroying = TRUE;
	(void)log_write_pending(log_io);

	/* write partial data as well */
	data = i_stream_get_data(log_io->stream, &size);
	if (size != 0) {
		t_push();
		log_it(log_io, t_strndup(data, size), TRUE);
		t_pop();
	}

	if (log_io == log_ios)
		log_ios = log_io->next;
	else
		log_io->prev->next = log_io->next;
	if (log_io->next != NULL)
		log_io->next->prev = log_io->prev;

	if (log_io->io != NULL)
		io_remove(&log_io->io);
	else
		throttle_count--;
	i_stream_destroy(&log_io->stream);
}

void log_unref(struct log_io *log_io)
{
	i_assert(log_io->refcount > 0);

	log_close(log_io);

	if (--log_io->refcount > 0)
		return;

	i_free(log_io->prefix);
	i_free(log_io);
}

static void log_throttle_timeout(void *context __attr_unused__)
{
	struct log_io *log, *next;
	unsigned int left = throttle_count;

	i_assert(left > 0);

	for (log = log_ios; log != NULL; log = next) {
		next = log->next;

		if (log->io == NULL) {
			if (log_write_pending(log))
				log_unthrottle(log);

			if (--left == 0)
				break;
		}
	}
}

void log_init(void)
{
	log_ios = NULL;
        throttle_count = 0;
	to = NULL;
}

void log_deinit(void)
{
	struct log_io *next;

	while (log_ios != NULL) {
		next = log_ios->next;
		/* do one final log read in case there's still something
		   waiting */
		if (log_read(log_ios) == 0)
			log_unref(log_ios);
		log_ios = next;
	}

	if (to != NULL)
		timeout_remove(&to);
}
