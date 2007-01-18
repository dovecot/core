/* Copyright (C) 2005 Johannes Berg */

#define _GNU_SOURCE
#include "lib.h"

#ifdef IOLOOP_NOTIFY_INOTIFY

#include "fd-close-on-exec.h"
#include "ioloop-internal.h"
#include "buffer.h"
#include "network.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>

#define INITIAL_INOTIFY_BUFLEN (FILENAME_MAX + sizeof(struct inotify_event))
#define MAXIMAL_INOTIFY_BUFLEN (32*1024)

struct inotify_io {
	struct io io;
	int wd;
};

struct ioloop_notify_handler_context {
	int inotify_fd;

	struct io *event_io;

	buffer_t *buf;
	bool disabled;
};

static bool event_read_next(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;
	struct io *io;
        struct inotify_event *event;
	ssize_t ret;
	size_t record_length;
	int required_bytes;

	if (ioctl(ctx->inotify_fd, FIONREAD, &required_bytes))
		i_fatal("ioctl(inotify_fd, FIONREAD) failed: %m");

	if (required_bytes <= 0)
		return FALSE;

	if (required_bytes > MAXIMAL_INOTIFY_BUFLEN)
		required_bytes = MAXIMAL_INOTIFY_BUFLEN;

	event = buffer_get_space_unsafe(ctx->buf, 0, required_bytes);
	ret = read(ctx->inotify_fd, (void *)event, required_bytes);

	if (ret == 0)
		return FALSE;

	if (ret < 0)
		i_fatal("read(inotify_fd) failed: %m");

	if (gettimeofday(&ioloop_timeval, &ioloop_timezone) < 0)
		i_fatal("gettimeofday(): %m");
	ioloop_time = ioloop_timeval.tv_sec;

	while ((size_t)required_bytes > sizeof(*event)) {
		for (io = ioloop->notifys; io != NULL; io = io->next) {
			struct inotify_io *iio = (struct inotify_io *)io;

			if (iio->wd == event->wd) {
				io->callback(io->context);
				break;
			}
		}

		record_length = event->len + sizeof(struct inotify_event);
		if ((size_t)required_bytes < record_length)
			break;
		required_bytes -= record_length;

		/* this might point outside the area if the loop
		   won't run again */
		event = PTR_OFFSET(event, record_length);
	}

	return TRUE;
}

static void event_callback(struct ioloop *ioloop)
{
	while (event_read_next(ioloop)) ;
}

struct io *io_loop_notify_add(struct ioloop *ioloop, const char *path,
			      io_callback_t *callback, void *context)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;
	struct inotify_io *io;
	int watchdescriptor;

	if (ctx->disabled)
		return NULL;

	watchdescriptor = inotify_add_watch(ctx->inotify_fd, path,
					    IN_CREATE | IN_DELETE | IN_MOVE |
					    IN_CLOSE | IN_MODIFY);
	
	if (watchdescriptor < 0) {
		ctx->disabled = TRUE;
		/* ESTALE could happen with NFS. Don't bother giving an error
		   message then. */
		if (errno != ESTALE)
			i_error("inotify_add_watch(%s) failed: %m", path);
		return NULL;
	}

	if (ctx->event_io == NULL) {
		ctx->event_io = io_add(ctx->inotify_fd, IO_READ,
				       event_callback, ioloop);
	}

	io = p_new(ioloop->pool, struct inotify_io, 1);
	io->io.fd = -1;

	io->io.callback = callback;
	io->io.context = context;
	io->wd = watchdescriptor;
	return &io->io;
}

void io_loop_notify_remove(struct ioloop *ioloop, struct io *_io)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;
	struct inotify_io *io = (struct inotify_io *)_io;

	if (inotify_rm_watch(ctx->inotify_fd, io->wd) < 0)
		i_error("inotify_rm_watch() failed: %m");

	if (ioloop->notifys == NULL)
		io_remove(&ctx->event_io);
}

void io_loop_notify_handler_init(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx;

	ctx = ioloop->notify_handler_context =
		i_new(struct ioloop_notify_handler_context, 1);

	ctx->inotify_fd = inotify_init();
	if (ctx->inotify_fd == -1) {
		i_error("inotify_init() failed: %m");
		ctx->disabled = TRUE;
		return;
	}
	fd_close_on_exec(ctx->inotify_fd, TRUE);

	ctx->buf = buffer_create_dynamic(default_pool, INITIAL_INOTIFY_BUFLEN);
}

void io_loop_notify_handler_deinit(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;

	if (ctx->inotify_fd != -1)
		if (close(ctx->inotify_fd) < 0)
			i_error("close(inotify descriptor) failed: %m");

	if (ctx->buf != NULL)
		buffer_free(ctx->buf);
	i_free(ctx);
}

#endif
