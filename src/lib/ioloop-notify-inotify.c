/* Copyright (C) 2005 Johannes Berg */

#define _GNU_SOURCE
#include "lib.h"

#ifdef IOLOOP_NOTIFY_INOTIFY

#include "ioloop-internal.h"
#include "buffer.h"
#include "network.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/inotify.h>

#define INITIAL_INOTIFY_BUFLEN (FILENAME_MAX + sizeof(struct inotify_event))
#define MAXIMAL_INOTIFY_BUFLEN (32*1024)

struct ioloop_notify_handler_context {
	int inotify_fd;

	struct io *event_io;

	buffer_t *buf;
	int disabled;
};

static int event_read_next(struct ioloop *ioloop)
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
			if (io->notify_context == event->wd) {
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

static void event_callback(void *context)
{
	struct ioloop *ioloop = context;

	while (event_read_next(ioloop)) ;
}

struct io *io_loop_notify_add(struct ioloop *ioloop, int fd,
			      enum io_condition condition,
			      io_callback_t *callback, void *context)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;
	struct io *io;
	struct inotify_watch_request req;
	int watchdescriptor;

	if ((condition & IO_FILE_NOTIFY) != 0)
		return NULL;

	if (ctx->disabled)
		return NULL;

	/* now set up the notification request and shoot it off */
	req.fd = fd;
	req.mask = IN_CREATE | IN_DELETE | IN_MOVE | IN_CLOSE | IN_MODIFY;
	watchdescriptor = ioctl(ctx->inotify_fd, INOTIFY_WATCH, &req);
	
	if (watchdescriptor < 0) {
		ctx->disabled = TRUE;
		i_error("ioctl(INOTIFY_WATCH) failed: %m");
		return NULL;
	}

	if (ctx->event_io == NULL) {
		ctx->event_io = io_add(ctx->inotify_fd, IO_READ,
				       event_callback, ioloop);
	}

	io = p_new(ioloop->pool, struct io, 1);
	io->fd = fd;
	io->condition = condition;

	io->callback = callback;
	io->context = context;
	io->notify_context = watchdescriptor;

	io->next = ioloop->notifys;
	ioloop->notifys = io;
	return io;
}

void io_loop_notify_remove(struct ioloop *ioloop, struct io *io)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;
	struct io **io_p;

	if (ctx->disabled)
		return;

	for (io_p = &ioloop->notifys; *io_p != NULL; io_p = &(*io_p)->next) {
		if (*io_p == io) {
			*io_p = io->next;
			break;
		}
	}

	if (ioctl(ctx->inotify_fd, INOTIFY_IGNORE, &io->notify_context) < 0)
		i_error("ioctl(INOTIFY_IGNORE) failed: %m");

	p_free(ioloop->pool, io);

	if (ioloop->notifys == NULL) {
		io_remove(ctx->event_io);
		ctx->event_io = NULL;
	}
}

void io_loop_notify_handler_init(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx;

	ctx = ioloop->notify_handler_context =
		i_new(struct ioloop_notify_handler_context, 1);

	ctx->inotify_fd = open("/dev/inotify", O_RDONLY);
	if (ctx->inotify_fd < 0) {
		ctx->disabled = TRUE;
		return;
	}

	ctx->buf = buffer_create_dynamic(default_pool, INITIAL_INOTIFY_BUFLEN);
}

void io_loop_notify_handler_deinit(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;

	if (close(ctx->inotify_fd) < 0)
		i_error("close(/dev/inotify) failed: %m");

	buffer_free(ctx->buf);
	i_free(ctx);
}

#endif
