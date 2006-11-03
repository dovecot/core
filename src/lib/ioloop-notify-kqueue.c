/*
 * BSD kqueue() based ioloop notify handler.
 *
 * Copyright (c) 2005 Vaclav Haisman <v.haisman@sh.cvut.cz>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE
#include "lib.h"

#ifdef IOLOOP_NOTIFY_KQUEUE

#include "ioloop-internal.h"
#include "fd-close-on-exec.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/stat.h>

/* kevent.udata's type just has to be different in NetBSD than in
   FreeBSD and OpenBSD.. */
#ifdef __NetBSD__
#  define MY_EV_SET(a, b, c, d, e, f, g) \
	EV_SET(a, b, c, d, e, f, (intptr_t)g)
#else
#  define MY_EV_SET(a, b, c, d, e, f, g) \
	EV_SET(a, b, c, d, e, f, g)
#endif

struct ioloop_notify_handler_context {
	int kq;
	struct io *event_io;
};

static void event_callback(void *context)
{
	struct ioloop_notify_handler_context *ctx = context;
	struct io *io;
	struct kevent ev;
	struct timespec ts;
	int ret;

	if (gettimeofday(&ioloop_timeval, &ioloop_timezone) < 0)
		i_fatal("gettimeofday() failed: %m");
	ioloop_time = ioloop_timeval.tv_sec;

	ts.tv_sec = 0;
	ts.tv_nsec = 0;

	ret = kevent(ctx->kq, NULL, 0, &ev, 1, &ts);
	if (ret <= 0) {
		if (ret == 0 || errno == EINTR)
			return;

		i_fatal("kevent(notify) failed: %m");
	}
	io = (void *)ev.udata;
	io->callback(io->context);
}

void io_loop_notify_handler_init(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx;

	ctx = ioloop->notify_handler_context =
		p_new(ioloop->pool, struct ioloop_notify_handler_context, 1);
	ctx->kq = kqueue();
	if (ctx->kq < 0)
		i_fatal("kqueue(notify) failed: %m");
	fd_close_on_exec(ctx->kq, TRUE);
}

void io_loop_notify_handler_deinit(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;

	if (ctx->event_io)
		io_remove(&ctx->event_io);
	if (close(ctx->kq) < 0)
		i_error("close(kqueue notify) failed: %m");
	p_free(ioloop->pool, ctx);
}

struct io *io_loop_notify_add(struct ioloop *ioloop, const char *path,
			      io_callback_t *callback, void *context)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;
	struct kevent ev;
	struct io *io;
	int fd;
	struct stat sb;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT)
			i_error("open(%s) for kq notify failed: %m", path);
		return NULL;
	}

	if (fstat(fd, &sb) < 0) {
		i_error("fstat(%d, %s) for kq notify failed: %m", fd, path);
		(void)close(fd);
		return NULL;
	}
	if (!S_ISDIR(sb.st_mode)) {
		(void)close(fd);
		return NULL;
	}
	fd_close_on_exec(fd, TRUE);

	io = p_new(ioloop->pool, struct io, 1);
	io->fd = fd;
	io->callback = callback;
	io->context = context;

	/* EV_CLEAR flag is needed because the EVFILT_VNODE filter reports
	   event state transitions and not the current state.  With this flag,
	   the same event is only returned once. */
	MY_EV_SET(&ev, fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
		  NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_REVOKE, 0, io);
	if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0) {
		i_error("kevent(%d, %s) for notify failed: %m", fd, path);
		(void)close(fd);
		p_free(ioloop->pool, io);
		return NULL;
	}

	if (ctx->event_io == NULL) {
		ctx->event_io =
			io_add(ctx->kq, IO_READ, event_callback,
			       ioloop->notify_handler_context);
	}
	return io;
}

void io_loop_notify_remove(struct ioloop *ioloop, struct io *io)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;
	struct kevent ev;

	i_assert((io->condition & IO_NOTIFY) != 0);

	MY_EV_SET(&ev, io->fd, EVFILT_VNODE, EV_DELETE, 0, 0, NULL);
	if (kevent(ctx->kq, &ev, 1, NULL, 0, 0) < 0)
		i_error("kevent(%d) for notify remove failed: %m", io->fd);
	if (close(io->fd) < 0)
		i_error("close(%d) for notify remove failed: %m", io->fd);
}

#endif
