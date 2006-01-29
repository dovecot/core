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

struct ioloop_notify_handler_context {
	int kq;
	struct io *event_io;
};

static void event_callback(void *context)
{
	struct ioloop_notify_handler_context *ctx = context;
	struct io *io;
	struct kevent ev;

	if (gettimeofday(&ioloop_timeval, &ioloop_timezone) < 0)
		i_fatal("gettimeofday() failed: %m");
	ioloop_time = ioloop_timeval.tv_sec;

	if (kevent(ctx->kq, NULL, 0, &ev, 1, 0) < 0)
		i_fatal("kevent() failed: %m");
	io = ev.udata;
	io->callback(io->context);
}

void io_loop_notify_handler_init(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx;

	ctx = ioloop->notify_handler_context =
		p_new(ioloop->pool, struct ioloop_notify_handler_context, 1);
	ctx->kq = kqueue();
	if (ctx->kq < 0)
		i_fatal("kqueue() in io_loop_notify_handler_init() failed: %m");
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
	struct kevent ev = { -1, EVFILT_VNODE, EV_ADD,
			     NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND
			     | NOTE_REVOKE, 0, NULL };
	struct io *io;
	int fd;
	struct stat sb;

	i_assert(callback != NULL);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
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
	ev.ident = fd;
	ev.udata = io;
	if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0) {
		i_error("kevent(%d, %s) for notify failed: %m", fd, path);
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
	struct kevent ev = { io->fd, EVFILT_VNODE, EV_DELETE, 0, 0, NULL };

	i_assert((io->condition & IO_NOTIFY) != 0);

	if (kevent(ctx->kq, &ev, 1, NULL, 0, 0) < 0)
		i_error("kevent(%d) for notify remove failed: %m", io->fd);
	if (close(io->fd) < 0)
		i_error("close(%d) failed: %m", io->fd);
}

#endif
