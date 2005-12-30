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
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

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

	if (kevent(ctx->kq, NULL, 0, &ev, 1, 0) < 0) {
		i_fatal("kevent() failed: %m");
		return;
	}
	io = ev.udata;
	io->callback(io->context);
}

void io_loop_notify_handler_init(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx;

	ctx = ioloop->notify_handler_context =
		p_new(ioloop->pool, struct ioloop_notify_handler_context, 1);
	ctx->event_io = NULL;
	ctx->kq = kqueue();
	if (ctx->kq < 0)
		i_fatal("kqueue() failed: %m");
}

void io_loop_notify_handler_deinit(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;

        if (ctx->event_io)
                io_remove(ctx->event_io);
	if (close(ctx->kq) < 0)
		i_error("close(kqueue notify) failed: %m");
	p_free(ioloop->pool, ctx);
}

static void unchain_io (struct ioloop *ioloop, struct io * io)
{
	struct io **io_p;

	for (io_p = &ioloop->notifys; *io_p != NULL; io_p = &(*io_p)->next) {
		if (*io_p == io) {
			*io_p = io->next;
			break;
		}
	}
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

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		i_error("open(%s) for notify failed: %m", path);
		return NULL;
	}

	ev.ident = fd;
	ev.udata = io;
	if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0) {
		i_error("kevent(%s) for notify failed: %m", path);
		return NULL;
	}

	io = p_new(ioloop->pool, struct io, 1);
	io->fd = fd;
	io->callback = callback;
	io->context = context;
	io->next = ioloop->notifys;
	ioloop->notifys = io;

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
	struct kevent ev = { io->fd, 0, EV_DELETE, 0, 0, NULL };
	int ret;

	unchain_io(ioloop, io);
	p_free(ioloop->pool, io);

	ret = kevent(ctx->kq, &ev, 1, NULL, 0, 0);
	if (ret == -1)
		i_error("kevent() for notify failed: %m");
}

#endif
