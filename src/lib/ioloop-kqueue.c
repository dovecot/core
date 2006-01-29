/*
 * BSD kqueue() based ioloop handler.
 *
 * Copyright (c) 2005 Vaclav Haisman <v.haisman@sh.cvut.cz>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* @UNSAFE: whole file */

#include "lib.h"

#ifdef IOLOOP_KQUEUE

#include "fd-close-on-exec.h"
#include "ioloop-internal.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#ifndef INITIAL_BUF_SIZE
#  define INITIAL_BUF_SIZE 128
#endif

#define MASK (IO_READ | IO_WRITE | IO_ERROR)

struct ioloop_handler_context {
	int kq;
	size_t evbuf_size;
	struct kevent *evbuf;

	size_t fds_size;
	struct fdrecord *fds;
};

struct fdrecord {
	struct io *errio;
	enum io_condition mode;
};

void io_loop_handler_init(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx;

	ioloop->handler_context = ctx =
		p_new(ioloop->pool, struct ioloop_handler_context, 1);

	ctx->evbuf_size = INITIAL_BUF_SIZE;
	ctx->evbuf = p_new(ioloop->pool, struct kevent, ctx->evbuf_size);
	ctx->kq = kqueue();
	if (ctx->kq < 0)
		i_fatal("kqueue() in io_loop_handler_init() failed: %m");
	fd_close_on_exec(ctx->kq, TRUE);

	ctx->fds_size = INITIAL_BUF_SIZE;
	ctx->fds = p_new(ioloop->pool, struct fdrecord, ctx->fds_size);
}

void io_loop_handler_deinit(struct ioloop *ioloop)
{
	if (close(ioloop->handler_context->kq) < 0)
		i_error("close(kqueue) in io_loop_handler_deinit() failed: %m");
	p_free(ioloop->pool, ioloop->handler_context->evbuf);
	p_free(ioloop->pool, ioloop->handler_context->fds);
	p_free(ioloop->pool, ioloop->handler_context);
}

void io_loop_handle_add(struct ioloop *ioloop, struct io *io)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	const int fd = io->fd;
	struct kevent ev = { fd, 0, EV_ADD | EV_EOF, 0, 0, NULL };
	enum io_condition condition = io->condition & MASK;
	
	i_assert(io->callback != NULL);

	/* grow ctx->fds array if necessary */
	if ((size_t)fd >= ctx->fds_size) {
		size_t old_size = ctx->fds_size;

		ctx->fds_size = nearest_power((unsigned int)fd+1);
		i_assert(ctx->fds_size < (size_t)-1 / sizeof(int));

		ctx->fds = p_realloc(ioloop->pool, ctx->fds,
				     sizeof(struct fdrecord) * old_size,
				     sizeof(struct fdrecord) * ctx->fds_size);
		memset(ctx->fds + old_size, 0,
		       sizeof(struct fdrecord) * (ctx->fds_size - old_size));
	}

	if (condition & (IO_READ | IO_WRITE))
		ev.udata = io;
	if (condition & IO_ERROR)
		ctx->fds[fd].errio = io;

	if (condition & (IO_READ | IO_ERROR)) {
		ctx->fds[fd].mode |= condition;
		ev.filter = EVFILT_READ;
		if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0) {
			i_error("kevent(%d) in io_loop_handle_add() failed: %m",
				fd);
		}
	}
	if (condition & (IO_WRITE | IO_ERROR)) {
		ctx->fds[fd].mode |= condition;
		ev.filter = EVFILT_WRITE;
		if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0) {
			i_error("kevent(%d) in io_loop_handle_add() failed: %m",
				fd);
		}
	}
}

void io_loop_handle_remove(struct ioloop *ioloop, struct io *io)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	const int fd = io->fd;
	struct kevent ev = { fd, 0, EV_DELETE, 0, 0, NULL };
	struct fdrecord *const fds = ctx->fds;
	const enum io_condition condition = io->condition & MASK;

	i_assert((size_t)fd < ctx->fds_size);

	if (condition & IO_ERROR)
		fds[fd].errio = NULL;
	if (condition & (IO_READ | IO_ERROR)) {
		ev.filter = EVFILT_READ;
		fds[fd].mode &= ~condition;
		if ((fds[fd].mode & (IO_READ | IO_ERROR)) == 0) {
			if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0) {
				i_error("kevent(%d) in io_loop_handle_remove "
					"failed: %m", fd);
			}
		}
	}
	if (condition & (IO_WRITE | IO_ERROR)) {
		ev.filter = EVFILT_WRITE;
		fds[fd].mode &= ~condition;
		if ((fds[fd].mode & (IO_WRITE | IO_ERROR)) == 0) {
			if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0) {
				i_error("kevent(%d) in io_loop_handle_remove "
					"failed: %m", fd);
			}
		}
	}
}

void io_loop_handler_run(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	struct timeval tv;
	struct timespec ts;
	unsigned int t_id;
	int msecs, ret, i;

	/* get the time left for next timeout task */
	msecs = io_loop_get_wait_time(ioloop->timeouts, &tv, NULL);
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;

	/* wait for events */
	ret = kevent (ctx->kq, NULL, 0, ctx->evbuf, ctx->evbuf_size, &ts);
	if (ret < 0 && errno != EINTR)
		i_fatal("kevent(): %m");

	/* execute timeout handlers */
	io_loop_handle_timeouts(ioloop);

	if (ret <= 0 || !ioloop->running) {
		/* no I/O events */
		return;
	}

	i_assert((size_t)ret <= ctx->evbuf_size);

	/* loop through all received events */
	for (i = 0; i < ret; ++i) {
		struct io *io = ctx->evbuf[i].udata;

		i_assert(ctx->evbuf[i].ident < ctx->fds_size);
		if ((ctx->fds[ctx->evbuf[i].ident].mode & IO_ERROR) &&
		    (ctx->evbuf[i].flags & EV_EOF)) {
			struct io *errio = ctx->fds[ctx->evbuf[i].ident].errio;

			t_id = t_push();
			errio->callback(errio->context);
			if (t_pop() != t_id) {
				i_panic("Leaked a t_pop() call"
					" in I/O handler %p",
					(void *)errio->callback);
			}
		} else if (ctx->fds[ctx->evbuf[i].ident].mode
			 & (IO_WRITE | IO_READ)) {
			t_id = t_push();
			io->callback(io->context);
			if (t_pop() != t_id) {
				i_panic("Leaked a t_pop() call"
					" in I/O handler %p",
					(void *)io->callback);
			}
		} else
			i_panic("Unrecognized event");
	}
}

#endif
