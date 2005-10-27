/*
 * Linux epoll() based ioloop handler.
 *
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published 
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* @UNSAFE: whole file */

#include "lib.h"
#include "array.h"
#include "fd-close-on-exec.h"
#include "ioloop-internal.h"

#ifdef IOLOOP_EPOLL

#include <sys/epoll.h>
#include <unistd.h>

#define INITIAL_EPOLL_EVENTS	128

enum {
	EPOLL_LIST_INPUT,
	EPOLL_LIST_OUTPUT,
	EPOLL_LIST_ERROR,

	EPOLL_IOS_PER_FD
};

struct ioloop_handler_context {
	int epfd;
	int events_size, events_pos;
	struct epoll_event *events;

	unsigned int idx_size;
	array_t ARRAY_DEFINE(fd_index, struct io_list *);
};

struct io_list {
	struct io *ios[EPOLL_IOS_PER_FD];
};

void io_loop_handler_init(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx;

	ioloop->handler_context = ctx =
		p_new(ioloop->pool, struct ioloop_handler_context, 1);

	ctx->events_pos = 0;
	ctx->events_size = INITIAL_EPOLL_EVENTS;
	ctx->events = p_new(ioloop->pool, struct epoll_event,
			    ctx->events_size);

	ctx->idx_size = INITIAL_EPOLL_EVENTS;
	ARRAY_CREATE(&ctx->fd_index, ioloop->pool,
		     struct io_list *, ctx->idx_size);

	ctx->epfd = epoll_create(INITIAL_EPOLL_EVENTS);
	if (ctx->epfd < 0)
		i_fatal("epoll_create(): %m");
	fd_close_on_exec(ctx->epfd, TRUE);
}

void io_loop_handler_deinit(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;

	if (close(ctx->epfd) < 0)
		i_error("close(epoll) failed: %m");
	array_free(&ioloop->handler_context->fd_index);
	p_free(ioloop->pool, ioloop->handler_context->events);
	p_free(ioloop->pool, ioloop->handler_context);
}

#define IO_EPOLL_ERROR (EPOLLERR | EPOLLHUP)
#define IO_EPOLL_INPUT (EPOLLIN | EPOLLPRI | IO_EPOLL_ERROR)
#define IO_EPOLL_OUTPUT	(EPOLLOUT | IO_EPOLL_ERROR)

static int epoll_event_mask(struct io_list *list)
{
	int events = 0, i;
	struct io *io;

	for (i = 0; i < EPOLL_IOS_PER_FD; i++) {
		io = list->ios[i];

		if (io == NULL)
			continue;

		if (io->condition & IO_READ)
			events |= IO_EPOLL_INPUT;
		if (io->condition & IO_WRITE)
			events |= IO_EPOLL_OUTPUT;
		if (io->condition & IO_ERROR)
			events |= IO_EPOLL_ERROR;
	}

	return events;
}

static int iolist_add(struct io_list *list, struct io *io)
{
	int i, idx;

	if ((io->condition & IO_READ) != 0)
		idx = EPOLL_LIST_INPUT;
	else if ((io->condition & IO_WRITE) != 0)
		idx = EPOLL_LIST_OUTPUT;
	else if ((io->condition & IO_ERROR) != 0)
		idx = EPOLL_LIST_ERROR;
	else {
		i_unreached();
	}

	i_assert(list->ios[idx] == NULL);
	list->ios[idx] = io;

	/* check if this was the first one */
	for (i = 0; i < EPOLL_IOS_PER_FD; i++) {
		if (i != idx && list->ios[i] != NULL)
			return FALSE;
	}

	return TRUE;
}

static int iolist_del(struct io_list *list, struct io *io)
{
	int i, last = TRUE;

	for (i = 0; i < EPOLL_IOS_PER_FD; i++) {
		if (list->ios[i] != NULL) {
			if (list->ios[i] == io)
				list->ios[i] = NULL;
			else
				last = TRUE;
		}
	}
	return last;
}

void io_loop_handle_add(struct ioloop *ioloop, struct io *io)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	struct io_list **list;
	struct epoll_event event;
	int ret, first, op, fd = io->fd;

	list = array_idx_modifyable(&ctx->fd_index, fd);
	if (*list == NULL)
		*list = p_new(ioloop->pool, struct io_list, 1);

	first = iolist_add(*list, io);

	event.data.ptr = *list;
	event.events = epoll_event_mask(*list);

	op = first ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;

	ret = epoll_ctl(ctx->epfd, op, fd, &event);
	if (ret < 0)
		i_fatal("epoll_ctl(%d): %m", op);

	if (ctx->events_pos >= ctx->events_size) {
		ctx->events_size = nearest_power(ctx->events_size + 1);

		p_free(ioloop->pool, ctx->events);
		ctx->events = p_new(ioloop->pool, struct epoll_event,
				    ctx->events_size);
	}

	ctx->events_pos++;
}

void io_loop_handle_remove(struct ioloop *ioloop, struct io *io)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	struct io_list **list;
	struct epoll_event event;
	int ret, last, op;

	list = array_idx_modifyable(&ctx->fd_index, io->fd);
	last = iolist_del(*list, io);

	event.data.ptr = *list;
	event.events = epoll_event_mask(*list);

	op = last ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;

	ret = epoll_ctl(ctx->epfd, op, io->fd, &event);
	if (ret < 0 && errno != EBADF)
		i_fatal("epoll_ctl(%d): %m", op);

	ctx->events_pos--;
}

void io_loop_handler_run(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	struct epoll_event *event;
	struct io_list *list;
	struct io *io;
	struct timeval tv;
	unsigned int t_id;
	int msecs, ret, i, call;

        /* get the time left for next timeout task */
	msecs = io_loop_get_wait_time(ioloop->timeouts, &tv, NULL);

	ret = epoll_wait(ctx->epfd, ctx->events, ctx->events_size, msecs);
	if (ret < 0 && errno != EINTR)
		i_fatal("epoll_wait(): %m");

	/* execute timeout handlers */
        io_loop_handle_timeouts(ioloop);

	if (ret <= 0 || !ioloop->running) {
		/* No events */
		return;
	}

	event = ctx->events;
	while (ret-- > 0) {
		list = event->data.ptr;

		for (i = 0; i < EPOLL_IOS_PER_FD; i++) {
			io = list->ios[i];
			if (io == NULL)
				continue;

			call = FALSE;
			if ((event->events & (EPOLLHUP | EPOLLERR)) != 0)
				call = TRUE;
			else if ((io->condition & IO_READ) != 0)
				call = (event->events & EPOLLIN) != 0;
			else if ((io->condition & IO_WRITE) != 0)
				call = (event->events & EPOLLOUT) != 0;
			else if ((io->condition & IO_ERROR) != 0)
				call = (event->events & IO_EPOLL_ERROR) != 0;

			if (call) {
				t_id = t_push();
				io->callback(io->context);
				if (t_pop() != t_id) {
					i_panic("Leaked a t_pop() call in "
						"I/O handler %p",
						(void *)io->callback);
				}
			}
		}
		event++;
	}
}

#endif	/* IOLOOP_EPOLL */
