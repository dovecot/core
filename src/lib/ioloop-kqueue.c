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

#include "lib.h"

#ifdef IOLOOP_KQUEUE

#include "array.h"
#include "fd-close-on-exec.h"
#include "ioloop-internal.h"
#include "ioloop-iolist.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

struct ioloop_handler_context {
	int kq;

	unsigned int deleted_count;
	array_t ARRAY_DEFINE(fd_index, struct io_list *);
	array_t ARRAY_DEFINE(events, struct kevent);
};

void io_loop_handler_init(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx;

	ioloop->handler_context = ctx =
		p_new(ioloop->pool, struct ioloop_handler_context, 1);

	ctx->kq = kqueue();
	if (ctx->kq < 0)
		i_fatal("kqueue() in io_loop_handler_init() failed: %m");
	fd_close_on_exec(ctx->kq, TRUE);

	ARRAY_CREATE(&ctx->events, ioloop->pool, struct kevent,
		     IOLOOP_INITIAL_FD_COUNT);
	ARRAY_CREATE(&ctx->fd_index, ioloop->pool,
		     struct io_list *, IOLOOP_INITIAL_FD_COUNT);
}

void io_loop_handler_deinit(struct ioloop *ioloop)
{
	if (close(ioloop->handler_context->kq) < 0)
		i_error("close(kqueue) in io_loop_handler_deinit() failed: %m");
	array_free(&ioloop->handler_context->fd_index);
	array_free(&ioloop->handler_context->events);
	p_free(ioloop->pool, ioloop->handler_context);
}

static int io_filter(struct io *io)
{
	int filter = 0;

	if ((io->condition & (IO_READ | IO_ERROR)) != 0)
		filter |= EVFILT_READ;
	if ((io->condition & (IO_WRITE | IO_ERROR)) != 0)
		filter |= EVFILT_WRITE;

	return filter;
}

static int io_list_filter(struct io_list *list)
{
	int filter = 0, i;
	struct io *io;

	for (i = 0; i < IOLOOP_IOLIST_IOS_PER_FD; i++) {
		io = list->ios[i];

		if (io == NULL)
			continue;

		if ((io->condition & (IO_READ | IO_ERROR)) != 0)
			filter |= EVFILT_READ;
		if ((io->condition & (IO_WRITE | IO_ERROR)) != 0)
			filter |= EVFILT_WRITE;
	}

	return filter;
}

void io_loop_handle_add(struct ioloop *ioloop, struct io *io)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	struct io_list **list;
	struct kevent ev;
	bool first;

	list = array_idx_modifyable(&ctx->fd_index, io->fd);
	if (*list == NULL)
		*list = p_new(ioloop->pool, struct io_list, 1);

	first = ioloop_iolist_add(*list, io);

	EV_SET(ev, io->fd, io_filter(io), EV_ADD, 0, 0, *list);
	if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0)
		i_fatal("kevent(EV_ADD, %d) failed: %m", io->fd);

	if (first) {
		/* allow kevent() to return the maximum number of events
		   by keeping space allocated for each file descriptor */
		if (ctx->deleted_count > 0)
			ctx->deleted_count--;
		else
			(void)array_append_space(&ctx->events);
	}
}

void io_loop_handle_remove(struct ioloop *ioloop, struct io *io)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	struct io_list **list;
	struct kevent ev;
	int filter;
	bool last;
	
	list = array_idx_modifyable(&ctx->fd_index, io->fd);
	last = ioloop_iolist_del(*list, io);

	filter = io_filter(io) & ~io_list_filter(*list);
	EV_SET(ev, io->fd, filter, EV_DELETE, 0, 0, *list);
	if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0)
		i_error("kevent(EV_DELETE, %d) failed: %m", io->fd);

	if (last) {
		/* since we're not freeing memory in any case, just increase
		   deleted counter so next handle_add() can just decrease it
		   insteading of appending to the events array */
		ctx->deleted_count++;
	}
}

void io_loop_handler_run(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	struct kevent *event;
	struct timeval tv;
	struct timespec ts;
	struct io_list *list;
	unsigned int events_count, t_id;
	int msecs, ret, i;
	bool call, called;

	/* get the time left for next timeout task */
	msecs = io_loop_get_wait_time(ioloop->timeouts, &tv, NULL);
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;

	/* wait for events */
	event = array_get_modifyable(&ctx->events, &events_count);
	ret = kevent (ctx->kq, NULL, 0, event, events_count, &ts);
	if (ret < 0 && errno != EINTR)
		i_fatal("kevent(): %m");

	/* execute timeout handlers */
	io_loop_handle_timeouts(ioloop);

	if (ret <= 0 || !ioloop->running) {
		/* no I/O events */
		return;
	}

	/* loop through all received events */
	while (ret-- > 0) {
		list = (void *)event->udata;

		called = FALSE;
		for (i = 0; i < IOLOOP_IOLIST_IOS_PER_FD; i++) {
			struct io *io = list->ios[i];
			if (io == NULL)
				continue;

			call = FALSE;
			if ((event->flags & EV_ERROR) != 0) {
				errno = event->data;
				i_error("kevent(): invalid fd %d callback "
					"%p: %m", io->fd, (void *)io->callback);
			} else if ((event->flags & EV_EOF) != 0)
				call = TRUE;
			else if ((io->condition & IO_READ) != 0)
				call = (event->filter & EVFILT_READ) != 0;
			else if ((io->condition & IO_WRITE) != 0)
				call = (event->filter & EVFILT_WRITE) != 0;

			if (call) {
				called = TRUE;
				t_id = t_push();
				io->callback(io->context);
				if (t_pop() != t_id) {
					i_panic("Leaked a t_pop() call in "
						"I/O handler %p",
						(void *)io->callback);
				}
			}
		}
		if (!called) {
			i_panic("Unrecognized event: kevent "
				"{.ident = %d,"
				" .filter = 0x%04x,"
				" .flags = 0x%04x,"
				" .fflags = 0x%08x,"
				" .data = 0x%08llx}, io filter = %x",
				event->ident,
				event->filter, event->flags,
				event->fflags, (unsigned long long)event->data,
				io_list_filter(list));
		}
		event++;
	}
}

#endif
