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
#include "ioloop-internal.h"

#ifdef IOLOOP_EPOLL

#include <sys/epoll.h>
#include <unistd.h>

#define INITIAL_EPOLL_EVENTS	128

enum {
	EPOLL_LIST_INPUT,
	EPOLL_LIST_OUTPUT,

	EPOLL_IOS_PER_FD
};

struct ioloop_handler_data {
	int epfd;
	int events_size, events_pos;
	struct epoll_event *events;

	unsigned int idx_size;
	struct io_list **fd_index;
};

struct io_list {
	struct io *ios[EPOLL_IOS_PER_FD];
};

void io_loop_handler_init(struct ioloop *ioloop)
{
	struct ioloop_handler_data *data;

	ioloop->handler_data = data =
		p_new(ioloop->pool, struct ioloop_handler_data, 1);

	data->events_pos = 0;
	data->events_size = INITIAL_EPOLL_EVENTS;
	data->events = p_new(ioloop->pool, struct epoll_event,
			     data->events_size);

	data->idx_size = INITIAL_EPOLL_EVENTS;
	data->fd_index = p_new(ioloop->pool, struct io_list *, data->idx_size);

	data->epfd = epoll_create(INITIAL_EPOLL_EVENTS);
	if (data->epfd < 0)
		i_panic("epoll_create(): %m");
}

void io_loop_handler_deinit(struct ioloop *ioloop)
{
	struct ioloop_handler_data *data = ioloop->handler_data;

	close(data->epfd);
	p_free(ioloop->pool, ioloop->handler_data->events);
	p_free(ioloop->pool, ioloop->handler_data->fd_index);
	p_free(ioloop->pool, ioloop->handler_data);
}

#define IO_EPOLL_INPUT	(EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP)
#define IO_EPOLL_OUTPUT	(EPOLLOUT | EPOLLERR | EPOLLHUP)

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
	}

	return events;
}

static int iolist_add(struct io_list *list, struct io *io)
{
	if ((io->condition & IO_READ) != 0) {
		i_assert(list->ios[EPOLL_LIST_INPUT] == NULL);
		list->ios[EPOLL_LIST_INPUT] = io;
		return list->ios[EPOLL_LIST_OUTPUT] == NULL;
	}
	if ((io->condition & IO_WRITE) != 0) {
		i_assert(list->ios[EPOLL_LIST_OUTPUT] == NULL);
		list->ios[EPOLL_LIST_OUTPUT] = io;
		return list->ios[EPOLL_LIST_INPUT] == NULL;
	}

	i_unreached();
	return TRUE;
}

static int iolist_del(struct io_list *list, struct io *io)
{
	if (list->ios[EPOLL_LIST_INPUT] == io) {
		list->ios[EPOLL_LIST_INPUT] = NULL;
		return list->ios[EPOLL_LIST_OUTPUT] == NULL;
	}
	if (list->ios[EPOLL_LIST_OUTPUT] == io) {
		list->ios[EPOLL_LIST_OUTPUT] = NULL;
		return list->ios[EPOLL_LIST_INPUT] == NULL;
	}

	i_unreached();
	return TRUE;
}

void io_loop_handle_add(struct ioloop *ioloop, struct io *io)
{
	struct ioloop_handler_data *data = ioloop->handler_data;
	struct io_list *list;
	struct epoll_event event;
	int ret, first, op, fd = io->fd;

	list = data->fd_index[fd];
	if (list == NULL) {
		if ((unsigned int) fd >= data->idx_size) {
                	/* grow the fd -> iolist array */
			unsigned int old_size = data->idx_size;

			data->idx_size = nearest_power((unsigned int) fd+1);

			i_assert(data->idx_size < (size_t)-1 / sizeof(int));

			data->fd_index = p_realloc(ioloop->pool, data->fd_index,
						   sizeof(int) * old_size,
						   sizeof(int) * data->idx_size);
		}

		data->fd_index[fd] = list =
			p_new(ioloop->pool, struct io_list, 1);
	}

	first = iolist_add(list, io);

	event.data.ptr = list;
	event.events = epoll_event_mask(list);

	op = first ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;

	ret = epoll_ctl(data->epfd, op, fd, &event);
	if (ret < 0)
		i_panic("epoll_ctl(): %m");

	if (data->events_pos >= data->events_size) {
		data->events_size = nearest_power(data->events_size + 1);

		p_free(ioloop->pool, data->events);
		data->events = p_new(ioloop->pool, struct epoll_event,
				     data->events_size);
	}

	data->events_pos++;
}

void io_loop_handle_remove(struct ioloop *ioloop, struct io *io)
{
	struct ioloop_handler_data *data = ioloop->handler_data;
	struct io_list *list = data->fd_index[io->fd];
	struct epoll_event event;
	int ret, last, op;

	last = iolist_del(list, io);

	event.data.ptr = list;
	event.events = epoll_event_mask(list);

	op = last ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;

	ret = epoll_ctl(data->epfd, op, io->fd, &event);
	if (ret < 0 && errno != EBADF)
		i_fatal("epoll_ctl(): %m");

	data->events_pos--;
}

void io_loop_handler_run(struct ioloop *ioloop)
{
	struct ioloop_handler_data *data = ioloop->handler_data;
	struct epoll_event *event;
	struct io_list *list;
	struct io *io;
	struct timeval tv;
	unsigned int t_id;
	int msecs, ret, i, call;

        /* get the time left for next timeout task */
	msecs = io_loop_get_wait_time(ioloop->timeouts, &tv, NULL);

	ret = epoll_wait(data->epfd, data->events, data->events_size, msecs);
	if (ret < 0 && errno != EINTR)
		i_fatal("epoll_wait(): %m");

	/* execute timeout handlers */
        io_loop_handle_timeouts(ioloop);

	if (ret <= 0 || !ioloop->running) {
		/* No events */
		return;
	}

	event = data->events;
	while (ret-- > 0) {
		list = event->data.ptr;

		for (i = 0; i < EPOLL_IOS_PER_FD; i++) {
			io = list->ios[i];
			if (io == NULL)
				continue;

			call = FALSE;
			if ((event->events & (EPOLLHUP | EPOLLERR)) != 0) {
				call = TRUE;
			} else if ((io->condition & IO_READ) != 0) {
				call = event->events & EPOLLIN;
			} else if ((io->condition & IO_WRITE) != 0) {
				call = event->events & EPOLLOUT;
			}

			if (call) {
				t_id = t_push();
				io->callback(io->context);
				if (t_pop() != t_id)
					i_panic("Leaked a t_pop() call!");
			}
		}
		event++;
	}
}

#endif	/* IOLOOP_EPOLL */
