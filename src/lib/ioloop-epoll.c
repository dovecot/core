/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop-private.h"
#include "ioloop-iolist.h"

#ifdef IOLOOP_EPOLL

#include <sys/epoll.h>
#include <unistd.h>

struct ioloop_handler_context {
	int epfd;

	unsigned int deleted_count;
	ARRAY(struct io_list *) fd_index;
	ARRAY(struct epoll_event) events;
};

void io_loop_handler_init(struct ioloop *ioloop, unsigned int initial_fd_count)
{
	struct ioloop_handler_context *ctx;

	ioloop->handler_context = ctx = i_new(struct ioloop_handler_context, 1);

	i_array_init(&ctx->events, initial_fd_count);
	i_array_init(&ctx->fd_index, initial_fd_count);

	ctx->epfd = epoll_create(initial_fd_count);
	if (ctx->epfd < 0) {
		if (errno != EMFILE)
			i_fatal("epoll_create(): %m");
		else {
			i_fatal("epoll_create(): %m (you may need to increase "
				"/proc/sys/fs/epoll/max_user_instances)");
		}
	}
	fd_close_on_exec(ctx->epfd, TRUE);
}

void io_loop_handler_deinit(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	struct io_list **list;
	unsigned int i, count;

	list = array_get_modifiable(&ctx->fd_index, &count);
	for (i = 0; i < count; i++)
		i_free(list[i]);

	if (close(ctx->epfd) < 0)
		i_error("close(epoll) failed: %m");
	array_free(&ioloop->handler_context->fd_index);
	array_free(&ioloop->handler_context->events);
	i_free(ioloop->handler_context);
}

#define IO_EPOLL_ERROR (EPOLLERR | EPOLLHUP)
#define IO_EPOLL_INPUT (EPOLLIN | EPOLLPRI | IO_EPOLL_ERROR)
#define IO_EPOLL_OUTPUT	(EPOLLOUT | IO_EPOLL_ERROR)

static int epoll_event_mask(struct io_list *list)
{
	int events = 0, i;
	struct io_file *io;

	for (i = 0; i < IOLOOP_IOLIST_IOS_PER_FD; i++) {
		io = list->ios[i];

		if (io == NULL)
			continue;

		if ((io->io.condition & IO_READ) != 0)
			events |= IO_EPOLL_INPUT;
		if ((io->io.condition & IO_WRITE) != 0)
			events |= IO_EPOLL_OUTPUT;
		if ((io->io.condition & IO_ERROR) != 0)
			events |= IO_EPOLL_ERROR;
	}

	return events;
}

void io_loop_handle_add(struct io_file *io)
{
	struct ioloop_handler_context *ctx = io->io.ioloop->handler_context;
	struct io_list **list;
	struct epoll_event event;
	int op;
	bool first;

	list = array_idx_get_space(&ctx->fd_index, io->fd);
	if (*list == NULL)
		*list = i_new(struct io_list, 1);

	first = ioloop_iolist_add(*list, io);

	i_zero(&event);
	event.data.ptr = *list;
	event.events = epoll_event_mask(*list);

	op = first ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;

	if (epoll_ctl(ctx->epfd, op, io->fd, &event) < 0) {
		if (errno == EPERM && op == EPOLL_CTL_ADD) {
			i_panic("epoll_ctl(add, %d) failed: %m "
				"(fd doesn't support epoll%s)", io->fd,
				io->fd != STDIN_FILENO ? "" :
				" - instead of '<file', try 'cat file|'");
		}
		i_panic("epoll_ctl(%s, %d) failed: %m",
			op == EPOLL_CTL_ADD ? "add" : "mod", io->fd);
	}

	if (first) {
		/* allow epoll_wait() to return the maximum number of events
		   by keeping space allocated for each file descriptor */
		if (ctx->deleted_count > 0)
			ctx->deleted_count--;
		else
			array_append_zero(&ctx->events);
	}
}

void io_loop_handle_remove(struct io_file *io, bool closed)
{
	struct ioloop_handler_context *ctx = io->io.ioloop->handler_context;
	struct io_list **list;
	struct epoll_event event;
	int op;
	bool last;

	list = array_idx_modifiable(&ctx->fd_index, io->fd);
	last = ioloop_iolist_del(*list, io);

	if (!closed) {
		i_zero(&event);
		event.data.ptr = *list;
		event.events = epoll_event_mask(*list);

		op = last ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;

		if (epoll_ctl(ctx->epfd, op, io->fd, &event) < 0) {
			const char *errstr = t_strdup_printf(
				"epoll_ctl(%s, %d) failed: %m",
				op == EPOLL_CTL_DEL ? "del" : "mod", io->fd);
			if (errno == EBADF)
				i_panic("%s", errstr);
			else
				i_error("%s", errstr);
		}
	}
	if (last) {
		/* since we're not freeing memory in any case, just increase
		   deleted counter so next handle_add() can just decrease it
		   instead of appending to the events array */
		ctx->deleted_count++;
	}
	i_free(io);
}

void io_loop_handler_run_internal(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	struct epoll_event *events;
	const struct epoll_event *event;
	struct io_list *list;
	struct io_file *io;
	struct timeval tv;
	unsigned int events_count;
	int msecs, ret, i, j;
	bool call;

	i_assert(ctx != NULL);

        /* get the time left for next timeout task */
	msecs = io_loop_run_get_wait_time(ioloop, &tv);

	events = array_get_modifiable(&ctx->events, &events_count);
	if (ioloop->io_files != NULL && events_count > ctx->deleted_count) {
		ret = epoll_wait(ctx->epfd, events, events_count, msecs);
		if (ret < 0 && errno != EINTR)
			i_fatal("epoll_wait(): %m");
	} else {
		/* no I/Os, but we should have some timeouts.
		   just wait for them. */
		if (msecs < 0)
			i_panic("BUG: No IOs or timeouts set. Not waiting for infinity.");
		usleep(msecs*1000);
		ret = 0;
	}

	/* execute timeout handlers */
        io_loop_handle_timeouts(ioloop);

	if (!ioloop->running)
		return;

	for (i = 0; i < ret; i++) {
		/* io_loop_handle_add() may cause events array reallocation,
		   so we have use array_idx() */
		event = array_idx(&ctx->events, i);
		list = event->data.ptr;

		for (j = 0; j < IOLOOP_IOLIST_IOS_PER_FD; j++) {
			io = list->ios[j];
			if (io == NULL)
				continue;

			call = FALSE;
			if ((event->events & (EPOLLHUP | EPOLLERR)) != 0)
				call = TRUE;
			else if ((io->io.condition & IO_READ) != 0)
				call = (event->events & EPOLLIN) != 0;
			else if ((io->io.condition & IO_WRITE) != 0)
				call = (event->events & EPOLLOUT) != 0;
			else if ((io->io.condition & IO_ERROR) != 0)
				call = (event->events & IO_EPOLL_ERROR) != 0;

			if (call) {
				io_loop_call_io(&io->io);
				if (!ioloop->running)
					return;
			}
		}
	}
}

#endif	/* IOLOOP_EPOLL */
