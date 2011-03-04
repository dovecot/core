/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "ioloop-internal.h"

#ifdef IOLOOP_POLL

#include <fcntl.h>
#include <sys/poll.h>

struct ioloop_handler_context {
	unsigned int fds_count, fds_pos;
	struct pollfd *fds;

	unsigned int idx_count;
	int *fd_index;
};

void io_loop_handler_init(struct ioloop *ioloop, unsigned int initial_fd_count)
{
	struct ioloop_handler_context *ctx;

	ioloop->handler_context = ctx = i_new(struct ioloop_handler_context, 1);
	ctx->fds_count = initial_fd_count;
	ctx->fds = i_new(struct pollfd, ctx->fds_count);

	ctx->idx_count = initial_fd_count;
	ctx->fd_index = i_new(int, ctx->idx_count);
        memset(ctx->fd_index, 0xff, sizeof(int) * ctx->idx_count);
}

void io_loop_handler_deinit(struct ioloop *ioloop)
{
        i_free(ioloop->handler_context->fds);
        i_free(ioloop->handler_context->fd_index);
        i_free(ioloop->handler_context);
}

#define IO_POLL_ERROR (POLLERR | POLLHUP | POLLNVAL)
#define IO_POLL_INPUT (POLLIN | POLLPRI | IO_POLL_ERROR)
#define IO_POLL_OUTPUT (POLLOUT | IO_POLL_ERROR)

void io_loop_handle_add(struct io_file *io)
{
	struct ioloop_handler_context *ctx = io->io.ioloop->handler_context;
	enum io_condition condition = io->io.condition;
	unsigned int old_count;
	int index, old_events, fd = io->fd;

	if ((unsigned int)fd >= ctx->idx_count) {
                /* grow the fd -> index array */
		old_count = ctx->idx_count;

		ctx->idx_count = nearest_power((unsigned int) fd+1);

		ctx->fd_index = i_realloc(ctx->fd_index,
					  sizeof(int) * old_count,
					  sizeof(int) * ctx->idx_count);
		memset(ctx->fd_index + old_count, 0xff,
		       sizeof(int) * (ctx->idx_count-old_count));
	}

	if (ctx->fds_pos >= ctx->fds_count) {
		/* grow the fd array */
		old_count = ctx->fds_count;

		ctx->fds_count = nearest_power(ctx->fds_count+1);

		ctx->fds = i_realloc(ctx->fds,
				     sizeof(struct pollfd) * old_count,
				     sizeof(struct pollfd) * ctx->fds_count);
	}

	if (ctx->fd_index[fd] != -1) {
		/* update existing pollfd */
                index = ctx->fd_index[fd];
	} else {
                /* add new pollfd */
                index = ctx->fds_pos++;

		ctx->fd_index[fd] = index;
		ctx->fds[index].fd = fd;
		ctx->fds[index].events = 0;
		ctx->fds[index].revents = 0;
	}

	old_events = ctx->fds[index].events;
	if (condition & IO_READ)
		ctx->fds[index].events |= IO_POLL_INPUT;
        if (condition & IO_WRITE)
		ctx->fds[index].events |= IO_POLL_OUTPUT;
	if (condition & IO_ERROR)
		ctx->fds[index].events |= IO_POLL_ERROR;
	i_assert(ctx->fds[index].events != old_events);
}

void io_loop_handle_remove(struct io_file *io, bool closed ATTR_UNUSED)
{
	struct ioloop_handler_context *ctx = io->io.ioloop->handler_context;
	enum io_condition condition = io->io.condition;
	int index, fd = io->fd;

	index = ctx->fd_index[fd];
	i_assert(index >= 0 && (unsigned int) index < ctx->fds_count);

#ifdef DEBUG
	if (!closed) {
		/* io_remove() is required to be called before fd is closed.
		   This is required by epoll/kqueue, but since poll is more
		   commonly used while developing, this check here should catch
		   the error early enough not to cause problems for kqueue
		   users. */
		if (fcntl(io->fd, F_GETFD, 0) < 0) {
			if (errno == EBADF)
				i_panic("io_remove(%d) called too late", io->fd);
			else
				i_error("fcntl(%d, F_GETFD) failed: %m", io->fd);
		}
	}
#endif
	i_free(io);

	if (condition & IO_READ) {
		ctx->fds[index].events &= ~(POLLIN|POLLPRI);
		ctx->fds[index].revents &= ~(POLLIN|POLLPRI);
	}
	if (condition & IO_WRITE) {
		ctx->fds[index].events &= ~POLLOUT;
		ctx->fds[index].revents &= ~POLLOUT;
	}

	if ((ctx->fds[index].events & (POLLIN|POLLOUT)) == 0) {
		/* remove the whole pollfd */
		ctx->fd_index[ctx->fds[index].fd] = -1;
		if (--ctx->fds_pos == (unsigned int) index)
                        return; /* removing last one */

                /* move the last pollfd over the removed one */
		ctx->fds[index] = ctx->fds[ctx->fds_pos];
		ctx->fd_index[ctx->fds[index].fd] = index;
	}
}

void io_loop_handler_run(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
        struct pollfd *pollfd;
        struct timeval tv;
	struct io_file *io;
	int msecs, ret;
	bool call;

        /* get the time left for next timeout task */
	msecs = io_loop_get_wait_time(ioloop, &tv);
#ifdef _AIX
	if (msecs > 1000) {
		/* AIX seems to check IO_POLL_ERRORs only at the beginning of
		   the poll() call, not during it. keep timeouts short enough
		   so that we'll notice them pretty quickly. */
		msecs = 1000;
	}
#endif

	ret = poll(ctx->fds, ctx->fds_pos, msecs);
	if (ret < 0 && errno != EINTR)
		i_fatal("poll(): %m");

	/* execute timeout handlers */
        io_loop_handle_timeouts(ioloop);

	if (ret <= 0 || !ioloop->running) {
                /* no I/O events */
		return;
	}

	io = ioloop->io_files;
	for (; io != NULL && ret > 0; io = ioloop->next_io_file) {
		ioloop->next_io_file = io->next;

		pollfd = &ctx->fds[ctx->fd_index[io->fd]];
		if (pollfd->revents != 0) {
			if (pollfd->revents & POLLNVAL) {
				i_error("invalid I/O fd %d, callback %p",
					io->fd, (void *) io->io.callback);
				pollfd->events = 0;
				pollfd->revents = 0;
				call = TRUE;
			} else if ((io->io.condition &
				    (IO_READ|IO_WRITE)) == (IO_READ|IO_WRITE)) {
				call = TRUE;
				pollfd->revents = 0;
			} else if (io->io.condition & IO_READ) {
				call = (pollfd->revents & IO_POLL_INPUT) != 0;
				pollfd->revents &= ~IO_POLL_INPUT;
			} else if (io->io.condition & IO_WRITE) {
				call = (pollfd->revents & IO_POLL_OUTPUT) != 0;
				pollfd->revents &= ~IO_POLL_OUTPUT;
			} else if (io->io.condition & IO_ERROR) {
				call = (pollfd->revents & IO_POLL_ERROR) != 0;
				pollfd->revents &= ~IO_POLL_ERROR;
			} else {
				call = FALSE;
			}

			if (pollfd->revents == 0)
				ret--;

			if (call)
				io_loop_call_io(&io->io);
		}
	}
}

#endif
