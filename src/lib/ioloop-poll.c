/*
 ioloop-poll.c : I/O loop handler using poll()

    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "lib.h"
#include "ioloop-internal.h"

#include <sys/poll.h>

#ifndef INITIAL_POLL_FDS
#  define INITIAL_POLL_FDS 128
#endif

struct _IOLoopHandlerData {
	unsigned int fds_size, fds_pos;
	struct pollfd *fds;

	unsigned int idx_size;
	int *fd_index;
};

void io_loop_handler_init(IOLoop ioloop)
{
	IOLoopHandlerData *data;

	ioloop->handler_data = data =
		p_new(ioloop->pool, IOLoopHandlerData, 1);
	data->fds_size = INITIAL_POLL_FDS;
	data->fds = p_new(ioloop->pool, struct pollfd, data->fds_size);

	data->idx_size = INITIAL_POLL_FDS;
	data->fd_index = p_new(ioloop->pool, int, data->idx_size);
        memset(data->fd_index, 0xff, sizeof(int) * data->idx_size);
}

void io_loop_handler_deinit(IOLoop ioloop)
{
        p_free(ioloop->pool, ioloop->handler_data->fds);
        p_free(ioloop->pool, ioloop->handler_data->fd_index);
        p_free(ioloop->pool, ioloop->handler_data);
}

#define IO_POLL_INPUT (POLLIN|POLLPRI|POLLERR|POLLHUP|POLLNVAL)
#define IO_POLL_OUTPUT (POLLOUT|POLLERR|POLLHUP|POLLNVAL)

void io_loop_handle_add(IOLoop ioloop, int fd, int condition)
{
	IOLoopHandlerData *data;
	int index, old_size;

        data = ioloop->handler_data;
	if ((unsigned int) fd >= data->idx_size) {
                /* grow the fd -> index array */
		old_size = data->idx_size;

		data->idx_size = nearest_power((unsigned int) fd+1);
		data->fd_index = p_realloc(ioloop->pool, data->fd_index,
					   sizeof(int) * data->idx_size);
		memset(data->fd_index + old_size, 0xff,
		       sizeof(int) * (data->idx_size-old_size));
	}

	if (data->fds_pos >= data->fds_size) {
		/* grow the fd array */
		data->fds_size = nearest_power(data->fds_size+1);
		data->fds = p_realloc(ioloop->pool, data->fds,
				      sizeof(struct pollfd) * data->fds_size);
	}

	if (data->fd_index[fd] != -1) {
		/* update existing pollfd */
                index = data->fd_index[fd];
	} else {
                /* add new pollfd */
                index = data->fds_pos++;

		data->fd_index[fd] = index;
		data->fds[index].fd = fd;
		data->fds[index].events = 0;
		data->fds[index].revents = 0;
	}

        if (condition & IO_READ)
		data->fds[index].events |= IO_POLL_INPUT;
        if (condition & IO_WRITE)
		data->fds[index].events |= IO_POLL_OUTPUT;
}

void io_loop_handle_remove(IOLoop ioloop, int fd, int condition)
{
	IOLoopHandlerData *data;
	int index;

        data = ioloop->handler_data;
	index = data->fd_index[fd];
	i_assert(index >= 0 && (unsigned int) index < data->fds_size);

	if (condition & IO_READ)
		data->fds[index].events &= ~(POLLIN|POLLPRI);
        if (condition & IO_WRITE)
		data->fds[index].events &= ~POLLOUT;

	if ((data->fds[index].events & (POLLIN|POLLOUT)) == 0) {
		/* remove the whole pollfd */
		data->fd_index[data->fds[index].fd] = -1;
		if (--data->fds_pos == (unsigned int) index)
                        return; /* removing last one */

                /* move the last pollfd over the removed one */
		data->fds[index] = data->fds[data->fds_pos];
		data->fd_index[data->fds[index].fd] = index;
	}
}

void io_loop_handler_run(IOLoop ioloop)
{
	IOLoopHandlerData *data;
        struct pollfd *pollfd;
        struct timeval tv;
	IO io, next;
	int msecs, ret, t_id;

        data = ioloop->handler_data;

        /* get the time left for next timeout task */
	msecs = io_loop_get_wait_time(ioloop->timeouts, &tv, NULL);

	ret = poll(data->fds, data->fds_pos, msecs);
	if (ret < 0 && errno != EINTR)
		i_warning("poll() : %m");

	/* execute timeout handlers */
        io_loop_handle_timeouts(ioloop);

	if (ret <= 0 || !ioloop->running) {
                /* no I/O events */
		return;
	}

	/* execute the I/O handlers in prioritized order */
	for (io = ioloop->ios; io != NULL && ret > 0; io = next) {
		next = io->next;

		if (io->destroyed) {
			/* we were destroyed, and io->fd points to
			   -1 now, so we can't know if there was any
			   revents left. */
			io_destroy(ioloop, io);
			continue;
		}

		i_assert(io->fd >= 0);

		pollfd = &data->fds[data->fd_index[io->fd]];
		if (pollfd->revents != 0)
			ret--;

		if (pollfd->revents == 0)
			continue;

		if (pollfd->revents & POLLNVAL) {
			if (!io->invalid) {
				io->invalid = TRUE;
				i_warning("invalid I/O fd %d, func %p",
					  io->fd, io->func);
			}

                        continue;
		}

		if ((io->condition &
		     (IO_READ|IO_WRITE)) == (IO_READ|IO_WRITE)) {
			pollfd->revents = 0;
		} else if (io->condition & IO_READ) {
			if ((pollfd->revents & IO_POLL_INPUT) == 0)
				continue;
                        pollfd->revents &= ~IO_POLL_INPUT;
		} else if (io->condition & IO_WRITE) {
			if ((pollfd->revents & IO_POLL_OUTPUT) == 0)
				continue;
                        pollfd->revents &= ~IO_POLL_OUTPUT;
		}

		t_id = t_push();
		io->func(io->user_data, io->fd, io);
		if (t_pop() != t_id)
			i_panic("Leaked a t_pop() call!");

		if (io->destroyed)
			io_destroy(ioloop, io);
	}
}
