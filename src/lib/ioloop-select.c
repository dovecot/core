/*
 ioloop-select.c : I/O loop handler using select()

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

#include <sys/types.h>
#include <unistd.h>

struct _IOLoopHandlerData {
	fd_set read_fds, write_fds;
};

static fd_set tmp_read_fds, tmp_write_fds;

void io_loop_handler_init(IOLoop ioloop)
{
	ioloop->handler_data = p_new(ioloop->pool, IOLoopHandlerData, 1);
        FD_ZERO(&ioloop->handler_data->read_fds);
	FD_ZERO(&ioloop->handler_data->write_fds);
}

void io_loop_handler_deinit(IOLoop ioloop)
{
        p_free(ioloop->pool, ioloop->handler_data);
}

void io_loop_handle_add(IOLoop ioloop, int fd, int condition)
{
        if (condition & IO_READ)
		FD_SET(fd, &ioloop->handler_data->read_fds);
        if (condition & IO_WRITE)
		FD_SET(fd, &ioloop->handler_data->write_fds);
}

void io_loop_handle_remove(IOLoop ioloop, int fd, int condition)
{
        if (condition & IO_READ)
		FD_CLR(fd, &ioloop->handler_data->read_fds);
        if (condition & IO_WRITE)
		FD_CLR(fd, &ioloop->handler_data->write_fds);
}

#define io_check_condition(fd, condition) \
	((((condition) & IO_READ) && \
	  FD_ISSET((fd), &tmp_read_fds)) || \
	 (((condition) & IO_WRITE) && \
	  FD_ISSET((fd), &tmp_write_fds)))

void io_loop_handler_run(IOLoop ioloop)
{
	struct timeval tv;
	IO io, next;
        unsigned int t_id;
	int ret, fd, condition, destroyed;

	/* get the time left for next timeout task */
	io_loop_get_wait_time(ioloop->timeouts, &tv, NULL);

        memcpy(&tmp_read_fds, &ioloop->handler_data->read_fds, sizeof(fd_set));
	memcpy(&tmp_write_fds, &ioloop->handler_data->write_fds,
	       sizeof(fd_set));

	ret = select(ioloop->highest_fd + 1, &tmp_read_fds, &tmp_write_fds,
		     NULL, &tv);
	if (ret < 0 && errno != EINTR)
		i_warning("select() : %m");

	/* execute timeout handlers */
        io_loop_handle_timeouts(ioloop);

	if (ret <= 0 || !ioloop->running) {
                /* no I/O events */
		return;
	}

	/* execute the I/O handlers in prioritized order */
	for (io = ioloop->ios; io != NULL; io = next) {
		next = io->next;

		fd = io->fd;
		condition = io->condition;

		destroyed = io->destroyed;
		if (destroyed)
			io_destroy(ioloop, io);

		if (!io_check_condition(fd, condition))
                        continue;

		if (!destroyed) {
			t_id = t_push();
			io->func(io->context, io->fd, io);
			if (t_pop() != t_id)
				i_panic("Leaked a t_pop() call!");
		}

		if (--ret == 0)
                        break;
	}
}
