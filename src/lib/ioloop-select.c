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

#ifdef IOLOOP_SELECT

#ifdef HAVE_SYS_SELECT_H
#  include <sys/select.h> /* According to POSIX 1003.1-2001 */
#endif
#include <sys/time.h>
#include <unistd.h>

struct ioloop_handler_data {
	fd_set read_fds, write_fds;
};

static fd_set tmp_read_fds, tmp_write_fds;

void io_loop_handler_init(struct ioloop *ioloop)
{
	ioloop->handler_data =
		p_new(ioloop->pool, struct ioloop_handler_data, 1);
        FD_ZERO(&ioloop->handler_data->read_fds);
	FD_ZERO(&ioloop->handler_data->write_fds);
}

void io_loop_handler_deinit(struct ioloop *ioloop)
{
        p_free(ioloop->pool, ioloop->handler_data);
}

void io_loop_handle_add(struct ioloop *ioloop, int fd, int condition)
{
	i_assert(fd >= 0);

	if (fd >= FD_SETSIZE)
		i_fatal("fd %d too large for select()", fd);

        if (condition & IO_READ)
		FD_SET(fd, &ioloop->handler_data->read_fds);
        if (condition & IO_WRITE)
		FD_SET(fd, &ioloop->handler_data->write_fds);
}

void io_loop_handle_remove(struct ioloop *ioloop, int fd, int condition)
{
	i_assert(fd >= 0 && fd < FD_SETSIZE);

        if (condition & IO_READ)
		FD_CLR(fd, &ioloop->handler_data->read_fds);
        if (condition & IO_WRITE)
		FD_CLR(fd, &ioloop->handler_data->write_fds);
}

#define io_check_condition(fd, condition) \
	((((condition) & IO_READ) && FD_ISSET((fd), &tmp_read_fds)) || \
	 (((condition) & IO_WRITE) && FD_ISSET((fd), &tmp_write_fds)))

void io_loop_handler_run(struct ioloop *ioloop)
{
	struct timeval tv;
	struct io *io, **io_p;
        unsigned int t_id;
	int ret, fd, condition;

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

	io_p = &ioloop->ios;
	for (io = ioloop->ios; io != NULL && ret > 0; io = *io_p) {
		if (io->destroyed) {
			/* we were destroyed, and io->fd points to -1 now. */
			io_destroy(ioloop, io_p);
			continue;
		}

		i_assert(io->fd >= 0);

		fd = io->fd;
		condition = io->condition;

		if (io_check_condition(fd, condition)) {
			ret--;

			t_id = t_push();
			io->callback(io->context);
			if (t_pop() != t_id)
				i_panic("Leaked a t_pop() call!");

			if (io->destroyed) {
				io_destroy(ioloop, io_p);
				continue;
			}
		}

		io_p = &io->next;
	}
}

#endif
