/* Copyright (c) 2002-2003 Timo Sirainen */

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

static void update_highest_fd(struct ioloop *ioloop)
{
        struct io *io;
	int max_highest_fd;

        max_highest_fd = ioloop->highest_fd-1;
	ioloop->highest_fd = -1;

	for (io = ioloop->ios; io != NULL; io = io->next) {
		if (!io->destroyed && io->fd > ioloop->highest_fd) {
			ioloop->highest_fd = io->fd;

			if (ioloop->highest_fd == max_highest_fd)
                                break;
		}
	}
}

void io_loop_handler_init(struct ioloop *ioloop)
{
	ioloop->highest_fd = -1;
	ioloop->handler_data =
		p_new(ioloop->pool, struct ioloop_handler_data, 1);
        FD_ZERO(&ioloop->handler_data->read_fds);
	FD_ZERO(&ioloop->handler_data->write_fds);
}

void io_loop_handler_deinit(struct ioloop *ioloop)
{
        p_free(ioloop->pool, ioloop->handler_data);
}

void io_loop_handle_add(struct ioloop *ioloop, struct io *io)
{
	enum io_condition condition = io->condition;
	int fd = io->fd;

	i_assert(fd >= 0);

	if (fd >= FD_SETSIZE)
		i_fatal("fd %d too large for select()", fd);

        if (condition & IO_READ)
		FD_SET(fd, &ioloop->handler_data->read_fds);
        if (condition & IO_WRITE)
		FD_SET(fd, &ioloop->handler_data->write_fds);

	if (io->fd > ioloop->highest_fd)
		ioloop->highest_fd = io->fd;
}

void io_loop_handle_remove(struct ioloop *ioloop, struct io *io)
{
	enum io_condition condition = io->condition;
	int fd = io->fd;

	i_assert(fd >= 0 && fd < FD_SETSIZE);

        if (condition & IO_READ)
		FD_CLR(fd, &ioloop->handler_data->read_fds);
        if (condition & IO_WRITE)
		FD_CLR(fd, &ioloop->handler_data->write_fds);

	/* check if we removed the highest fd */
	if (io->fd == ioloop->highest_fd)
		update_highest_fd(ioloop);
}

#define io_check_condition(fd, condition) \
	((((condition) & IO_READ) && FD_ISSET((fd), &tmp_read_fds)) || \
	 (((condition) & IO_WRITE) && FD_ISSET((fd), &tmp_write_fds)))

void io_loop_handler_run(struct ioloop *ioloop)
{
	struct timeval tv;
	struct io *io, **io_p;
	unsigned int t_id;
	int ret;

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

		if (io_check_condition(io->fd, io->condition)) {
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
