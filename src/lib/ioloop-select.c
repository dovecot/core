/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop-internal.h"

#ifdef IOLOOP_SELECT

#ifdef HAVE_SYS_SELECT_H
#  include <sys/select.h> /* According to POSIX 1003.1-2001 */
#endif
#include <sys/time.h>
#include <unistd.h>

struct ioloop_handler_context {
	int highest_fd;
	fd_set read_fds, write_fds, except_fds;
	fd_set tmp_read_fds, tmp_write_fds, tmp_except_fds;
};

static void update_highest_fd(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
        struct io_file *io;
	int max_highest_fd;

        max_highest_fd = ctx->highest_fd-1;
	ctx->highest_fd = -1;

	for (io = ioloop->io_files; io != NULL; io = io->next) {
		if (io->fd <= ctx->highest_fd)
			continue;

		ctx->highest_fd = io->fd;

		if (ctx->highest_fd == max_highest_fd)
			break;
	}
}

void io_loop_handler_init(struct ioloop *ioloop,
			  unsigned int initial_fd_count ATTR_UNUSED)
{
	struct ioloop_handler_context *ctx;

	ioloop->handler_context = ctx = i_new(struct ioloop_handler_context, 1);
	ctx->highest_fd = -1;
        FD_ZERO(&ctx->read_fds);
	FD_ZERO(&ctx->write_fds);
	FD_ZERO(&ctx->except_fds);
}

void io_loop_handler_deinit(struct ioloop *ioloop)
{
        i_free(ioloop->handler_context);
}

void io_loop_handle_add(struct io_file *io)
{
	struct ioloop_handler_context *ctx = io->io.ioloop->handler_context;
	enum io_condition condition = io->io.condition;
	int fd = io->fd;

	i_assert(fd >= 0);

	if (fd >= FD_SETSIZE)
		i_fatal("fd %d too large for select()", fd);

        if ((condition & (IO_READ | IO_ERROR)) != 0)
		FD_SET(fd, &ctx->read_fds);
        if ((condition & IO_WRITE) != 0)
		FD_SET(fd, &ctx->write_fds);
	FD_SET(fd, &ctx->except_fds);

	if (io->fd > ctx->highest_fd)
		ctx->highest_fd = io->fd;
}

void io_loop_handle_remove(struct io_file *io, bool closed ATTR_UNUSED)
{
	struct ioloop_handler_context *ctx = io->io.ioloop->handler_context;
	enum io_condition condition = io->io.condition;
	int fd = io->fd;

	i_assert(fd >= 0 && fd < FD_SETSIZE);

	if ((condition & (IO_READ | IO_ERROR)) != 0)
		FD_CLR(fd, &ctx->read_fds);
        if ((condition & IO_WRITE) != 0)
		FD_CLR(fd, &ctx->write_fds);

	if (!FD_ISSET(fd, &ctx->read_fds) && !FD_ISSET(fd, &ctx->write_fds)) {
		FD_CLR(fd, &ctx->except_fds);

		/* check if we removed the highest fd */
		if (io->fd == ctx->highest_fd)
			update_highest_fd(io->io.ioloop);
	}
	i_free(io);
}

#define io_check_condition(ctx, fd, cond) \
	((FD_ISSET((fd), &(ctx)->tmp_read_fds) && ((cond) & (IO_READ|IO_ERROR))) || \
	 (FD_ISSET((fd), &(ctx)->tmp_write_fds) && ((cond) & IO_WRITE)) || \
	 (FD_ISSET((fd), &(ctx)->tmp_except_fds)))

void io_loop_handler_run(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	struct timeval tv;
	struct io_file *io;
	int ret;

	/* get the time left for next timeout task */
	io_loop_get_wait_time(ioloop, &tv);

	memcpy(&ctx->tmp_read_fds, &ctx->read_fds, sizeof(fd_set));
	memcpy(&ctx->tmp_write_fds, &ctx->write_fds, sizeof(fd_set));
	memcpy(&ctx->tmp_except_fds, &ctx->except_fds, sizeof(fd_set));

	ret = select(ctx->highest_fd + 1, &ctx->tmp_read_fds,
		     &ctx->tmp_write_fds, &ctx->tmp_except_fds, &tv);
	if (ret < 0 && errno != EINTR)
		i_warning("select() : %m");

	/* execute timeout handlers */
        io_loop_handle_timeouts(ioloop);

	if (ret <= 0 || !ioloop->running) {
                /* no I/O events */
		return;
	}

	io = ioloop->io_files;
	for (; io != NULL && ret > 0; io = ioloop->next_io_file) {
                ioloop->next_io_file = io->next;

		if (io_check_condition(ctx, io->fd, io->io.condition)) {
			ret--;
			io_loop_call_io(&io->io);
		}
	}
}

#endif
