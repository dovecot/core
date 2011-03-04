/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop-internal.h"
#include "ioloop-notify-fd.h"

#if defined(IOLOOP_NOTIFY_DNOTIFY) || defined(IOLOOP_NOTIFY_INOTIFY)

struct io *io_notify_fd_add(struct ioloop_notify_fd_context *ctx, int fd,
			    io_callback_t *callback, void *context)
{
	struct io_notify *io;

	io = i_new(struct io_notify, 1);
	io->io.condition = IO_NOTIFY;
	io->io.callback = callback;
	io->io.context = context;
	io->io.ioloop = current_ioloop;
	io->fd = fd;

	if (ctx->notifies != NULL) {
		ctx->notifies->prev = io;
		io->next = ctx->notifies;
	}
	ctx->notifies = io;
	return &io->io;
}

void io_notify_fd_free(struct ioloop_notify_fd_context *ctx,
		       struct io_notify *io)
{
	if (io->prev != NULL)
		io->prev->next = io->next;
	else
		ctx->notifies = io->next;

	if (io->next != NULL)
		io->next->prev = io->prev;
	i_free(io);
}

struct io_notify *
io_notify_fd_find(struct ioloop_notify_fd_context *ctx, int fd)
{
	struct io_notify *io;

	for (io = ctx->notifies; io != NULL; io = io->next) {
		if (io->fd == fd)
			return io;
	}

	return NULL;
}

#endif
