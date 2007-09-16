#ifndef IOLOOP_NOTIFY_FD_H
#define IOLOOP_NOTIFY_FD_H

/* common notify code for fd-based notifications (dnotify, inotify) */

struct io_notify {
	struct io io;

	/* use a doubly linked list so that io_remove() is quick */
	struct io_notify *prev, *next;

	int fd;
};

struct ioloop_notify_fd_context {
	struct io_notify *notifies;
};

struct io *io_notify_fd_add(struct ioloop_notify_fd_context *ctx, int fd,
			    io_callback_t *callback, void *context);
void io_notify_fd_free(struct ioloop_notify_fd_context *ctx,
		       struct io_notify *io);

struct io_notify *
io_notify_fd_find(struct ioloop_notify_fd_context *ctx, int fd);

#endif
