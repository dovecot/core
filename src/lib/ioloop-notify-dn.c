/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

/* Logic is pretty much based on dnotify by Oskar Liljeblad. */

#define _GNU_SOURCE
#include "lib.h"

#ifdef IOLOOP_NOTIFY_DNOTIFY

#include "ioloop-internal.h"
#include "ioloop-notify-fd.h"
#include "fd-set-nonblock.h"
#include "fd-close-on-exec.h"

#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

struct ioloop_notify_handler_context {
	struct ioloop_notify_fd_context fd_ctx;

	struct io *event_io;
	int event_pipe[2];

	bool disabled;
};

static int sigrt_refcount = 0;

static struct ioloop_notify_handler_context *io_loop_notify_handler_init(void);

static void ioloop_dnotify_disable(struct ioloop_notify_handler_context *ctx)
{
	if (ctx->disabled)
		return;

	if (--sigrt_refcount == 0)
		signal(SIGRTMIN, SIG_IGN);

	if (close(ctx->event_pipe[0]) < 0)
		i_error("close(dnotify pipe[0]) failed: %m");
	if (close(ctx->event_pipe[1]) < 0)
		i_error("close(dnotify pipe[1]) failed: %m");
	ctx->disabled = TRUE;
}

static void sigrt_handler(int signo ATTR_UNUSED, siginfo_t *si,
			  void *data ATTR_UNUSED)
{
	struct ioloop_notify_handler_context *ctx =
		current_ioloop->notify_handler_context;
	int saved_errno = errno;
	int ret;

	if (ctx->disabled)
		return;

	ret = write(ctx->event_pipe[1], &si->si_fd, sizeof(int));
	if (ret < 0 && errno != EINTR && errno != EAGAIN) {
		i_error("write(dnotify pipe) failed: %m");
		ioloop_dnotify_disable(ctx);
	}

	i_assert(ret <= 0 || ret == sizeof(int));

	errno = saved_errno;
}

static void dnotify_input(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;
	struct io_notify *io;
	int fd_buf[256], i, ret;

	ret = read(ctx->event_pipe[0], fd_buf, sizeof(fd_buf));
	if (ret < 0)
		i_fatal("read(dnotify pipe) failed: %m");
	if ((ret % sizeof(fd_buf[0])) != 0)
		i_fatal("read(dnotify pipe) returned %d", ret);
	ret /= sizeof(fd_buf[0]);

	if (gettimeofday(&ioloop_timeval, NULL) < 0)
		i_fatal("gettimeofday(): %m");
	ioloop_time = ioloop_timeval.tv_sec;

	for (i = 0; i < ret; i++) {
		io = io_notify_fd_find(&ctx->fd_ctx, fd_buf[i]);
		if (io != NULL)
			io->io.callback(io->io.context);
	}
}

#undef io_add_notify
enum io_notify_result io_add_notify(const char *path, io_callback_t *callback,
				    void *context, struct io **io_r)
{
	struct ioloop_notify_handler_context *ctx =
		current_ioloop->notify_handler_context;
	int fd;

	*io_r = NULL;

	if (ctx == NULL)
		ctx = io_loop_notify_handler_init();
	if (ctx->disabled)
		return IO_NOTIFY_NOSUPPORT;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		/* ESTALE could happen with NFS. Don't bother giving an error
		   message then. */
		if (errno != ENOENT && errno != ESTALE)
			i_error("open(%s) for dnotify failed: %m", path);
		return IO_NOTIFY_NOTFOUND;
	}

	if (fcntl(fd, F_SETSIG, SIGRTMIN) < 0) {
		/* EINVAL means there's no realtime signals and no dnotify */
		if (errno != EINVAL)
			i_error("fcntl(F_SETSIG) failed: %m");
		ioloop_dnotify_disable(ctx);
		(void)close(fd);
		return IO_NOTIFY_NOSUPPORT;
	}
	if (fcntl(fd, F_NOTIFY, DN_CREATE | DN_DELETE | DN_RENAME |
		  DN_MULTISHOT) < 0) {
		if (errno == ENOTDIR) {
			/* we're trying to add dnotify to a non-directory fd.
			   fail silently. */
		} else {
			/* dnotify not in kernel. disable it. */
			if (errno != EINVAL)
				i_error("fcntl(F_NOTIFY) failed: %m");
			ioloop_dnotify_disable(ctx);
		}
		(void)fcntl(fd, F_SETSIG, 0);
		(void)close(fd);
		return IO_NOTIFY_NOSUPPORT;
	}

	if (ctx->event_io == NULL) {
		ctx->event_io = io_add(ctx->event_pipe[0], IO_READ,
				       dnotify_input, current_ioloop);
	}

	*io_r = io_notify_fd_add(&ctx->fd_ctx, fd, callback, context);
	return IO_NOTIFY_ADDED;
}

void io_loop_notify_remove(struct io *_io)
{
	struct ioloop_notify_handler_context *ctx =
		_io->ioloop->notify_handler_context;
	struct io_notify *io = (struct io_notify *)_io;

	if (fcntl(io->fd, F_NOTIFY, 0) < 0)
		i_error("fcntl(F_NOTIFY, 0) failed: %m");
	if (fcntl(io->fd, F_SETSIG, 0) < 0)
		i_error("fcntl(F_SETSIG, 0) failed: %m");
	if (close(io->fd))
		i_error("close(dnotify) failed: %m");

	io_notify_fd_free(&ctx->fd_ctx, io);

	if (ctx->fd_ctx.notifies == NULL)
		io_remove(&ctx->event_io);
}

static struct ioloop_notify_handler_context *io_loop_notify_handler_init(void)
{
	struct ioloop_notify_handler_context *ctx;
	struct sigaction act;

	ctx = current_ioloop->notify_handler_context =
		i_new(struct ioloop_notify_handler_context, 1);

	if (pipe(ctx->event_pipe) < 0) {
		ctx->disabled = TRUE;
		i_error("dnotify: pipe() failed: %m");
		return ctx;
	}

	fd_set_nonblock(ctx->event_pipe[0], TRUE);
	fd_set_nonblock(ctx->event_pipe[1], TRUE);

	fd_close_on_exec(ctx->event_pipe[0], TRUE);
	fd_close_on_exec(ctx->event_pipe[1], TRUE);

	if (sigrt_refcount++ == 0) {
		/* SIGIO is sent if queue gets full. we'll just ignore it. */
		signal(SIGIO, SIG_IGN);

		act.sa_sigaction = sigrt_handler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;

		if (sigaction(SIGRTMIN, &act, NULL) < 0) {
			if (errno == EINVAL) {
				/* kernel is too old to understand even RT
				   signals, so there's no way dnotify works */
				ioloop_dnotify_disable(ctx);
			} else {
				i_fatal("sigaction(SIGRTMIN) failed: %m");
			}
		}
	}
	return ctx;
}

void io_loop_notify_handler_deinit(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;

	ioloop_dnotify_disable(ctx);
	i_free(ctx);
}

#endif
