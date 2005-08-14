/* Copyright (C) 2003 Timo Sirainen */

/* Logic is pretty much based on dnotify by Oskar Liljeblad. */

#define _GNU_SOURCE
#include "lib.h"

#ifdef IOLOOP_NOTIFY_DNOTIFY

#include "ioloop-internal.h"
#include "network.h"
#include "fd-close-on-exec.h"

#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

struct ioloop_notify_handler_context {
	struct io *event_io;
	int disabled;
};

static int event_pipe[2] = { -1, -1 };

static void sigrt_handler(int signo __attr_unused__, siginfo_t *si,
			  void *data __attr_unused__)
{
	int ret;

	ret = write(event_pipe[1], &si->si_fd, sizeof(int));
	if (ret < 0 && errno != EINTR && errno != EAGAIN)
		i_fatal("write(event_pipe) failed: %m");

	i_assert(ret <= 0 || ret == sizeof(int));
}

static void event_callback(void *context)
{
	struct ioloop *ioloop = context;
	struct io *io;
	int fd, ret;

	ret = read(event_pipe[0], &fd, sizeof(fd));
	if (ret < 0)
		i_fatal("read(event_pipe) failed: %m");
	if (ret != sizeof(fd))
		i_fatal("read(event_pipe) returned %d != %d", ret, sizeof(fd));

	if (gettimeofday(&ioloop_timeval, &ioloop_timezone) < 0)
		i_fatal("gettimeofday(): %m");
	ioloop_time = ioloop_timeval.tv_sec;

	for (io = ioloop->notifys; io != NULL; io = io->next) {
		if (io->fd == fd) {
			io->callback(io->context);
			break;
		}
	}
}

struct io *io_loop_notify_add(struct ioloop *ioloop, const char *path,
			      io_callback_t *callback, void *context)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;
	struct io *io;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		i_error("open(%s) for dnotify failed: %m", path);
		return NULL;
	}

	if (fcntl(fd, F_SETSIG, SIGRTMIN) < 0) {
		if (errno == EINVAL) {
			/* dnotify not in kernel. disable it. */
			ctx->disabled = TRUE;
			return NULL;
		}
		i_error("fcntl(F_SETSIG) failed: %m");
		return NULL;
	}
	if (fcntl(fd, F_NOTIFY, DN_CREATE | DN_DELETE | DN_RENAME |
		  DN_MULTISHOT) < 0) {
		/* we fail here if we're trying to add dnotify to
		   non-directory fd. fail silently in that case. */
		if (errno != ENOTDIR)
			i_error("fcntl(F_NOTIFY) failed: %m");
		(void)fcntl(fd, F_SETSIG, 0);
		(void)close(fd);
		return NULL;
	}

	if (ctx->event_io == NULL) {
		ctx->event_io =
			io_add(event_pipe[0], IO_READ, event_callback, ioloop);
	}

	io = p_new(ioloop->pool, struct io, 1);
	io->fd = fd;

	io->callback = callback;
        io->context = context;

	io->next = ioloop->notifys;
	ioloop->notifys = io;
	return io;
}

void io_loop_notify_remove(struct ioloop *ioloop, struct io *io)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;
	struct io **io_p;

	if (ctx->disabled)
		return;

	for (io_p = &ioloop->notifys; *io_p != NULL; io_p = &(*io_p)->next) {
		if (*io_p == io) {
			*io_p = io->next;
			break;
		}
	}

	if (fcntl(io->fd, F_NOTIFY, 0) < 0)
		i_error("fcntl(F_NOTIFY, 0) failed: %m");
	if (fcntl(io->fd, F_SETSIG, 0) < 0)
		i_error("fcntl(F_SETSIG, 0) failed: %m");
	if (close(io->fd))
		i_error("close(dnotify) failed: %m");

	p_free(ioloop->pool, io);

	if (ioloop->notifys == NULL) {
		io_remove(ctx->event_io);
		ctx->event_io = NULL;
	}
}

void io_loop_notify_handler_init(struct ioloop *ioloop)
{
	struct ioloop_notify_handler_context *ctx;
	struct sigaction act;

	i_assert(event_pipe[0] == -1);

	ctx = ioloop->notify_handler_context =
		i_new(struct ioloop_notify_handler_context, 1);

	if (pipe(event_pipe) < 0) {
		i_fatal("pipe() failed: %m");
		return;
	}

	net_set_nonblock(event_pipe[0], TRUE);
	net_set_nonblock(event_pipe[1], TRUE);

	fd_close_on_exec(event_pipe[0], TRUE);
	fd_close_on_exec(event_pipe[1], TRUE);

	/* SIGIO is sent if queue gets full. we'll just ignore it. */
        signal(SIGIO, SIG_IGN);

	act.sa_sigaction = sigrt_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;

	if (sigaction(SIGRTMIN, &act, NULL) < 0)
		i_fatal("sigaction(SIGRTMIN) failed: %m");
}

void io_loop_notify_handler_deinit(struct ioloop *ioloop __attr_unused__)
{
	struct ioloop_notify_handler_context *ctx =
		ioloop->notify_handler_context;

	signal(SIGRTMIN, SIG_IGN);

	if (close(event_pipe[0]) < 0)
		i_error("close(event_pipe[0]) failed: %m");
	if (close(event_pipe[1]) < 0)
		i_error("close(event_pipe[1]) failed: %m");

	i_free(ctx);
}

#endif
