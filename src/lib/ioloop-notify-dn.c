/* Copyright (C) 2003 Timo Sirainen */

/* Logic is pretty much based on dnotify by Oskar Liljeblad. */

#define _GNU_SOURCE
#include "lib.h"

#ifdef IOLOOP_NOTIFY_DNOTIFY

#include "ioloop-internal.h"
#include "write-full.h"

#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

static int event_pipe[2] = { -1, -1 };

static void sigrt_handler(int signo __attr_unused__, siginfo_t *si,
			  void *data __attr_unused__)
{
	if (write_full(event_pipe[1], &si->si_fd, sizeof(int)) < 0)
		i_fatal("write_full(event_pipe) failed: %m");
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

static int dn_init(void)
{
	struct sigaction act;

	if (pipe(event_pipe) < 0) {
		i_error("pipe() failed: %m");
		return FALSE;
	}

	act.sa_sigaction = sigrt_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_SIGINFO | SA_RESTART | SA_NODEFER;

	if (sigaction(SIGRTMIN, &act, NULL) < 0) {
		i_error("sigaction(SIGRTMIN) failed: %m");
		close(event_pipe[0]);
		close(event_pipe[1]);
		return FALSE;
	}

	return TRUE;
}

struct io *io_loop_notify_add(struct ioloop *ioloop, int fd,
			      enum io_condition condition,
			      io_callback_t *callback, void *context)
{
	struct io *io;

	if ((condition & IO_FILE_NOTIFY) != 0)
		return NULL;

	if (event_pipe[0] == -1) {
		if (!dn_init())
			return NULL;
	}
	if (ioloop->event_io == NULL) {
		ioloop->event_io =
			io_add(event_pipe[0], IO_READ, event_callback, ioloop);
	}

	if (fcntl(fd, F_SETSIG, SIGRTMIN) < 0) {
		i_error("fcntl(F_SETSIG) failed: %m");
		return FALSE;
	}
	if (fcntl(fd, F_NOTIFY, DN_CREATE | DN_DELETE | DN_RENAME |
		  DN_MULTISHOT) < 0) {
		i_error("fcntl(F_NOTIFY) failed: %m");
		(void)fcntl(fd, F_SETSIG, 0);
		return FALSE;
	}

	io = p_new(ioloop->pool, struct io, 1);
	io->fd = fd;
        io->condition = condition;

	io->callback = callback;
        io->context = context;

	io->next = ioloop->notifys;
	ioloop->notifys = io;
	return io;
}

void io_loop_notify_remove(struct ioloop *ioloop, struct io *io)
{
	struct io **io_p;

	for (io_p = &ioloop->notifys; *io_p != NULL; io_p = &(*io_p)->next) {
		if (*io_p == io) {
			*io_p = io->next;
			break;
		}
	}

	if (fcntl(io->fd, F_SETSIG, 0) < 0)
		i_error("fcntl(F_SETSIG, 0) failed: %m");
	if (fcntl(io->fd, F_NOTIFY, 0) < 0)
		i_error("fcntl(F_NOTIFY, 0) failed: %m");

	p_free(ioloop->pool, io);

	if (ioloop->notifys == NULL) {
		io_remove(ioloop->event_io);
		ioloop->event_io = NULL;
	}
}

#endif
