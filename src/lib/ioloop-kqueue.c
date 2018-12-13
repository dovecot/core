/*
 * BSD kqueue() based ioloop handler.
 *
 * Copyright (c) 2005 Vaclav Haisman <v.haisman@sh.cvut.cz>
 */

#include "lib.h"

#ifdef IOLOOP_KQUEUE

#include "array.h"
#include "sleep.h"
#include "ioloop-private.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

/* kevent.udata's type just has to be different in NetBSD than in
   FreeBSD and OpenBSD.. */
#ifdef __NetBSD__
#  define MY_EV_SET(a, b, c, d, e, f, g) \
	EV_SET(a, b, c, d, e, f, (intptr_t)g)
#else
#  define MY_EV_SET(a, b, c, d, e, f, g) \
	EV_SET(a, b, c, d, e, f, g)
#endif

struct ioloop_handler_context {
	int kq;

	unsigned int deleted_count;
	ARRAY(struct kevent) events;
};

void io_loop_handler_init(struct ioloop *ioloop, unsigned int initial_fd_count)
{
	struct ioloop_handler_context *ctx;

	ioloop->handler_context = ctx = i_new(struct ioloop_handler_context, 1);
	ctx->kq = kqueue();
	if (ctx->kq < 0)
		i_fatal("kqueue() in io_loop_handler_init() failed: %m");
	fd_close_on_exec(ctx->kq, TRUE);

	i_array_init(&ctx->events, initial_fd_count);
}

void io_loop_handler_deinit(struct ioloop *ioloop)
{
	if (close(ioloop->handler_context->kq) < 0)
		i_error("close(kqueue) in io_loop_handler_deinit() failed: %m");
	array_free(&ioloop->handler_context->events);
	i_free(ioloop->handler_context);
}

void io_loop_handle_add(struct io_file *io)
{
	struct ioloop_handler_context *ctx = io->io.ioloop->handler_context;
	struct kevent ev;

	if ((io->io.condition & (IO_READ | IO_ERROR)) != 0) {
		MY_EV_SET(&ev, io->fd, EVFILT_READ, EV_ADD, 0, 0, io);
		if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0)
			i_panic("kevent(EV_ADD, READ, %d) failed: %m", io->fd);
	}
	if ((io->io.condition & IO_WRITE) != 0) {
		MY_EV_SET(&ev, io->fd, EVFILT_WRITE, EV_ADD, 0, 0, io);
		if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0)
			i_panic("kevent(EV_ADD, WRITE, %d) failed: %m", io->fd);
	}

	/* allow kevent() to return the maximum number of events
	   by keeping space allocated for each handle */
	if (ctx->deleted_count > 0)
		ctx->deleted_count--;
	else
		array_append_zero(&ctx->events);
}

void io_loop_handle_remove(struct io_file *io, bool closed)
{
	struct ioloop_handler_context *ctx = io->io.ioloop->handler_context;
	struct kevent ev;

	i_assert(io->io.condition != 0);
	if ((io->io.condition & (IO_READ | IO_ERROR)) != 0 && !closed) {
		MY_EV_SET(&ev, io->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0)
			i_error("kevent(EV_DELETE, %d) failed: %m", io->fd);
	}
	if ((io->io.condition & IO_WRITE) != 0 && !closed) {
		MY_EV_SET(&ev, io->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
		if (kevent(ctx->kq, &ev, 1, NULL, 0, NULL) < 0)
			i_error("kevent(EV_DELETE, %d) failed: %m", io->fd);
	}
	io->io.condition = 0;

	/* since we're not freeing memory in any case, just increase
	   deleted counter so next handle_add() can just decrease it
	   instead of appending to the events array */
	ctx->deleted_count++;

	i_assert(io->refcount > 0);
	if (--io->refcount == 0)
		i_free(io);
}

void io_loop_handler_run_internal(struct ioloop *ioloop)
{
	struct ioloop_handler_context *ctx = ioloop->handler_context;
	struct kevent *events;
	const struct kevent *event;
	struct timeval tv;
	struct timespec ts;
	struct io_file *io;
	unsigned int events_count;
	int ret, i, msecs;

	/* get the time left for next timeout task */
	msecs = io_loop_run_get_wait_time(ioloop, &tv);
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * 1000;

	/* wait for events */
	events = array_get_modifiable(&ctx->events, &events_count);

	if (events_count > 0) {
		ret = kevent (ctx->kq, NULL, 0, events, events_count, &ts);
		if (ret < 0 && errno != EINTR) {
			i_panic("kevent(events=%u, ts=%ld.%u) failed: %m",
				events_count, (long)ts.tv_sec,
				(unsigned int)ts.tv_nsec);
		}
	} else {
		i_assert(msecs >= 0);
		i_sleep_intr_msecs(msecs);
		ret = 0;
	}

	/* reference all IOs */
	for (i = 0; i < ret; i++) {
		io = (void *)events[i].udata;
		i_assert(io->refcount > 0);
		io->refcount++;
	}

	/* execute timeout handlers */
	io_loop_handle_timeouts(ioloop);

	if (!ioloop->running)
		return;

	for (i = 0; i < ret; i++) {
		/* io_loop_handle_add() may cause events array reallocation,
		   so we have use array_idx() */
		event = array_idx(&ctx->events, i);
		io = (void *)event->udata;

		/* callback is NULL if io_remove() was already called */
		if (io->io.callback != NULL) {
			io_loop_call_io(&io->io);
			if (!ioloop->running)
				break;
		}

		i_assert(io->refcount > 0);
		if (--io->refcount == 0)
			i_free(io);
	}
}

#endif
