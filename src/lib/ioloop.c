/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "ioloop-internal.h"

#undef timercmp
#define timercmp(tvp, uvp) \
	((tvp)->tv_sec > (uvp)->tv_sec || \
	 ((tvp)->tv_sec == (uvp)->tv_sec && \
	  (tvp)->tv_usec > (uvp)->tv_usec))

time_t ioloop_time = 0;
struct timeval ioloop_timeval;
struct timezone ioloop_timezone;

static struct ioloop *current_ioloop = NULL;

struct io *io_add(int fd, enum io_condition condition,
		  io_callback_t *callback, void *context)
{
	struct io *io;

	i_assert(fd >= 0);
	i_assert(callback != NULL);
	i_assert((condition & IO_NOTIFY) == 0);

	io = p_new(current_ioloop->pool, struct io, 1);
	io->fd = fd;
        io->condition = condition;

	io->callback = callback;
        io->context = context;

	io_loop_handle_add(current_ioloop, io);

	/* have to append it, or io_destroy() breaks */
	io->next = current_ioloop->ios;
	current_ioloop->ios = io;

	if (io->next != NULL)
		io->next->prev = io;
	return io;
}

struct io *io_add_notify(const char *path, io_callback_t *callback,
			 void *context)
{
	struct io *io;

	i_assert(path != NULL);
	i_assert(callback != NULL);
	
	io = io_loop_notify_add(current_ioloop, path, callback, context);
	if (io != NULL)
		io->condition |= IO_NOTIFY;
	return io;
}

void io_remove(struct io *io)
{
	if ((io->condition & IO_NOTIFY) != 0) {
		io_loop_notify_remove(current_ioloop, io);
		return;
	}

	/* notify the real I/O handler */
	io_loop_handle_remove(current_ioloop, io);

	if (current_ioloop->next_io == io)
                current_ioloop->next_io = io->next;

	if (io->prev == NULL)
		current_ioloop->ios = io->next;
	else
		io->prev->next = io->next;
	if (io->next != NULL)
		io->next->prev = io->prev;

	p_free(current_ioloop->pool, io);
}

static void timeout_list_insert(struct ioloop *ioloop, struct timeout *timeout)
{
	struct timeout **t;
        struct timeval *next_run;

        next_run = &timeout->next_run;
	for (t = &ioloop->timeouts; *t != NULL; t = &(*t)->next) {
		if (timercmp(&(*t)->next_run, next_run))
                        break;
	}

        timeout->next = *t;
        *t = timeout;
}

static void timeout_update_next(struct timeout *timeout, struct timeval *tv_now)
{
	if (tv_now == NULL) {
		if (gettimeofday(&timeout->next_run, NULL) < 0)
			i_fatal("gettimeofday(): %m");
	} else {
                timeout->next_run.tv_sec = tv_now->tv_sec;
                timeout->next_run.tv_usec = tv_now->tv_usec;
	}

	/* we don't want microsecond accuracy or this function will be
	   called all the time - millisecond is more than enough */
	timeout->next_run.tv_usec -= timeout->next_run.tv_usec % 1000;

	timeout->next_run.tv_sec += timeout->msecs/1000;
	timeout->next_run.tv_usec += (timeout->msecs%1000)*1000;

	if (timeout->next_run.tv_usec > 1000000) {
                timeout->next_run.tv_sec++;
                timeout->next_run.tv_usec -= 1000000;
	}
}

struct timeout *timeout_add(unsigned int msecs, timeout_callback_t *callback,
			    void *context)
{
	struct timeout *timeout;

	timeout = p_new(current_ioloop->pool, struct timeout, 1);
        timeout->msecs = msecs;

	timeout->callback = callback;
	timeout->context = context;

	timeout_update_next(timeout, current_ioloop->running ?
			    NULL : &ioloop_timeval);
        timeout_list_insert(current_ioloop, timeout);
	return timeout;
}

void timeout_remove(struct timeout *timeout)
{
	i_assert(timeout != NULL);

	timeout->destroyed = TRUE;
}

void timeout_destroy(struct ioloop *ioloop, struct timeout **timeout_p)
{
        struct timeout *timeout = *timeout_p;

	*timeout_p = timeout->next;
        p_free(ioloop->pool, timeout);
}

int io_loop_get_wait_time(struct timeout *timeout, struct timeval *tv,
			  struct timeval *tv_now)
{
	if (timeout == NULL) {
		/* no timeouts. give it INT_MAX msecs. */
		tv->tv_sec = INT_MAX / 1000;
		tv->tv_usec = 0;
		return INT_MAX;
	}

	if (tv_now == NULL) {
		if (gettimeofday(tv, NULL) < 0)
			i_fatal("gettimeofday(): %m");
	} else {
		tv->tv_sec = tv_now->tv_sec;
		tv->tv_usec = tv_now->tv_usec;
	}

	tv->tv_sec = timeout->next_run.tv_sec - tv->tv_sec;
	tv->tv_usec = timeout->next_run.tv_usec - tv->tv_usec;
	if (tv->tv_usec < 0) {
		tv->tv_sec--;
		tv->tv_usec += 1000000;
	}

	if (tv->tv_sec > 0 || (tv->tv_sec == 0 && tv->tv_usec > 0))
		return tv->tv_sec*1000 + tv->tv_usec/1000;

	/* no need to calculate the times again with this timeout */
        tv->tv_sec = tv->tv_usec = 0;
	timeout->run_now = TRUE;
        return 0;
}

void io_loop_handle_timeouts(struct ioloop *ioloop)
{
	struct timeout *t, **t_p;
	struct timeval tv;
        unsigned int t_id;

	if (gettimeofday(&ioloop_timeval, &ioloop_timezone) < 0)
		i_fatal("gettimeofday(): %m");
	ioloop_time = ioloop_timeval.tv_sec;

	if (ioloop->timeouts == NULL || !ioloop->timeouts->run_now)
		return;

	t_p = &ioloop->timeouts;
	for (t = ioloop->timeouts; t != NULL; t = *t_p) {
		if (t->destroyed) {
                        timeout_destroy(ioloop, t_p);
			continue;
		}
		t_p = &t->next;

		if (!t->run_now) {
			io_loop_get_wait_time(t, &tv, &ioloop_timeval);

			if (!t->run_now)
				break;
		}

                t->run_now = FALSE;
                timeout_update_next(t, &ioloop_timeval);

                t_id = t_push();
		t->callback(t->context);
		if (t_pop() != t_id) {
			i_panic("Leaked a t_pop() call in timeout handler %p",
				(void *)t->callback);
		}
	}
}

void io_loop_run(struct ioloop *ioloop)
{
        ioloop->running = TRUE;
	while (ioloop->running)
		io_loop_handler_run(ioloop);
}

void io_loop_stop(struct ioloop *ioloop)
{
        ioloop->running = FALSE;
}

void io_loop_set_running(struct ioloop *ioloop)
{
        ioloop->running = TRUE;
}

int io_loop_is_running(struct ioloop *ioloop)
{
        return ioloop->running;
}

struct ioloop *io_loop_create(pool_t pool)
{
	struct ioloop *ioloop;

	/* initialize time */
	if (gettimeofday(&ioloop_timeval, &ioloop_timezone) < 0)
		i_fatal("gettimeofday(): %m");
	ioloop_time = ioloop_timeval.tv_sec;

        ioloop = p_new(pool, struct ioloop, 1);
	pool_ref(pool);
	ioloop->pool = pool;

	io_loop_handler_init(ioloop);
	io_loop_notify_handler_init(ioloop);

	ioloop->prev = current_ioloop;
        current_ioloop = ioloop;

        return ioloop;
}

void io_loop_destroy(struct ioloop *ioloop)
{
	pool_t pool;

	while (ioloop->ios != NULL) {
		struct io *io = ioloop->ios;

		i_warning("I/O leak: %p (%d)", (void *)io->callback, io->fd);
		io_remove(io);
	}

	while (ioloop->timeouts != NULL) {
		struct timeout *to = ioloop->timeouts;

		if (!to->destroyed) {
			i_warning("Timeout leak: %p", (void *)to->callback);
			timeout_remove(to);
		}
                timeout_destroy(ioloop, &ioloop->timeouts);
	}

	io_loop_notify_handler_deinit(ioloop);
        io_loop_handler_deinit(ioloop);

        /* ->prev won't work unless loops are destroyed in create order */
        i_assert(ioloop == current_ioloop);
	current_ioloop = current_ioloop->prev;

	pool = ioloop->pool;
	p_free(pool, ioloop);
	pool_unref(pool);
}
