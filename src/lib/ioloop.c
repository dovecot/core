/*
 ioloop.c : I/O loop

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

/* FIXME: inserting IO is slow if there's lots of them. I should add a linked
   list of priorities pointing to first item in the list with the priority. */

#include "lib.h"
#include "ioloop-internal.h"

#undef timercmp
#define timercmp(tvp, uvp) \
	((tvp)->tv_sec > (uvp)->tv_sec || \
	 ((tvp)->tv_sec == (uvp)->tv_sec && \
	  (tvp)->tv_usec > (uvp)->tv_usec))

time_t ioloop_time;
struct timeval ioloop_timeval;

static IOLoop current_ioloop = NULL;

static void update_highest_fd(IOLoop ioloop)
{
        IO io;
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

static void io_list_insert(IOLoop ioloop, IO io)
{
	IO prev, next;

        prev = NULL;
	for (next = ioloop->ios; next != NULL; next = next->next) {
		if (next->priority >= io->priority)
                        break;
                prev = next;
	}

	if (prev == NULL)
                ioloop->ios = io;
	else {
		io->prev = prev;
                prev->next = io;
	}

	if (next != NULL) {
		io->next = next;
		next->prev = io;
	}
}

IO io_add(int fd, int condition, IOFunc func, void *data)
{
	return io_add_priority(fd, IO_PRIORITY_DEFAULT,
			       condition, func, data);
}

IO io_add_priority(int fd, int priority, int condition,
		   IOFunc func, void *context)
{
	IO io;

	i_assert(fd >= 0);
	i_assert(func != NULL);

	io = p_new(current_ioloop->pool, struct _IO, 1);
	io->fd = fd;
	io->priority = priority;
        io->condition = condition;

	io->func = func;
        io->context = context;

	if (io->fd > current_ioloop->highest_fd)
                current_ioloop->highest_fd = io->fd;

        io_loop_handle_add(current_ioloop, io->fd, io->condition);
	io_list_insert(current_ioloop, io);

	return io;
}

void io_remove(IO io)
{
	i_assert(io != NULL);
	i_assert(io->fd >= 0);
	i_assert(io->fd <= current_ioloop->highest_fd);

        /* notify the real I/O handler */
	io_loop_handle_remove(current_ioloop, io->fd, io->condition);

        /* check if we removed the highest fd */
	if (io->fd == current_ioloop->highest_fd)
                update_highest_fd(current_ioloop);

	io->destroyed = TRUE;
	io->fd = -1;
}

void io_destroy(IOLoop ioloop, IO io)
{
        /* remove from list */
	if (io->prev == NULL)
                ioloop->ios = io->next;
	else
		io->prev->next = io->next;

	if (io->next != NULL)
		io->next->prev = io->prev;

	p_free(ioloop->pool, io);
}

static void timeout_list_insert(IOLoop ioloop, Timeout timeout)
{
	Timeout *t;
        struct timeval *next_run;

        next_run = &timeout->next_run;
	for (t = &ioloop->timeouts; *t != NULL; t = &(*t)->next) {
		if (timercmp(&(*t)->next_run, next_run))
                        break;
	}

        timeout->next = *t;
        *t = timeout;
}

inline static void timeout_update_next(Timeout timeout, struct timeval *tv_now)
{
        if (tv_now == NULL)
		gettimeofday(&timeout->next_run, NULL);
	else {
                timeout->next_run.tv_sec = tv_now->tv_sec;
                timeout->next_run.tv_usec = tv_now->tv_usec;
	}

	/* we don't want microsecond accuracy or this function will be
	   called all the time - millisecond is more than enough */
	timeout->next_run.tv_usec /= 1000;
	timeout->next_run.tv_usec *= 1000;

	timeout->next_run.tv_sec += timeout->msecs/1000;
	timeout->next_run.tv_usec += (timeout->msecs%1000)*1000;

	if (timeout->next_run.tv_usec > 1000000) {
                timeout->next_run.tv_sec++;
                timeout->next_run.tv_usec -= 1000000;
	}
}

Timeout timeout_add(int msecs, TimeoutFunc func, void *context)
{
	Timeout timeout;

	timeout = p_new(current_ioloop->pool, struct _Timeout, 1);
        timeout->msecs = msecs;

	timeout->func = func;
	timeout->context = context;

        timeout_update_next(timeout, NULL);
        timeout_list_insert(current_ioloop, timeout);
	return timeout;
}

void timeout_remove(Timeout timeout)
{
	i_assert(timeout != NULL);

	timeout->destroyed = TRUE;
}

void timeout_destroy(IOLoop ioloop, Timeout timeout)
{
	Timeout *t;

	for (t = &ioloop->timeouts; *t != NULL; t = &(*t)->next) {
		if (*t == timeout)
			break;
	}
	*t = timeout->next;

        p_free(ioloop->pool, timeout);
}

int io_loop_get_wait_time(Timeout timeout, struct timeval *tv,
			  struct timeval *tv_now)
{
	if (timeout == NULL)
		return INT_MAX;

	if (tv_now == NULL)
		gettimeofday(tv, NULL);
	else {
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

void io_loop_handle_timeouts(IOLoop ioloop)
{
	Timeout t, next;
	struct timeval tv;
        int t_id;

	gettimeofday(&ioloop_timeval, NULL);
	ioloop_time = ioloop_timeval.tv_sec;

	if (ioloop->timeouts == NULL || !ioloop->timeouts->run_now)
		return;

	for (t = ioloop->timeouts; t != NULL; t = next) {
		next = t->next;

		if (t->destroyed) {
                        timeout_destroy(ioloop, t);
			continue;
		}

		if (!t->run_now) {
			io_loop_get_wait_time(t, &tv, &ioloop_timeval);

			if (!t->run_now)
				break;
		}

                t->run_now = FALSE;
                timeout_update_next(t, &ioloop_timeval);

                t_id = t_push();
		t->func(t->context, t);
		if (t_pop() != t_id)
                        i_panic("Leaked a t_pop() call!");
	}
}

void io_loop_run(IOLoop ioloop)
{
        ioloop->running = TRUE;
	while (ioloop->running)
		io_loop_handler_run(ioloop);
}

void io_loop_stop(IOLoop ioloop)
{
        ioloop->running = FALSE;
}

void io_loop_set_running(IOLoop ioloop)
{
        ioloop->running = TRUE;
}

IOLoop io_loop_create(Pool pool)
{
	IOLoop ioloop;

	/* initialize time */
	gettimeofday(&ioloop_timeval, NULL);
	ioloop_time = ioloop_timeval.tv_sec;

        ioloop = p_new(pool, struct _IOLoop, 1);
	pool_ref(pool);
	ioloop->pool = pool;
	ioloop->highest_fd = -1;

	io_loop_handler_init(ioloop);

	ioloop->prev = current_ioloop;
        current_ioloop = ioloop;

        return ioloop;
}

void io_loop_destroy(IOLoop ioloop)
{
	while (ioloop->ios != NULL) {
		IO io = ioloop->ios;

		if (!io->destroyed) {
			i_warning("I/O leak: %p (%d)", io->func, io->fd);
			io_remove(io);
		}
		io_destroy(ioloop, io);
	}

	while (ioloop->timeouts != NULL) {
		Timeout to = ioloop->timeouts;

		if (!to->destroyed) {
			i_warning("Timeout leak: %p", to->func);
			timeout_remove(to);
		}
                timeout_destroy(ioloop, to);
	}

        io_loop_handler_deinit(ioloop);

        /* ->prev won't work unless loops are destroyed in create order */
        i_assert(ioloop == current_ioloop);
	current_ioloop = current_ioloop->prev;

	pool_unref(ioloop->pool);
}
