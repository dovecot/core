/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop-internal.h"

#include <unistd.h>

/* If time moves backwards more than this, kill ourself instead of sleeping. */
#define IOLOOP_MAX_TIME_BACKWARDS_SLEEP 5

#define timer_is_larger(tvp, uvp) \
	((tvp)->tv_sec > (uvp)->tv_sec || \
	 ((tvp)->tv_sec == (uvp)->tv_sec && \
	  (tvp)->tv_usec > (uvp)->tv_usec))

time_t ioloop_time = 0;
struct timeval ioloop_timeval;
struct timezone ioloop_timezone;

struct ioloop *current_ioloop = NULL;

#undef io_add
struct io *io_add(int fd, enum io_condition condition,
		  io_callback_t *callback, void *context)
{
	struct io_file *io;

	i_assert(fd >= 0);
	i_assert(callback != NULL);
	i_assert((condition & IO_NOTIFY) == 0);

	io = i_new(struct io_file, 1);
        io->io.condition = condition;
	io->io.callback = callback;
        io->io.context = context;
	io->io.ioloop = current_ioloop;
	io->refcount = 1;
	io->fd = fd;

	if (io->io.ioloop->handler_context == NULL)
		io_loop_handler_init(io->io.ioloop);
	io_loop_handle_add(io);

	if (io->io.ioloop->io_files != NULL) {
		io->io.ioloop->io_files->prev = io;
		io->next = io->io.ioloop->io_files;
	}
	io->io.ioloop->io_files = io;
	return &io->io;
}

static void io_file_unlink(struct io_file *io)
{
	if (io->prev != NULL)
		io->prev->next = io->next;
	else
		io->io.ioloop->io_files = io->next;

	if (io->next != NULL)
		io->next->prev = io->prev;

	/* if we got here from an I/O handler callback, make sure we
	   don't try to handle this one next. */
	if (io->io.ioloop->next_io_file == io)
		io->io.ioloop->next_io_file = io->next;
}

static void io_remove_full(struct io **_io, bool closed)
{
	struct io *io = *_io;

	i_assert(io->callback != NULL);

	*_io = NULL;

	/* make sure the callback doesn't get called anymore.
	   kqueue code relies on this. */
	io->callback = NULL;

	if ((io->condition & IO_NOTIFY) != 0)
		io_loop_notify_remove(io);
	else {
		struct io_file *io_file = (struct io_file *)io;

		io_file_unlink(io_file);
		io_loop_handle_remove(io_file, closed);
	}
}

void io_remove(struct io **io)
{
	io_remove_full(io, FALSE);
}

void io_remove_closed(struct io **io)
{
	i_assert(((*io)->condition & IO_NOTIFY) == 0);

	io_remove_full(io, TRUE);
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

#undef timeout_add
struct timeout *timeout_add(unsigned int msecs, timeout_callback_t *callback,
			    void *context)
{
	struct timeout *timeout;

	timeout = i_new(struct timeout, 1);
        timeout->msecs = msecs;
	timeout->ioloop = current_ioloop;

	timeout->callback = callback;
	timeout->context = context;

	timeout_update_next(timeout, timeout->ioloop->running ?
			    NULL : &ioloop_timeval);
	priorityq_add(timeout->ioloop->timeouts, &timeout->item);
	return timeout;
}

void timeout_remove(struct timeout **_timeout)
{
	struct timeout *timeout = *_timeout;

	*_timeout = NULL;
	priorityq_remove(timeout->ioloop->timeouts, &timeout->item);
	i_free(timeout);
}

static void
timeout_reset_timeval(struct timeout *timeout, struct timeval *tv_now)
{
	timeout_update_next(timeout, tv_now);
	if (timeout->msecs == 0) {
		/* if we came here from io_loop_handle_timeouts(),
		   next_run must be larger than tv_now or we could go to
		   infinite loop. +1000 to get 1 ms further, another +1000 to
		   account for timeout_update_next()'s truncation. */
		timeout->next_run.tv_usec += 2000;
		if (timeout->next_run.tv_usec >= 1000000) {
			timeout->next_run.tv_sec++;
			timeout->next_run.tv_usec -= 1000000;
		}
	}
	i_assert(tv_now == NULL ||
		 timeout->next_run.tv_sec > tv_now->tv_sec ||
		 (timeout->next_run.tv_sec == tv_now->tv_sec &&
		  timeout->next_run.tv_usec > tv_now->tv_usec));
	priorityq_remove(timeout->ioloop->timeouts, &timeout->item);
	priorityq_add(timeout->ioloop->timeouts, &timeout->item);
}

void timeout_reset(struct timeout *timeout)
{
	timeout_reset_timeval(timeout, timeout->ioloop->running ? NULL :
			      &ioloop_timeval);
}

static int timeout_get_wait_time(struct timeout *timeout, struct timeval *tv_r,
				 struct timeval *tv_now)
{
	int ret;

	if (tv_now == NULL) {
		if (gettimeofday(tv_r, NULL) < 0)
			i_fatal("gettimeofday(): %m");
	} else {
		tv_r->tv_sec = tv_now->tv_sec;
		tv_r->tv_usec = tv_now->tv_usec;
	}
	i_assert(tv_r->tv_sec > 0);
	i_assert(timeout->next_run.tv_sec > 0);

	tv_r->tv_sec = timeout->next_run.tv_sec - tv_r->tv_sec;
	tv_r->tv_usec = timeout->next_run.tv_usec - tv_r->tv_usec;
	if (tv_r->tv_usec < 0) {
		tv_r->tv_sec--;
		tv_r->tv_usec += 1000000;
	}

	if (tv_r->tv_sec < 0 || (tv_r->tv_sec == 0 && tv_r->tv_usec < 1000)) {
		tv_r->tv_sec = 0;
		tv_r->tv_usec = 0;
		return 0;
	}
	if (tv_r->tv_sec > INT_MAX/1000-1)
		tv_r->tv_sec = INT_MAX/1000-1;

	/* round wait times up to next millisecond */
	ret = tv_r->tv_sec * 1000 + (tv_r->tv_usec + 999) / 1000;
	i_assert(ret > 0 && tv_r->tv_sec >= 0 && tv_r->tv_usec >= 0);
	return ret;
}

int io_loop_get_wait_time(struct ioloop *ioloop, struct timeval *tv_r,
			  struct timeval *tv_now)
{
	struct priorityq_item *item;
	struct timeout *timeout;

	item = priorityq_peek(ioloop->timeouts);
	timeout = (struct timeout *)item;
	if (timeout == NULL) {
		/* no timeouts. give it INT_MAX msecs. */
		tv_r->tv_sec = INT_MAX / 1000;
		tv_r->tv_usec = 0;
		return INT_MAX;
	}

	return timeout_get_wait_time(timeout, tv_r, tv_now);
}

static int timeout_cmp(const void *p1, const void *p2)
{
	const struct timeout *to1 = p1, *to2 = p2;
	int diff;

	diff = to1->next_run.tv_sec - to2->next_run.tv_sec;
	if (diff == 0)
		diff = to1->next_run.tv_usec - to2->next_run.tv_usec;
	return diff;
}

static void io_loop_handle_timeouts_real(struct ioloop *ioloop)
{
	struct priorityq_item *item;
	struct timeval tv, tv_call;
        unsigned int t_id;

	if (gettimeofday(&ioloop_timeval, &ioloop_timezone) < 0)
		i_fatal("gettimeofday(): %m");

	/* Don't bother comparing usecs. */
	if (ioloop_time > ioloop_timeval.tv_sec) {
		time_t diff = ioloop_time - ioloop_timeval.tv_sec;

		/* Note that this code is here only because this is the easiest
		   place to check for this. The I/O loop code itself could be
		   easily fixed to work with time moving backwards, but there's
		   really no point because there are a lot of other places
		   which may break in more or less bad ways, such as files'
		   timestamps moving backwards. */
		if (diff > IOLOOP_MAX_TIME_BACKWARDS_SLEEP) {
			i_fatal("Time just moved backwards by %ld seconds. "
				"This might cause a lot of problems, "
				"so I'll just kill myself now. "
				"http://wiki.dovecot.org/TimeMovedBackwards",
				(long)diff);
		} else {
			i_error("Time just moved backwards by %ld seconds. "
				"I'll sleep now until we're back in present. "
				"http://wiki.dovecot.org/TimeMovedBackwards",
				(long)diff);
			/* Sleep extra second to make sure usecs also grows. */
			diff++;

			while (diff > 0 && sleep(diff) != 0) {
				/* don't use sleep()'s return value, because
				   it could get us to a long loop in case
				   interrupts just keep coming */
				diff = ioloop_time - time(NULL) + 1;
			}

			/* Try again. */
			io_loop_handle_timeouts(ioloop);
		}
	}
	ioloop_time = ioloop_timeval.tv_sec;
	tv_call = ioloop_timeval;

	while ((item = priorityq_peek(ioloop->timeouts)) != NULL) {
		struct timeout *timeout = (struct timeout *)item;

		/* use tv_call to make sure we don't get to infinite loop in
		   case callbacks update ioloop_timeval. */
		if (timeout_get_wait_time(timeout, &tv, &tv_call) > 0)
			break;

		/* update timeout's next_run and reposition it in the queue */
		timeout_reset_timeval(timeout, &tv_call);

                t_id = t_push();
		timeout->callback(timeout->context);
		if (t_pop() != t_id) {
			i_panic("Leaked a t_pop() call in timeout handler %p",
				(void *)timeout->callback);
		}
	}
}

void io_loop_handle_timeouts(struct ioloop *ioloop)
{
	T_BEGIN {
		io_loop_handle_timeouts_real(ioloop);
	} T_END;
}

void io_loop_run(struct ioloop *ioloop)
{
	if (ioloop->handler_context == NULL)
		io_loop_handler_init(ioloop);

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

bool io_loop_is_running(struct ioloop *ioloop)
{
        return ioloop->running;
}

struct ioloop *io_loop_create(void)
{
	struct ioloop *ioloop;

	/* initialize time */
	if (gettimeofday(&ioloop_timeval, &ioloop_timezone) < 0)
		i_fatal("gettimeofday(): %m");
	ioloop_time = ioloop_timeval.tv_sec;

        ioloop = i_new(struct ioloop, 1);
	ioloop->timeouts = priorityq_init(timeout_cmp, 32);

	ioloop->prev = current_ioloop;
        current_ioloop = ioloop;

        return ioloop;
}

void io_loop_destroy(struct ioloop **_ioloop)
{
	struct ioloop *ioloop = *_ioloop;
	struct priorityq_item *item;

	*_ioloop = NULL;

	if (ioloop->notify_handler_context != NULL)
		io_loop_notify_handler_deinit(ioloop);

	while (ioloop->io_files != NULL) {
		struct io_file *io = ioloop->io_files;
		struct io *_io = &io->io;

		i_warning("I/O leak: %p (%d)", (void *)io->io.callback, io->fd);
		io_remove(&_io);
	}

	while ((item = priorityq_pop(ioloop->timeouts)) != NULL) {
		struct timeout *to = (struct timeout *)item;

		i_warning("Timeout leak: %p", (void *)to->callback);
		i_free(to);
	}
	priorityq_deinit(&ioloop->timeouts);

	if (ioloop->handler_context != NULL)
		io_loop_handler_deinit(ioloop);

	/* ->prev won't work unless loops are destroyed in create order */
        i_assert(ioloop == current_ioloop);
	current_ioloop = current_ioloop->prev;

	i_free(ioloop);
}

void io_loop_set_current(struct ioloop *ioloop)
{
	current_ioloop = ioloop;
}
