/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "time-util.h"
#include "ioloop-internal.h"

#include <unistd.h>

#define timer_is_larger(tvp, uvp) \
	((tvp)->tv_sec > (uvp)->tv_sec || \
	 ((tvp)->tv_sec == (uvp)->tv_sec && \
	  (tvp)->tv_usec > (uvp)->tv_usec))

time_t ioloop_time = 0;
struct timeval ioloop_timeval;

struct ioloop *current_ioloop = NULL;

static void io_loop_initialize_handler(struct ioloop *ioloop)
{
	unsigned int initial_fd_count;

	initial_fd_count = ioloop->max_fd_count > 0 &&
		ioloop->max_fd_count < IOLOOP_INITIAL_FD_COUNT ?
		ioloop->max_fd_count : IOLOOP_INITIAL_FD_COUNT;
	io_loop_handler_init(ioloop, initial_fd_count);
}

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

	if (io->io.ioloop->cur_log != NULL) {
		io->io.log = io->io.ioloop->cur_log;
		io_loop_log_ref(io->io.log);
	}

	if (io->io.ioloop->handler_context == NULL)
		io_loop_initialize_handler(io->io.ioloop);
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

	if (io->log != NULL)
		io_loop_log_unref(&io->log);

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

	if (timeout->ioloop->cur_log != NULL) {
		timeout->log = timeout->ioloop->cur_log;
		io_loop_log_ref(timeout->log);
	}

	timeout_update_next(timeout, timeout->ioloop->running ?
			    NULL : &ioloop_timeval);
	priorityq_add(timeout->ioloop->timeouts, &timeout->item);
	return timeout;
}

static void timeout_free(struct timeout *timeout)
{
	if (timeout->log != NULL)
		io_loop_log_unref(&timeout->log);
	i_free(timeout);
}

void timeout_remove(struct timeout **_timeout)
{
	struct timeout *timeout = *_timeout;

	*_timeout = NULL;
	priorityq_remove(timeout->ioloop->timeouts, &timeout->item);
	timeout_free(timeout);
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

	if (tv_now->tv_sec == 0) {
		if (gettimeofday(tv_now, NULL) < 0)
			i_fatal("gettimeofday(): %m");
	} 
	tv_r->tv_sec = tv_now->tv_sec;
	tv_r->tv_usec = tv_now->tv_usec;

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

int io_loop_get_wait_time(struct ioloop *ioloop, struct timeval *tv_r)
{
	struct timeval tv_now;
	struct priorityq_item *item;
	struct timeout *timeout;
	int msecs;

	item = priorityq_peek(ioloop->timeouts);
	timeout = (struct timeout *)item;
	if (timeout == NULL) {
		/* no timeouts. use INT_MAX msecs for timeval and
		   return -1 for poll/epoll infinity. */
		tv_r->tv_sec = INT_MAX / 1000;
		tv_r->tv_usec = 0;
		ioloop->next_max_time = (1ULL << (TIME_T_MAX_BITS-1)) - 1;
		return -1;
	}

	tv_now.tv_sec = 0;
	msecs = timeout_get_wait_time(timeout, tv_r, &tv_now);
	ioloop->next_max_time = (tv_now.tv_sec + msecs/1000) + 1;
	return msecs;
}

static int timeout_cmp(const void *p1, const void *p2)
{
	const struct timeout *to1 = p1, *to2 = p2;

	return timeval_cmp(&to1->next_run, &to2->next_run);
}

static void io_loop_default_time_moved(time_t old_time, time_t new_time)
{
	if (old_time > new_time) {
		i_warning("Time moved backwards by %ld seconds.",
			  (long)(old_time - new_time));
	}
}

static void io_loop_timeouts_update(struct ioloop *ioloop, long diff_secs)
{
	struct priorityq_item *const *items;
	unsigned int i, count;

	count = priorityq_count(ioloop->timeouts);
	items = priorityq_items(ioloop->timeouts);
	for (i = 0; i < count; i++) {
		struct timeout *to = (struct timeout *)items[i];

		to->next_run.tv_sec += diff_secs;
	}
}

static void io_loops_timeouts_update(long diff_secs)
{
	struct ioloop *ioloop;

	for (ioloop = current_ioloop; ioloop != NULL; ioloop = ioloop->prev)
		io_loop_timeouts_update(ioloop, diff_secs);
}

static void io_loop_handle_timeouts_real(struct ioloop *ioloop)
{
	struct priorityq_item *item;
	struct timeval tv, tv_call;
	unsigned int t_id;

	if (gettimeofday(&ioloop_timeval, NULL) < 0)
		i_fatal("gettimeofday(): %m");

	/* Don't bother comparing usecs. */
	if (unlikely(ioloop_time > ioloop_timeval.tv_sec)) {
		/* time moved backwards */
		io_loops_timeouts_update(-(long)(ioloop_time -
						 ioloop_timeval.tv_sec));
		ioloop->time_moved_callback(ioloop_time,
					    ioloop_timeval.tv_sec);
		/* the callback may have slept, so check the time again. */
		if (gettimeofday(&ioloop_timeval, NULL) < 0)
			i_fatal("gettimeofday(): %m");
	} else if (unlikely(ioloop_timeval.tv_sec >
			    ioloop->next_max_time)) {
		io_loops_timeouts_update(ioloop_timeval.tv_sec -
					ioloop->next_max_time);
		/* time moved forwards */
		ioloop->time_moved_callback(ioloop->next_max_time,
					    ioloop_timeval.tv_sec);
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

		if (timeout->log != NULL) {
			ioloop->cur_log = timeout->log;
			io_loop_log_ref(ioloop->cur_log);
			i_set_failure_prefix(timeout->log->prefix);
		}
                t_id = t_push();
		timeout->callback(timeout->context);
		if (t_pop() != t_id) {
			i_panic("Leaked a t_pop() call in timeout handler %p",
				(void *)timeout->callback);
		}
		if (ioloop->cur_log != NULL) {
			io_loop_log_unref(&ioloop->cur_log);
			i_set_failure_prefix(ioloop->default_log_prefix);
		}
	}
}

void io_loop_handle_timeouts(struct ioloop *ioloop)
{
	T_BEGIN {
		io_loop_handle_timeouts_real(ioloop);
	} T_END;
}

void io_loop_call_io(struct io *io)
{
	struct ioloop *ioloop = io->ioloop;
	unsigned int t_id;

	if (io->log != NULL) {
		ioloop->cur_log = io->log;
		io_loop_log_ref(ioloop->cur_log);
		i_set_failure_prefix(io->log->prefix);
	}
	t_id = t_push();
	io->callback(io->context);
	if (t_pop() != t_id) {
		i_panic("Leaked a t_pop() call in I/O handler %p",
			(void *)io->callback);
	}
	if (ioloop->cur_log != NULL) {
		io_loop_log_unref(&ioloop->cur_log);
		i_set_failure_prefix(ioloop->default_log_prefix);
	}
}

void io_loop_run(struct ioloop *ioloop)
{
	if (ioloop->handler_context == NULL)
		io_loop_initialize_handler(ioloop);

	if (ioloop->cur_log != NULL)
		io_loop_log_unref(&ioloop->cur_log);

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

void io_loop_set_max_fd_count(struct ioloop *ioloop, unsigned int max_fds)
{
	ioloop->max_fd_count = max_fds;
}

bool io_loop_is_running(struct ioloop *ioloop)
{
        return ioloop->running;
}

struct ioloop *io_loop_create(void)
{
	struct ioloop *ioloop;

	/* initialize time */
	if (gettimeofday(&ioloop_timeval, NULL) < 0)
		i_fatal("gettimeofday(): %m");
	ioloop_time = ioloop_timeval.tv_sec;

        ioloop = i_new(struct ioloop, 1);
	ioloop->timeouts = priorityq_init(timeout_cmp, 32);

	ioloop->time_moved_callback = current_ioloop != NULL ?
		current_ioloop->time_moved_callback :
		io_loop_default_time_moved;

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
		timeout_free(to);
	}
	priorityq_deinit(&ioloop->timeouts);

	if (ioloop->handler_context != NULL)
		io_loop_handler_deinit(ioloop);

	/* ->prev won't work unless loops are destroyed in create order */
        i_assert(ioloop == current_ioloop);
	current_ioloop = current_ioloop->prev;

	i_free(ioloop);
}

void io_loop_set_time_moved_callback(struct ioloop *ioloop,
				     io_loop_time_moved_callback_t *callback)
{
	ioloop->time_moved_callback = callback;
}

void io_loop_set_current(struct ioloop *ioloop)
{
	current_ioloop = ioloop;
}

struct ioloop_log *io_loop_log_new(struct ioloop *ioloop)
{
	struct ioloop_log *log;

	i_assert(ioloop->default_log_prefix != NULL);

	log = i_new(struct ioloop_log, 1);
	log->refcount = 2;
	log->prefix = i_strdup("");

	log->ioloop = ioloop;
	if (ioloop->cur_log != NULL)
		io_loop_log_unref(&ioloop->cur_log);
	ioloop->cur_log = log;
	return log;
}

void io_loop_log_ref(struct ioloop_log *log)
{
	i_assert(log->refcount > 0);

	log->refcount++;
}

void io_loop_log_unref(struct ioloop_log **_log)
{
	struct ioloop_log *log = *_log;

	*_log = NULL;

	i_assert(log->refcount > 0);
	if (--log->refcount > 0)
		return;

	/* cur_log itself keeps a reference */
	i_assert(log->ioloop->cur_log != log);

	i_free(log->prefix);
	i_free(log);
}

void io_loop_log_set_prefix(struct ioloop_log *log, const char *prefix)
{
	i_free(log->prefix);
	log->prefix = i_strdup(prefix);
}

void io_loop_set_default_log_prefix(struct ioloop *ioloop, const char *prefix)
{
	i_assert(prefix != NULL);

	i_free(ioloop->default_log_prefix);
	ioloop->default_log_prefix = i_strdup(prefix);
}
