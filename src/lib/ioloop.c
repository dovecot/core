/* Copyright (c) 2002-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "time-util.h"
#include "istream-private.h"
#include "ioloop-private.h"

#include <unistd.h>

#define timer_is_larger(tvp, uvp) \
	((tvp)->tv_sec > (uvp)->tv_sec || \
	 ((tvp)->tv_sec == (uvp)->tv_sec && \
	  (tvp)->tv_usec > (uvp)->tv_usec))

time_t ioloop_time = 0;
struct timeval ioloop_timeval;

struct ioloop *current_ioloop = NULL;
static ARRAY(io_switch_callback_t *) io_switch_callbacks = ARRAY_INIT;

static void io_loop_initialize_handler(struct ioloop *ioloop)
{
	unsigned int initial_fd_count;

	initial_fd_count = ioloop->max_fd_count > 0 &&
		ioloop->max_fd_count < IOLOOP_INITIAL_FD_COUNT ?
		ioloop->max_fd_count : IOLOOP_INITIAL_FD_COUNT;
	io_loop_handler_init(ioloop, initial_fd_count);
}

static struct io_file *
io_add_file(int fd, enum io_condition condition,
	    unsigned int source_linenum,
	    io_callback_t *callback, void *context)
{
	struct io_file *io;

	i_assert(callback != NULL);
	i_assert((condition & IO_NOTIFY) == 0);

	io = i_new(struct io_file, 1);
        io->io.condition = condition;
	io->io.callback = callback;
        io->io.context = context;
	io->io.ioloop = current_ioloop;
	io->io.source_linenum = source_linenum;
	io->refcount = 1;
	io->fd = fd;

	if (io->io.ioloop->cur_ctx != NULL) {
		io->io.ctx = io->io.ioloop->cur_ctx;
		io_loop_context_ref(io->io.ctx);
	}

	if (io->io.ioloop->handler_context == NULL)
		io_loop_initialize_handler(io->io.ioloop);
	if (fd != -1)
		io_loop_handle_add(io);
	else {
		/* we're adding an istream whose only way to get notified
		   is to call i_stream_set_input_pending() */
	}

	if (io->io.ioloop->io_files != NULL) {
		io->io.ioloop->io_files->prev = io;
		io->next = io->io.ioloop->io_files;
	}
	io->io.ioloop->io_files = io;
	return io;
}

#undef io_add
struct io *io_add(int fd, enum io_condition condition,
		  unsigned int source_linenum,
		  io_callback_t *callback, void *context)
{
	struct io_file *io;

	i_assert(fd >= 0);
	io = io_add_file(fd, condition, source_linenum, callback, context);
	return &io->io;
}

#undef io_add_istream
struct io *io_add_istream(struct istream *input, unsigned int source_linenum,
			  io_callback_t *callback, void *context)
{
	struct io_file *io;

	io = io_add_file(i_stream_get_fd(input), IO_READ, source_linenum,
			 callback, context);
	io->istream = input;
	i_stream_ref(io->istream);
	i_stream_set_io(io->istream, &io->io);
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

	if (io->pending) {
		i_assert(io->ioloop->io_pending_count > 0);
		io->ioloop->io_pending_count--;
	}

	if (io->ctx != NULL)
		io_loop_context_unref(&io->ctx);

	if ((io->condition & IO_NOTIFY) != 0)
		io_loop_notify_remove(io);
	else {
		struct io_file *io_file = (struct io_file *)io;
		struct istream *istream = io_file->istream;

		if (istream != NULL) {
			/* remove io before it's freed */
			i_stream_unset_io(istream, io);
		}

		io_file_unlink(io_file);
		if (io_file->fd != -1)
			io_loop_handle_remove(io_file, closed);
		else
			i_free(io);

		/* remove io from the ioloop before unreferencing the istream,
		   because a destroyed istream may automatically close the
		   fd. */
		if (istream != NULL)
			i_stream_unref(&istream);
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

void io_set_pending(struct io *io)
{
	i_assert((io->condition & IO_NOTIFY) == 0);

	if (!io->pending) {
		io->pending = TRUE;
		io->ioloop->io_pending_count++;
	}
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

static struct timeout *
timeout_add_common(unsigned int source_linenum,
			    timeout_callback_t *callback, void *context)
{
	struct timeout *timeout;

	timeout = i_new(struct timeout, 1);
	timeout->item.idx = UINT_MAX;
	timeout->source_linenum = source_linenum;
	timeout->ioloop = current_ioloop;

	timeout->callback = callback;
	timeout->context = context;

	if (timeout->ioloop->cur_ctx != NULL) {
		timeout->ctx = timeout->ioloop->cur_ctx;
		io_loop_context_ref(timeout->ctx);
	}

	return timeout;
}

#undef timeout_add
struct timeout *timeout_add(unsigned int msecs, unsigned int source_linenum,
			    timeout_callback_t *callback, void *context)
{
	struct timeout *timeout;

	timeout = timeout_add_common(source_linenum, callback, context);
	timeout->msecs = msecs;

	if (msecs > 0) {
		/* start this timeout in the next run cycle */
		array_append(&timeout->ioloop->timeouts_new, &timeout, 1);
	} else {
		/* trigger zero timeouts as soon as possible */
		timeout_update_next(timeout, timeout->ioloop->running ?
			    NULL : &ioloop_timeval);
		priorityq_add(timeout->ioloop->timeouts, &timeout->item);
	}
	return timeout;
}

#undef timeout_add_short
struct timeout *
timeout_add_short(unsigned int msecs, unsigned int source_linenum,
		  timeout_callback_t *callback, void *context)
{
	return timeout_add(msecs, source_linenum, callback, context);
}

#undef timeout_add_absolute
struct timeout *
timeout_add_absolute(const struct timeval *time,
		     unsigned int source_linenum,
		     timeout_callback_t *callback, void *context)
{
	struct timeout *timeout;

	timeout = timeout_add_common(source_linenum, callback, context);
	timeout->one_shot = TRUE;
	timeout->next_run = *time;

	priorityq_add(timeout->ioloop->timeouts, &timeout->item);
	return timeout;
}

static struct timeout *
timeout_copy(const struct timeout *old_to)
{
	struct timeout *new_to;

	new_to = timeout_add_common
		(old_to->source_linenum, old_to->callback, old_to->context);
	new_to->one_shot = old_to->one_shot;
	new_to->msecs = old_to->msecs;
	new_to->next_run = old_to->next_run;

	if (old_to->item.idx != UINT_MAX)
		priorityq_add(new_to->ioloop->timeouts, &new_to->item);
	else if (!new_to->one_shot) {
		i_assert(new_to->msecs > 0);
		array_append(&new_to->ioloop->timeouts_new, &new_to, 1);
	}

	return new_to;
}

static void timeout_free(struct timeout *timeout)
{
	if (timeout->ctx != NULL)
		io_loop_context_unref(&timeout->ctx);
	i_free(timeout);
}

void timeout_remove(struct timeout **_timeout)
{
	struct timeout *timeout = *_timeout;
	struct ioloop *ioloop = timeout->ioloop;

	*_timeout = NULL;
	if (timeout->item.idx != UINT_MAX)
		priorityq_remove(timeout->ioloop->timeouts, &timeout->item);
	else if (!timeout->one_shot && timeout->msecs > 0) {
		struct timeout *const *to_idx;
		array_foreach(&ioloop->timeouts_new, to_idx) {
			if (*to_idx == timeout) {
				array_delete(&ioloop->timeouts_new,
					array_foreach_idx(&ioloop->timeouts_new, to_idx), 1);
				break;
			}
		}
	}
	timeout_free(timeout);
}

static void ATTR_NULL(2)
timeout_reset_timeval(struct timeout *timeout, struct timeval *tv_now)
{
	if (timeout->item.idx == UINT_MAX)
		return;

	timeout_update_next(timeout, tv_now);
	if (timeout->msecs <= 1) {
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
	i_assert(!timeout->one_shot);
	timeout_reset_timeval(timeout, NULL);
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

	/* we need to see if there are pending IO waiting,
	   if there is, we set msecs = 0 to ensure they are
	   processed without delay */
	if (timeout == NULL && ioloop->io_pending_count == 0) {
		/* no timeouts. use INT_MAX msecs for timeval and
		   return -1 for poll/epoll infinity. */
		tv_r->tv_sec = INT_MAX / 1000;
		tv_r->tv_usec = 0;
		ioloop->next_max_time = (1ULL << (TIME_T_MAX_BITS-1)) - 1;
		return -1;
	}

	if (ioloop->io_pending_count > 0) {
		if (gettimeofday(&tv_now, NULL) < 0)
			i_fatal("gettimeofday(): %m");
		msecs = 0;
	} else {
		tv_now.tv_sec = 0;
		msecs = timeout_get_wait_time(timeout, tv_r, &tv_now);
	}
	ioloop->next_max_time = (tv_now.tv_sec + msecs/1000) + 1;

	/* update ioloop_timeval - this is meant for io_loop_handle_timeouts()'s
	   ioloop_wait_usecs calculation. normally after this we go to the
	   ioloop and after that we update ioloop_timeval immediately again. */
	ioloop_timeval = tv_now;
	ioloop_time = tv_now.tv_sec;
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

static void io_loop_timeouts_start_new(struct ioloop *ioloop)
{
	struct timeout *const *to_idx;

	if (array_count(&ioloop->timeouts_new) == 0)
		return;
	
	io_loop_time_refresh();

	array_foreach(&ioloop->timeouts_new, to_idx) {
		struct timeout *timeout= *to_idx;
		i_assert(timeout->next_run.tv_sec == 0 &&
			timeout->next_run.tv_usec == 0);
		i_assert(!timeout->one_shot);
		i_assert(timeout->msecs > 0);
		timeout_update_next(timeout, &ioloop_timeval);
		priorityq_add(ioloop->timeouts, &timeout->item);
	}
	array_clear(&ioloop->timeouts_new);
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
	struct timeval tv, tv_call, prev_ioloop_timeval = ioloop_timeval;
	data_stack_frame_t t_id;

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
	} else {
		if (unlikely(ioloop_timeval.tv_sec >
			     ioloop->next_max_time)) {
			io_loops_timeouts_update(ioloop_timeval.tv_sec -
						 ioloop->next_max_time);
			/* time moved forwards */
			ioloop->time_moved_callback(ioloop->next_max_time,
						    ioloop_timeval.tv_sec);
		}
		ioloop->ioloop_wait_usecs +=
			timeval_diff_usecs(&ioloop_timeval, &prev_ioloop_timeval);
	}

	ioloop_time = ioloop_timeval.tv_sec;
	tv_call = ioloop_timeval;

	while ((item = priorityq_peek(ioloop->timeouts)) != NULL) {
		struct timeout *timeout = (struct timeout *)item;

		/* use tv_call to make sure we don't get to infinite loop in
		   case callbacks update ioloop_timeval. */
		if (timeout_get_wait_time(timeout, &tv, &tv_call) > 0)
			break;

		if (timeout->one_shot) {
			/* remove timeout from queue */
			priorityq_remove(timeout->ioloop->timeouts, &timeout->item);
		} else {
			/* update timeout's next_run and reposition it in the queue */
			timeout_reset_timeval(timeout, &tv_call);
		}

		if (timeout->ctx != NULL)
			io_loop_context_activate(timeout->ctx);
		t_id = t_push_named("ioloop timeout handler %p",
				    (void *)timeout->callback);
		timeout->callback(timeout->context);
		if (!t_pop(&t_id)) {
			i_panic("Leaked a t_pop() call in timeout handler %p",
				(void *)timeout->callback);
		}
		if (ioloop->cur_ctx != NULL)
			io_loop_context_deactivate(ioloop->cur_ctx);
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
	data_stack_frame_t t_id;

	if (io->pending) {
		i_assert(ioloop->io_pending_count > 0);
		ioloop->io_pending_count--;
		io->pending = FALSE;
	}

	if (io->ctx != NULL)
		io_loop_context_activate(io->ctx);
	t_id = t_push_named("ioloop handler %p",
			    (void *)io->callback);
	io->callback(io->context);
	if (!t_pop(&t_id)) {
		i_panic("Leaked a t_pop() call in I/O handler %p",
			(void *)io->callback);
	}
	if (ioloop->cur_ctx != NULL)
		io_loop_context_deactivate(ioloop->cur_ctx);
}

void io_loop_run(struct ioloop *ioloop)
{
	if (ioloop->handler_context == NULL)
		io_loop_initialize_handler(ioloop);

	if (ioloop->cur_ctx != NULL)
		io_loop_context_unref(&ioloop->cur_ctx);

	/* recursive io_loop_run() isn't allowed for the same ioloop.
	   it can break backends. */
	i_assert(!ioloop->iolooping);
	ioloop->iolooping = TRUE;

	ioloop->running = TRUE;
	while (ioloop->running)
		io_loop_handler_run(ioloop);
	ioloop->iolooping = FALSE;
}

static void io_loop_call_pending(struct ioloop *ioloop)
{
	struct io_file *io;

	while (ioloop->io_pending_count > 0) {
		io = ioloop->io_files;
		do {
			ioloop->next_io_file = io->next;
			if (io->io.pending)
				io_loop_call_io(&io->io);
			if (ioloop->io_pending_count == 0)
				break;
			io = ioloop->next_io_file;
		} while (io != NULL);
	}
}

void io_loop_handler_run(struct ioloop *ioloop)
{
	io_loop_timeouts_start_new(ioloop);
	io_loop_handler_run_internal(ioloop);
	io_loop_call_pending(ioloop);
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

void io_loop_time_refresh(void)
{
	if (gettimeofday(&ioloop_timeval, NULL) < 0)
		i_fatal("gettimeofday(): %m");
	ioloop_time = ioloop_timeval.tv_sec;
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
	i_array_init(&ioloop->timeouts_new, 8);

	ioloop->time_moved_callback = current_ioloop != NULL ?
		current_ioloop->time_moved_callback :
		io_loop_default_time_moved;

	ioloop->prev = current_ioloop;
        io_loop_set_current(ioloop);
        return ioloop;
}

void io_loop_destroy(struct ioloop **_ioloop)
{
	struct ioloop *ioloop = *_ioloop;
	struct timeout *const *to_idx;
	struct priorityq_item *item;

	*_ioloop = NULL;

	/* ->prev won't work unless loops are destroyed in create order */
        i_assert(ioloop == current_ioloop);
	io_loop_set_current(current_ioloop->prev);

	if (ioloop->notify_handler_context != NULL)
		io_loop_notify_handler_deinit(ioloop);

	while (ioloop->io_files != NULL) {
		struct io_file *io = ioloop->io_files;
		struct io *_io = &io->io;

		i_warning("I/O leak: %p (line %u, fd %d)",
			  (void *)io->io.callback,
			  io->io.source_linenum, io->fd);
		io_remove(&_io);
	}
	i_assert(ioloop->io_pending_count == 0);

	array_foreach(&ioloop->timeouts_new, to_idx) {
		struct timeout *to = *to_idx;

		i_warning("Timeout leak: %p (line %u)", (void *)to->callback,
			  to->source_linenum);
		timeout_free(to);
	}
	array_free(&ioloop->timeouts_new);

	while ((item = priorityq_pop(ioloop->timeouts)) != NULL) {
		struct timeout *to = (struct timeout *)item;

		i_warning("Timeout leak: %p (line %u)", (void *)to->callback,
			  to->source_linenum);
		timeout_free(to);
	}
	priorityq_deinit(&ioloop->timeouts);

	if (ioloop->handler_context != NULL)
		io_loop_handler_deinit(ioloop);

	if (ioloop->cur_ctx != NULL)
		io_loop_context_deactivate(ioloop->cur_ctx);

	i_free(ioloop);
}

void io_loop_set_time_moved_callback(struct ioloop *ioloop,
				     io_loop_time_moved_callback_t *callback)
{
	ioloop->time_moved_callback = callback;
}

static void io_switch_callbacks_free(void)
{
	array_free(&io_switch_callbacks);
}

void io_loop_set_current(struct ioloop *ioloop)
{
	io_switch_callback_t *const *callbackp;
	struct ioloop *prev_ioloop = current_ioloop;

	current_ioloop = ioloop;
	if (array_is_created(&io_switch_callbacks)) {
		array_foreach(&io_switch_callbacks, callbackp)
			(*callbackp)(prev_ioloop);
	}
}

void io_loop_add_switch_callback(io_switch_callback_t *callback)
{
	if (!array_is_created(&io_switch_callbacks)) {
		i_array_init(&io_switch_callbacks, 4);
		lib_atexit(io_switch_callbacks_free);
	}
	array_append(&io_switch_callbacks, &callback, 1);
}

void io_loop_remove_switch_callback(io_switch_callback_t *callback)
{
	io_switch_callback_t *const *callbackp;
	unsigned int idx;

	array_foreach(&io_switch_callbacks, callbackp) {
		if (*callbackp == callback) {
			idx = array_foreach_idx(&io_switch_callbacks, callbackp);
			array_delete(&io_switch_callbacks, idx, 1);
			return;
		}
	}
	i_unreached();
}

struct ioloop_context *io_loop_context_new(struct ioloop *ioloop)
{
	struct ioloop_context *ctx;

	ctx = i_new(struct ioloop_context, 1);
	ctx->refcount = 2;
	ctx->ioloop = ioloop;
	i_array_init(&ctx->callbacks, 4);

	if (ioloop->cur_ctx != NULL)
		io_loop_context_unref(&ioloop->cur_ctx);
	ioloop->cur_ctx = ctx;
	return ctx;
}

void io_loop_context_ref(struct ioloop_context *ctx)
{
	i_assert(ctx->refcount > 0);

	ctx->refcount++;
}

void io_loop_context_unref(struct ioloop_context **_ctx)
{
	struct ioloop_context *ctx = *_ctx;

	*_ctx = NULL;

	i_assert(ctx->refcount > 0);
	if (--ctx->refcount > 0)
		return;

	/* cur_ctx itself keeps a reference */
	i_assert(ctx->ioloop->cur_ctx != ctx);

	array_free(&ctx->callbacks);
	i_free(ctx);
}

#undef io_loop_context_add_callbacks
void io_loop_context_add_callbacks(struct ioloop_context *ctx,
				   io_callback_t *activate,
				   io_callback_t *deactivate, void *context)
{
	struct ioloop_context_callback cb;

	memset(&cb, 0, sizeof(cb));
	cb.activate = activate;
	cb.deactivate = deactivate;
	cb.context = context;

	array_append(&ctx->callbacks, &cb, 1);
}

#undef io_loop_context_remove_callbacks
void io_loop_context_remove_callbacks(struct ioloop_context *ctx,
				      io_callback_t *activate,
				      io_callback_t *deactivate, void *context)
{
	struct ioloop_context_callback *cb;

	array_foreach_modifiable(&ctx->callbacks, cb) {
		if (cb->context == context &&
		    cb->activate == activate && cb->deactivate == deactivate) {
			/* simply mark it as deleted, since we could get
			   here from activate/deactivate loop */
			cb->activate = NULL;
			cb->deactivate = NULL;
			cb->context = NULL;
			return;
		}
	}
	i_panic("io_loop_context_remove_callbacks() context not found");
}

static void
io_loop_context_remove_deleted_callbacks(struct ioloop_context *ctx)
{
	const struct ioloop_context_callback *cbs;
	unsigned int i, count;

	cbs = array_get(&ctx->callbacks, &count);
	for (i = 0; i < count; ) {
		if (cbs[i].activate != NULL)
			i++;
		else {
			array_delete(&ctx->callbacks, i, 1);
			cbs = array_get(&ctx->callbacks, &count);
		}
	}
}

void io_loop_context_activate(struct ioloop_context *ctx)
{
	struct ioloop_context_callback *cb;

	i_assert(ctx->ioloop->cur_ctx == NULL);

	ctx->ioloop->cur_ctx = ctx;
	io_loop_context_ref(ctx);
	array_foreach_modifiable(&ctx->callbacks, cb) {
		i_assert(!cb->activated);
		if (cb->activate != NULL)
			cb->activate(cb->context);
		cb->activated = TRUE;
	}
}

void io_loop_context_deactivate(struct ioloop_context *ctx)
{
	struct ioloop_context_callback *cb;

	i_assert(ctx->ioloop->cur_ctx != NULL);

	array_foreach_modifiable(&ctx->callbacks, cb) {
		if (!cb->activated) {
			/* we just added this callback. don't deactivate it
			   before it gets first activated. */
		} else {
			if (cb->deactivate != NULL)
				cb->deactivate(cb->context);
			cb->activated = FALSE;
		}
	}
	ctx->ioloop->cur_ctx = NULL;
	io_loop_context_remove_deleted_callbacks(ctx);
	io_loop_context_unref(&ctx);
}

struct ioloop_context *io_loop_get_current_context(struct ioloop *ioloop)
{
	return ioloop->cur_ctx;
}

struct io *io_loop_move_io(struct io **_io)
{
	struct io *old_io = *_io;
	struct io_file *old_io_file, *new_io_file;

	i_assert((old_io->condition & IO_NOTIFY) == 0);

	if (old_io->ioloop == current_ioloop)
		return old_io;

	old_io_file = (struct io_file *)old_io;
	new_io_file = io_add_file(old_io_file->fd, old_io->condition,
				  old_io->source_linenum,
				  old_io->callback, old_io->context);
	if (old_io_file->istream != NULL) {
		/* reference before io_remove() */
		new_io_file->istream = old_io_file->istream;
		i_stream_ref(new_io_file->istream);
	}
	if (old_io->pending)
		io_set_pending(&new_io_file->io);
	io_remove(_io);
	if (new_io_file->istream != NULL) {
		/* update istream io after it was removed with io_remove() */
		i_stream_set_io(new_io_file->istream, &new_io_file->io);
	}
	return &new_io_file->io;
}

struct timeout *io_loop_move_timeout(struct timeout **_timeout)
{
	struct timeout *new_to, *old_to = *_timeout;

	if (old_to->ioloop == current_ioloop)
		return old_to;

	new_to = timeout_copy(old_to);
	timeout_remove(_timeout);
	return new_to;
}

bool io_loop_have_ios(struct ioloop *ioloop)
{
	return ioloop->io_files != NULL;
}

bool io_loop_have_immediate_timeouts(struct ioloop *ioloop)
{
	struct timeval tv;

	return io_loop_get_wait_time(ioloop, &tv) == 0;
}

uint64_t io_loop_get_wait_usecs(struct ioloop *ioloop)
{
	return ioloop->ioloop_wait_usecs;
}

enum io_condition io_loop_find_fd_conditions(struct ioloop *ioloop, int fd)
{
	enum io_condition conditions = 0;
	struct io_file *io;

	i_assert(fd >= 0);

	for (io = ioloop->io_files; io != NULL; io = io->next) {
		if (io->fd == fd)
			conditions |= io->io.condition;
	}
	return conditions;
}
