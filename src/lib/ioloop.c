/* Copyright (c) 2002-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "time-util.h"
#include "ioloop-private.h"

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
		  unsigned int source_linenum,
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
	io->io.source_linenum = source_linenum;
	io->refcount = 1;
	io->fd = fd;

	if (io->io.ioloop->cur_ctx != NULL) {
		io->io.ctx = io->io.ioloop->cur_ctx;
		io_loop_context_ref(io->io.ctx);
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

	if (io->ctx != NULL)
		io_loop_context_unref(&io->ctx);

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
struct timeout *timeout_add(unsigned int msecs, unsigned int source_linenum,
			    timeout_callback_t *callback, void *context)
{
	struct timeout *timeout;

	timeout = i_new(struct timeout, 1);
        timeout->source_linenum = source_linenum;
        timeout->msecs = msecs;
	timeout->ioloop = current_ioloop;

	timeout->callback = callback;
	timeout->context = context;

	if (timeout->ioloop->cur_ctx != NULL) {
		timeout->ctx = timeout->ioloop->cur_ctx;
		io_loop_context_ref(timeout->ctx);
	}

	timeout_update_next(timeout, timeout->ioloop->running ?
			    NULL : &ioloop_timeval);
	priorityq_add(timeout->ioloop->timeouts, &timeout->item);
	return timeout;
}

#undef timeout_add_short
struct timeout *
timeout_add_short(unsigned int msecs, unsigned int source_linenum,
		  timeout_callback_t *callback, void *context)
{
	return timeout_add(msecs, source_linenum, callback, context);
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

		if (timeout->ctx != NULL)
			io_loop_context_activate(timeout->ctx);
                t_id = t_push();
		timeout->callback(timeout->context);
		if (t_pop() != t_id) {
			i_panic("Leaked a t_pop() call in timeout handler %p",
				(void *)timeout->callback);
		}
		if (ioloop->cur_ctx != NULL)
			io_loop_context_activate(ioloop->cur_ctx);
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

	if (io->ctx != NULL)
		io_loop_context_activate(io->ctx);
	t_id = t_push();
	io->callback(io->context);
	if (t_pop() != t_id) {
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

		i_warning("I/O leak: %p (line %u, fd %d)",
			  (void *)io->io.callback,
			  io->io.source_linenum, io->fd);
		io_remove(&_io);
	}

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
	const struct ioloop_context_callback *cb;

	ctx->ioloop->cur_ctx = ctx;
	io_loop_context_ref(ctx);
	array_foreach(&ctx->callbacks, cb) {
		if (cb->activate != NULL)
			cb->activate(cb->context);
	}
}

void io_loop_context_deactivate(struct ioloop_context *ctx)
{
	const struct ioloop_context_callback *cb;

	array_foreach(&ctx->callbacks, cb) {
		if (cb->deactivate != NULL)
			cb->deactivate(cb->context);
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
	struct io *new_io, *old_io = *_io;
	struct io_file *old_io_file;

	i_assert((old_io->condition & IO_NOTIFY) == 0);

	if (old_io->ioloop == current_ioloop)
		return old_io;

	old_io_file = (struct io_file *)old_io;
	new_io = io_add(old_io_file->fd, old_io->condition,
			old_io->source_linenum,
			old_io->callback, old_io->context);
	io_remove(_io);
	return new_io;
}

struct timeout *io_loop_move_timeout(struct timeout **_timeout)
{
	struct timeout *new_to, *old_to = *_timeout;

	if (old_to->ioloop == current_ioloop)
		return old_to;

	new_to = timeout_add(old_to->msecs, old_to->source_linenum,
			     old_to->callback, old_to->context);
	timeout_remove(_timeout);
	return new_to;
}
