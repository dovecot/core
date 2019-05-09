#ifndef IOLOOP_H
#define IOLOOP_H

#include <sys/time.h>
#include <time.h>

struct io;
struct timeout;
struct ioloop;
struct istream;

enum io_condition {
	IO_READ		= 0x01,
	IO_WRITE	= 0x02,
	/* IO_ERROR can be used to check when writable pipe's reader side
	   closes the pipe. For other uses IO_READ should work just as well. */
	IO_ERROR	= 0x04,
	
	/* internal */
	IO_NOTIFY	= 0x08
};

enum io_notify_result {
	/* Notify added successfully */
	IO_NOTIFY_ADDED,
	/* Specified file doesn't exist, can't wait on it */
	IO_NOTIFY_NOTFOUND,
	/* Can't add notify for specified file. Main reasons for this:
	   a) No notify support at all, b) Only directory notifies supported */
	IO_NOTIFY_NOSUPPORT
};

typedef void io_callback_t(void *context);
typedef void timeout_callback_t(void *context);
typedef void io_loop_time_moved_callback_t(time_t old_time, time_t new_time);
typedef void io_switch_callback_t(struct ioloop *prev_ioloop);

/* Time when the I/O loop started calling handlers.
   Can be used instead of time(NULL). */
extern time_t ioloop_time;
extern struct timeval ioloop_timeval;

extern struct ioloop *current_ioloop;
/* Number of microseconds spent on all the ioloops waiting for themselves. */
extern uint64_t ioloop_global_wait_usecs;

/* You can create different handlers for IO_READ and IO_WRITE. IO_READ and
   IO_ERROR can't use different handlers (and there's no point anyway).

   Don't try to add multiple handlers for the same type. It's not checked and
   the behavior will be undefined. */
struct io *io_add(int fd, enum io_condition condition,
		  const char *source_filename,
		  unsigned int source_linenum,
		  io_callback_t *callback, void *context) ATTR_NULL(5);
#define io_add(fd, condition, callback, context) \
	io_add(fd, condition, __FILE__, __LINE__ - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(io_callback_t *)callback, context)
struct io *io_add_to(struct ioloop *ioloop, int fd, enum io_condition condition,
		  const char *source_filename,
		  unsigned int source_linenum,
		  io_callback_t *callback, void *context) ATTR_NULL(5);
#define io_add_to(ioloop, fd, condition, callback, context) \
	io_add_to(ioloop, fd, condition, __FILE__, __LINE__ - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(io_callback_t *)callback, context)

enum io_notify_result
io_add_notify(const char *path, const char *source_filename,
	      unsigned int source_linenum,
	      io_callback_t *callback, void *context,
	      struct io **io_r) ATTR_NULL(3);
#define io_add_notify(path, callback, context, io_r) \
	io_add_notify(path, __FILE__, __LINE__ - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(io_callback_t *)callback, context, io_r)

struct io *io_add_istream(struct istream *input, const char *source_filename,
			  unsigned int source_linenum,
			  io_callback_t *callback, void *context) ATTR_NULL(3);
#define io_add_istream(input, callback, context) \
	io_add_istream(input, __FILE__, __LINE__ - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(io_callback_t *)callback, context)
struct io *io_add_istream_to(struct ioloop *ioloop, struct istream *input,
			     const char *source_filename,
			     unsigned int source_linenum,
			     io_callback_t *callback, void *context)
	ATTR_NULL(3);
#define io_add_istream_to(ioloop, input, callback, context) \
	io_add_istream_to(ioloop, input, __FILE__, __LINE__ - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(io_callback_t *)callback, context)

/* Remove I/O handler, and set io pointer to NULL. */
void io_remove(struct io **io);
/* Like io_remove(), but assume that the file descriptor is already closed.
   With some backends this simply frees the memory. */
void io_remove_closed(struct io **io);

/* Make sure the I/O callback is called by io_loop_run() even if there isn't
   any input actually pending currently as seen by the OS. This may be useful
   if some of the input has already read into some internal buffer and the
   caller wants to handle it the same way as if the fd itself had input. */
void io_set_pending(struct io *io);
/* Returns TRUE if io_set_pending() has been called for the IO and its callback
   hasn't been called yet. */
bool io_is_pending(struct io *io);
/* If set, this IO shouldn't be the only thing being waited on, because
   it would just result in infinite wait. In those situations rather just
   crash to indicate that there's a bug. */
void io_set_never_wait_alone(struct io *io, bool set);

/* Timeout handlers */
struct timeout *
timeout_add(unsigned int msecs, const char *source_filename,
	    unsigned int source_linenum,
	    timeout_callback_t *callback, void *context) ATTR_NULL(4);
#define timeout_add(msecs, callback, context) \
	timeout_add(msecs, __FILE__, __LINE__ - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))) - \
		COMPILE_ERROR_IF_TRUE(__builtin_constant_p(msecs) && \
				      ((msecs) > 0 && (msecs) < 1000)), \
		(io_callback_t *)callback, context)
struct timeout *
timeout_add_to(struct ioloop *ioloop, unsigned int msecs,
	       const char *source_filename, unsigned int source_linenum,
	       timeout_callback_t *callback, void *context) ATTR_NULL(4);
#define timeout_add_to(ioloop, msecs, callback, context) \
	timeout_add_to(ioloop, msecs, __FILE__, __LINE__ - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))) - \
		COMPILE_ERROR_IF_TRUE(__builtin_constant_p(msecs) && \
				      ((msecs) > 0 && (msecs) < 1000)), \
		(io_callback_t *)callback, context)

struct timeout *
timeout_add_short(unsigned int msecs, const char *source_filename,
		  unsigned int source_linenum,
		  timeout_callback_t *callback, void *context) ATTR_NULL(4);
#define timeout_add_short(msecs, callback, context) \
	timeout_add_short(msecs, __FILE__, __LINE__ - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(io_callback_t *)callback, context)
struct timeout *
timeout_add_short_to(struct ioloop *ioloop, unsigned int msecs,
		     const char *source_filename, unsigned int source_linenum,
		     timeout_callback_t *callback, void *context) ATTR_NULL(4);
#define timeout_add_short_to(ioloop, msecs, callback, context) \
	timeout_add_short_to(ioloop, msecs, __FILE__, __LINE__ - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(io_callback_t *)callback, context)

struct timeout *
timeout_add_absolute(const struct timeval *time,
		     const char *source_filename,
		     unsigned int source_linenum,
		     timeout_callback_t *callback, void *context) ATTR_NULL(4);
#define timeout_add_absolute(time, callback, context) \
	timeout_add_absolute(time, __FILE__, __LINE__ - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(io_callback_t *)callback, context)
struct timeout *
timeout_add_absolute_to(struct ioloop *ioloop,
			const struct timeval *time,
			const char *source_filename,
			unsigned int source_linenum,
			timeout_callback_t *callback, void *context) ATTR_NULL(4);
#define timeout_add_absolute_to(ioloop, time, callback, context) \
	timeout_add_absolute_to(ioloop, time, __FILE__, __LINE__ - \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(io_callback_t *)callback, context)

/* Remove timeout handler, and set timeout pointer to NULL. */
void timeout_remove(struct timeout **timeout);
/* Reset timeout so it's next run after now+msecs. */
void timeout_reset(struct timeout *timeout);

/* Refresh ioloop_time and ioloop_timeval variables. */
void io_loop_time_refresh(void);

void io_loop_run(struct ioloop *ioloop);
void io_loop_stop(struct ioloop *ioloop); /* safe to run in signal handler */

bool io_loop_is_running(struct ioloop *ioloop);

/* call these if you wish to run the iteration only once */
void io_loop_set_running(struct ioloop *ioloop);
void io_loop_handler_run(struct ioloop *ioloop);

struct ioloop *io_loop_create(void);
/* Specify the maximum number of fds we're expecting to use. */
void io_loop_set_max_fd_count(struct ioloop *ioloop, unsigned int max_fds);
/* Destroy I/O loop and set ioloop pointer to NULL. */
void io_loop_destroy(struct ioloop **ioloop);

/* If time moves backwards or jumps forwards call the callback. */
void io_loop_set_time_moved_callback(struct ioloop *ioloop,
				     io_loop_time_moved_callback_t *callback);

/* Change the current_ioloop. */
void io_loop_set_current(struct ioloop *ioloop);
/* Call the callback whenever ioloop is changed. */
void io_loop_add_switch_callback(io_switch_callback_t *callback);
void io_loop_remove_switch_callback(io_switch_callback_t *callback);

/* Create a new ioloop context. This context is automatically attached to all
   the following I/Os and timeouts that are added until the context is
   deactivated (e.g. returning to back to a running ioloop). Whenever such
   added I/O or timeout callback is called, this context is automatically
   activated.

   Creating this context already deactivates any currently running context
   and activates the newly created context. */
struct ioloop_context *io_loop_context_new(struct ioloop *ioloop);
void io_loop_context_ref(struct ioloop_context *ctx);
void io_loop_context_unref(struct ioloop_context **ctx);
/* Call the activate callback when this context is activated (I/O callback is
   about to be called), and the deactivate callback when the context is
   deactivated (I/O callback has returned). You can add multiple callbacks.

   The ioloop context is a global state, so only a single context can be active
   at a time. The callbacks are guaranteed to be called only at their proper
   states, i.e. activate() callback is called only when switching from
   no context to the active context, and deactive() is called only when
   switching from previously activated context into no context. No context is
   active at a time when the ioloop is destroyed. */
void io_loop_context_add_callbacks(struct ioloop_context *ctx,
				   io_callback_t *activate,
				   io_callback_t *deactivate, void *context);
#define io_loop_context_add_callbacks(ctx, activate, deactivate, context) \
	io_loop_context_add_callbacks(ctx, 1 ? (io_callback_t *)activate : \
		CALLBACK_TYPECHECK(activate, void (*)(typeof(context))) - \
		CALLBACK_TYPECHECK(deactivate, void (*)(typeof(context))), \
		(io_callback_t *)deactivate, context)
/* Remove callbacks with the given callbacks and context. */
void io_loop_context_remove_callbacks(struct ioloop_context *ctx,
				      io_callback_t *activate,
				      io_callback_t *deactivate, void *context);
#define io_loop_context_remove_callbacks(ctx, activate, deactivate, context) \
	io_loop_context_remove_callbacks(ctx, 1 ? (io_callback_t *)activate : \
		CALLBACK_TYPECHECK(activate, void (*)(typeof(context))) - \
		CALLBACK_TYPECHECK(deactivate, void (*)(typeof(context))), \
		(io_callback_t *)deactivate, context)
/* Returns the current context set to ioloop. */
struct ioloop_context *io_loop_get_current_context(struct ioloop *ioloop);

/* Explicitly activate an ioloop context. There must not be any context active
   at the moment, so this most likely shouldn't be called while ioloop is
   running. An activated context must be explicitly deactivated with
   io_loop_context_deactivate() before the ioloop is destroyed, or before
   any ioloop is run. */
void io_loop_context_activate(struct ioloop_context *ctx);
/* Explicitly deactivate an ioloop context. The given context must be currently
   active or it assert-crashes. This should be called only after a context
   was explicitly activated with io_loop_context_activate(). */
void io_loop_context_deactivate(struct ioloop_context *ctx);

/* Returns fd, which contains all of the ioloop's current notifications.
   When it becomes readable, there is a new notification. Calling this function
   stops the existing notifications in the ioloop from working anymore.
   This function's main idea is that the fd can be passed to another process,
   which can use it to find out if an interesting notification happens.
   Returns fd on success, -1 on error. */
int io_loop_extract_notify_fd(struct ioloop *ioloop);

/* IO wait timers can be used to track how much time the io_wait_timer has
   spent on waiting in its ioloops. This is similar to
   io_loop_get_wait_usecs(), but it's easier to use when the wait time needs
   to be tracked across multiple ioloops. */
struct io_wait_timer *
io_wait_timer_add(const char *source_filename, unsigned int source_linenum);
#define io_wait_timer_add() \
	io_wait_timer_add(__FILE__, __LINE__)
struct io_wait_timer *
io_wait_timer_add_to(struct ioloop *ioloop, const char *source_filename,
		     unsigned int source_linenum);
#define io_wait_timer_add_to(ioloop) \
	io_wait_timer_add_to(ioloop, __FILE__, __LINE__)

struct io_wait_timer *io_wait_timer_move(struct io_wait_timer **timer);
struct io_wait_timer *io_wait_timer_move_to(struct io_wait_timer **timer,
					    struct ioloop *ioloop);
void io_wait_timer_remove(struct io_wait_timer **timer);
uint64_t io_wait_timer_get_usecs(struct io_wait_timer *timer);

/* Move the given I/O into the provided/current I/O loop if it's not already
   there. New I/O is returned, while the old one is freed. */
struct io *io_loop_move_io_to(struct ioloop *ioloop, struct io **_io);
struct io *io_loop_move_io(struct io **io);
/* Like io_loop_move_io(), but for timeouts. */
struct timeout *io_loop_move_timeout_to(struct ioloop *ioloop,
					struct timeout **timeout);
struct timeout *io_loop_move_timeout(struct timeout **timeout);
/* Returns TRUE if any IOs have been added to the ioloop. */
bool io_loop_have_ios(struct ioloop *ioloop);
/* Returns TRUE if there is a pending timeout that is going to be run
   immediately. */
bool io_loop_have_immediate_timeouts(struct ioloop *ioloop);
/* Returns number of microseconds spent on the ioloop waiting itself. */
uint64_t io_loop_get_wait_usecs(struct ioloop *ioloop);
/* Return all io conditions added for the given fd. This needs to scan through
   all the file ios in the ioloop. */
enum io_condition io_loop_find_fd_conditions(struct ioloop *ioloop, int fd);

#endif
