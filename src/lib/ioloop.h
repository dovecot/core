#ifndef IOLOOP_H
#define IOLOOP_H

#include <sys/time.h>
#include <time.h>

struct io;
struct timeout;
struct ioloop;

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

/* Time when the I/O loop started calling handlers.
   Can be used instead of time(NULL). */
extern time_t ioloop_time;
extern struct timeval ioloop_timeval;

extern struct ioloop *current_ioloop;

/* You can create different handlers for IO_READ and IO_WRITE. IO_READ and
   IO_ERROR can't use different handlers (and there's no point anyway).

   Don't try to add multiple handlers for the same type. It's not checked and
   the behavior will be undefined. */
struct io *io_add(int fd, enum io_condition condition,
		  unsigned int source_linenum,
		  io_callback_t *callback, void *context) ATTR_NULL(5);
#define io_add(fd, condition, callback, context) \
	io_add(fd, condition, __LINE__ + \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(io_callback_t *)callback, context)
enum io_notify_result
io_add_notify(const char *path, io_callback_t *callback,
	      void *context, struct io **io_r) ATTR_NULL(3);
#define io_add_notify(path, callback, context, io_r) \
	io_add_notify(path + \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(io_callback_t *)callback, context, io_r)

/* Remove I/O handler, and set io pointer to NULL. */
void io_remove(struct io **io);
/* Like io_remove(), but assume that the file descriptor is already closed.
   With some backends this simply frees the memory. */
void io_remove_closed(struct io **io);

/* Timeout handlers */
struct timeout *
timeout_add(unsigned int msecs, unsigned int source_linenum,
	    timeout_callback_t *callback, void *context) ATTR_NULL(4);
#define timeout_add(msecs, callback, context) \
	timeout_add(msecs, __LINE__ + \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))) + \
		COMPILE_ERROR_IF_TRUE(__builtin_constant_p(msecs) && \
				      (msecs > 0 && msecs < 1000)), \
		(io_callback_t *)callback, context)
struct timeout *
timeout_add_short(unsigned int msecs, unsigned int source_linenum,
		  timeout_callback_t *callback, void *context) ATTR_NULL(4);
#define timeout_add_short(msecs, callback, context) \
	timeout_add_short(msecs, __LINE__ + \
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

/* This context is used for all further I/O and timeout callbacks that are
   added until returning to ioloop. When a callback is called, this context is
   again activated. */
struct ioloop_context *io_loop_context_new(struct ioloop *ioloop);
void io_loop_context_ref(struct ioloop_context *ctx);
void io_loop_context_unref(struct ioloop_context **ctx);
/* Call the activate callback when this context is activated (I/O callback is
   about to be called), and the deactivate callback when the context is
   deactivated (I/O callback has returned). You can add multiple callbacks. */
void io_loop_context_add_callbacks(struct ioloop_context *ctx,
				   io_callback_t *activate,
				   io_callback_t *deactivate, void *context);
/* Remove callbacks with the given callbacks and context. */
void io_loop_context_remove_callbacks(struct ioloop_context *ctx,
				      io_callback_t *activate,
				      io_callback_t *deactivate, void *context);
/* Returns the current context set to ioloop. */
struct ioloop_context *io_loop_get_current_context(struct ioloop *ioloop);

/* Move the given I/O into the current I/O loop if it's not already
   there. New I/O is returned, while the old one is freed. */
struct io *io_loop_move_io(struct io **io);
/* Like io_loop_move_io(), but for timeouts. */
struct timeout *io_loop_move_timeout(struct timeout **timeout);
/* Returns TRUE if any IOs have been added to the ioloop. */
bool io_loop_have_ios(struct ioloop *ioloop);
/* Returns TRUE if there is a pending timeout that is going to be run
   immediately. */
bool io_loop_have_immediate_timeouts(struct ioloop *ioloop);

#endif
