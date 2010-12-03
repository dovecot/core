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
		  io_callback_t *callback, void *context);
#define io_add(fd, condition, callback, context) \
	CONTEXT_CALLBACK(io_add, io_callback_t, \
			 callback, context, fd, condition)
enum io_notify_result io_add_notify(const char *path, io_callback_t *callback,
				    void *context, struct io **io_r);
#ifdef CONTEXT_TYPE_SAFETY
#  define io_add_notify(path, callback, context, io_r) \
	({(void)(1 ? 0 : callback(context)); \
	io_add_notify(path, (io_callback_t *)callback, context, io_r); })
#else
#  define io_add_notify(path, callback, context, io_r) \
	io_add_notify(path, (io_callback_t *)callback, context, io_r)
#endif

/* Remove I/O handler, and set io pointer to NULL. */
void io_remove(struct io **io);
/* Like io_remove(), but assume that the file descriptor is already closed.
   With some backends this simply frees the memory. */
void io_remove_closed(struct io **io);

/* Timeout handlers */
struct timeout *timeout_add(unsigned int msecs, timeout_callback_t *callback,
			    void *context);
#define timeout_add(msecs, callback, context) \
	CONTEXT_CALLBACK(timeout_add, timeout_callback_t, \
			 callback, context, msecs)
/* Remove timeout handler, and set timeout pointer to NULL. */
void timeout_remove(struct timeout **timeout);
/* Reset timeout so it's next run after now+msecs. */
void timeout_reset(struct timeout *timeout);

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

/* This log is used for all further I/O and timeout callbacks that are added
   until returning to ioloop. */
struct ioloop_log *io_loop_log_new(struct ioloop *ioloop);
void io_loop_log_ref(struct ioloop_log *log);
void io_loop_log_unref(struct ioloop_log **log);
/* Set the log's prefix. Note that this doesn't immediately call
   i_set_failure_prefix(). */
void io_loop_log_set_prefix(struct ioloop_log *log, const char *prefix);
/* Set the default log prefix to use outside callbacks. */
void io_loop_set_default_log_prefix(struct ioloop *ioloop, const char *prefix);

#endif
