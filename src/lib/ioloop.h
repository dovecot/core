#ifndef __IOLOOP_H
#define __IOLOOP_H

#include <time.h>

#define IO_READ			(1 << 0)
#define IO_WRITE		(1 << 1)

#define IO_PRIORITY_LOW		100
#define IO_PRIORITY_DEFAULT	0
#define IO_PRIORITY_HIGH	-100

typedef void (*IOFunc) (void *context, int fd, IO io);
typedef void (*TimeoutFunc) (void *context, Timeout timeout);

/* Time when the I/O loop started calling handlers.
   Can be used instead of time(NULL). */
extern time_t ioloop_time;
extern struct timeval ioloop_timeval;

/* I/O listeners - you can create different handlers for IO_READ and IO_WRITE,
   but make sure you don't create multiple handlers of same type, it's not
   checked and removing one will stop the other from working as well. */
IO io_add(int fd, int condition, IOFunc func, void *context);
IO io_add_priority(int fd, int priority, int condition,
		   IOFunc func, void *context);
void io_remove(IO io);

/* Timeout handlers */
Timeout timeout_add(int msecs, TimeoutFunc func, void *context);
void timeout_remove(Timeout timeout);

void io_loop_run(IOLoop ioloop);
void io_loop_stop(IOLoop ioloop); /* safe to run in signal handler */

/* call these if you wish to run the iteration only once */
void io_loop_set_running(IOLoop ioloop);
void io_loop_handler_run(IOLoop ioloop);

IOLoop io_loop_create(Pool pool);
void io_loop_destroy(IOLoop ioloop);

#endif
