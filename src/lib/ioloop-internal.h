#ifndef __IOLOOP_INTERNAL_H
#define __IOLOOP_INTERNAL_H

#include "ioloop.h"

#include <sys/time.h>

typedef struct _IOLoopHandlerData IOLoopHandlerData;

struct _IOLoop {
        struct _IOLoop *prev;

	Pool pool;
	int highest_fd;

	IO ios; /* sorted by priority */
	Timeout timeouts; /* sorted by next_run */

        IOLoopHandlerData *handler_data;

	unsigned int running:1;
};

struct _IO {
	IO prev, next;

	int fd;
        int priority;
	int condition;

	unsigned int destroyed:1;
	unsigned int invalid:1;

	IOFunc func;
        void *user_data;
};

struct _Timeout {
	Timeout next;

	struct timeval next_run;
        int msecs;
	int run_now;
        int destroyed;

	TimeoutFunc func;
        void *user_data;
};

int io_loop_get_wait_time(Timeout timeout, struct timeval *tv,
			  struct timeval *tv_now);
void io_loop_handle_timeouts(IOLoop ioloop);

/* call only when io->destroyed is TRUE */
void io_destroy(IOLoop ioloop, IO io);
/* call only when timeout->destroyed is TRUE */
void timeout_destroy(IOLoop ioloop, Timeout timeout);

/* I/O handler calls */
void io_loop_handle_add(IOLoop ioloop, int fd, int condition);
void io_loop_handle_remove(IOLoop ioloop, int fd, int condition);

void io_loop_handler_init(IOLoop ioloop);
void io_loop_handler_deinit(IOLoop ioloop);

#endif
