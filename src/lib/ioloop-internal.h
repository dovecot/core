#ifndef __IOLOOP_INTERNAL_H
#define __IOLOOP_INTERNAL_H

#include "ioloop.h"

struct ioloop {
        struct ioloop *prev;

	pool_t pool;

	struct io *ios;
	struct io *notifys, *event_io;
	struct io *next_io;
	struct timeout *timeouts; /* sorted by next_run */

        struct ioloop_handler_data *handler_data;

	unsigned int running:1;
};

struct io {
	struct io *prev, *next;

	int fd;
	enum io_condition condition;

	io_callback_t *callback;
        void *context;
};

struct timeout {
	struct timeout *next;

	struct timeval next_run;
        unsigned int msecs;

	unsigned int run_now:1;
	unsigned int destroyed:1;

	timeout_callback_t *callback;
        void *context;
};

int io_loop_get_wait_time(struct timeout *timeout, struct timeval *tv,
			  struct timeval *tv_now);
void io_loop_handle_timeouts(struct ioloop *ioloop);

/* call only when timeout->destroyed is TRUE */
void timeout_destroy(struct ioloop *ioloop, struct timeout **timeout_p);

/* I/O handler calls */
void io_loop_handle_add(struct ioloop *ioloop, struct io *io);
void io_loop_handle_remove(struct ioloop *ioloop, struct io *io);

void io_loop_handler_init(struct ioloop *ioloop);
void io_loop_handler_deinit(struct ioloop *ioloop);

struct io *io_loop_notify_add(struct ioloop *ioloop, int fd,
			      enum io_condition condition,
			      io_callback_t *callback, void *context);
void io_loop_notify_remove(struct ioloop *ioloop, struct io *io);

#endif
