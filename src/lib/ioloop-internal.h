#ifndef IOLOOP_INTERNAL_H
#define IOLOOP_INTERNAL_H

#include "ioloop.h"

#ifndef IOLOOP_INITIAL_FD_COUNT
#  define IOLOOP_INITIAL_FD_COUNT 128
#endif

struct ioloop {
        struct ioloop *prev;

	struct io_file *io_files;
	struct io_file *next_io_file;
	struct timeout *timeouts; /* sorted by next_run */

        struct ioloop_handler_context *handler_context;
        struct ioloop_notify_handler_context *notify_handler_context;

	unsigned int running:1;
};

struct io {
	enum io_condition condition;

	io_callback_t *callback;
        void *context;
};

struct io_file {
	struct io io;

	/* use a doubly linked list so that io_remove() is quick */
	struct io_file *prev, *next;

	int refcount;
	int fd;
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
void io_loop_handle_timeouts(struct ioloop *ioloop, bool update_run_now);

/* I/O handler calls */
void io_loop_handle_add(struct ioloop *ioloop, struct io_file *io);
void io_loop_handle_remove(struct ioloop *ioloop, struct io_file *io);

void io_loop_handler_init(struct ioloop *ioloop);
void io_loop_handler_deinit(struct ioloop *ioloop);

void io_loop_notify_remove(struct ioloop *ioloop, struct io *io);
void io_loop_notify_handler_deinit(struct ioloop *ioloop);

#endif
