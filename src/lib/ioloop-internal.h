#ifndef IOLOOP_INTERNAL_H
#define IOLOOP_INTERNAL_H

#include "priorityq.h"
#include "ioloop.h"

#ifndef IOLOOP_INITIAL_FD_COUNT
#  define IOLOOP_INITIAL_FD_COUNT 128
#endif

struct ioloop {
        struct ioloop *prev;

	struct ioloop_log *cur_log;
	char *default_log_prefix;

	struct io_file *io_files;
	struct io_file *next_io_file;
	struct priorityq *timeouts;

        struct ioloop_handler_context *handler_context;
        struct ioloop_notify_handler_context *notify_handler_context;
	unsigned int max_fd_count;

	io_loop_time_moved_callback_t *time_moved_callback;
	time_t next_max_time;

	unsigned int running:1;
};

struct io {
	enum io_condition condition;

	io_callback_t *callback;
        void *context;

	struct ioloop *ioloop;
	struct ioloop_log *log;
};

struct io_file {
	struct io io;

	/* use a doubly linked list so that io_remove() is quick */
	struct io_file *prev, *next;

	int refcount;
	int fd;
};

struct timeout {
	struct priorityq_item item;

        unsigned int msecs;
	struct timeval next_run;

	timeout_callback_t *callback;
        void *context;

	struct ioloop *ioloop;
	struct ioloop_log *log;
};

struct ioloop_log {
	int refcount;
	char *prefix;
	struct ioloop *ioloop;
};

int io_loop_get_wait_time(struct ioloop *ioloop, struct timeval *tv_r);
void io_loop_handle_timeouts(struct ioloop *ioloop);
void io_loop_call_io(struct io *io);

/* I/O handler calls */
void io_loop_handle_add(struct io_file *io);
void io_loop_handle_remove(struct io_file *io, bool closed);

void io_loop_handler_init(struct ioloop *ioloop, unsigned int initial_fd_count);
void io_loop_handler_deinit(struct ioloop *ioloop);

void io_loop_notify_remove(struct io *io);
void io_loop_notify_handler_deinit(struct ioloop *ioloop);

#endif
