#ifndef IOLOOP_IOLIST_H
#define IOLOOP_IOLIST_H

enum {
	IOLOOP_IOLIST_INPUT,
	IOLOOP_IOLIST_OUTPUT,
	IOLOOP_IOLIST_ERROR,

	IOLOOP_IOLIST_IOS_PER_FD
};

struct io_list {
	struct io_file *ios[IOLOOP_IOLIST_IOS_PER_FD];
};

bool ioloop_iolist_add(struct io_list *list, struct io_file *io);
bool ioloop_iolist_del(struct io_list *list, struct io_file *io);

#endif
