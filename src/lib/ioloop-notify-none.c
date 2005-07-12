/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "ioloop-internal.h"

#ifdef IOLOOP_NOTIFY_NONE

struct io *io_loop_notify_add(struct ioloop *ioloop __attr_unused__,
			      int fd __attr_unused__,
			      enum io_condition condition __attr_unused__,
			      io_callback_t *callback __attr_unused__,
			      void *context __attr_unused__)
{
	return NULL;
}

void io_loop_notify_remove(struct ioloop *ioloop __attr_unused__,
			   struct io *io __attr_unused__)
{
}

void io_loop_notify_handler_init(struct ioloop *ioloop __attr_unused__)
{
}

void io_loop_notify_handler_deinit(struct ioloop *ioloop __attr_unused__)
{
}

#endif
