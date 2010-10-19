/*
 * Copyright (c) 2004 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "lib.h"
#include "ioloop-internal.h"
#include "ioloop-iolist.h"

bool ioloop_iolist_add(struct io_list *list, struct io_file *io)
{
	int i, idx;

	if ((io->io.condition & IO_READ) != 0)
		idx = IOLOOP_IOLIST_INPUT;
	else if ((io->io.condition & IO_WRITE) != 0)
		idx = IOLOOP_IOLIST_OUTPUT;
	else if ((io->io.condition & IO_ERROR) != 0)
		idx = IOLOOP_IOLIST_ERROR;
	else {
		i_unreached();
	}

	if (list->ios[idx] != NULL) {
		i_panic("io_add(0x%x) called twice fd=%d, callback=%p -> %p",
			io->io.condition, io->fd, list->ios[idx]->io.callback,
			io->io.callback);
	}
	i_assert(list->ios[idx] == NULL);
	list->ios[idx] = io;

	/* check if this was the first one */
	for (i = 0; i < IOLOOP_IOLIST_IOS_PER_FD; i++) {
		if (i != idx && list->ios[i] != NULL)
			return FALSE;
	}

	return TRUE;
}

bool ioloop_iolist_del(struct io_list *list, struct io_file *io)
{
	bool last = TRUE;
	int i;

	for (i = 0; i < IOLOOP_IOLIST_IOS_PER_FD; i++) {
		if (list->ios[i] != NULL) {
			if (list->ios[i] == io)
				list->ios[i] = NULL;
			else
				last = FALSE;
		}
	}
	return last;
}
