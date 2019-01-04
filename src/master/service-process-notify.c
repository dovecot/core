/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "aqueue.h"
#include "ioloop.h"
#include "service.h"
#include "service-process.h"
#include "service-process-notify.h"

struct service_process_notify {
	service_process_notify_callback_t *write_callback;

	int fd;
	struct io *io_write;
	struct aqueue *process_queue;
	ARRAY(struct service_process *) processes;
};

struct service_process_notify *
service_process_notify_init(int fd,
			    service_process_notify_callback_t *write_callback)
{
	struct service_process_notify *notify;

	notify = i_new(struct service_process_notify, 1);
	notify->fd = fd;
	notify->write_callback = write_callback;

	i_array_init(&notify->processes, 64);
	notify->process_queue = aqueue_init(&notify->processes.arr);
	return notify;
}

static void service_process_notify_reset(struct service_process_notify *notify)
{
	struct service_process *const *processes, *process;
	unsigned int i, count;

	if (notify->io_write == NULL)
		return;

	processes = array_first_modifiable(&notify->processes);
	count = aqueue_count(notify->process_queue);
	for (i = 0; i < count; i++) {
		process = processes[aqueue_idx(notify->process_queue, i)];
		service_process_unref(process);
	}
	aqueue_clear(notify->process_queue);
	array_clear(&notify->processes);

	io_remove(&notify->io_write);
}

static void notify_flush(struct service_process_notify *notify)
{
	struct service_process *const *processes, *process;

	while (aqueue_count(notify->process_queue) > 0) {
		processes = array_first_modifiable(&notify->processes);
		process = processes[aqueue_idx(notify->process_queue, 0)];

		if (notify->write_callback(notify->fd, process) < 0) {
			if (errno != EAGAIN)
				service_process_notify_reset(notify);
			return;
		}
		service_process_unref(process);
		aqueue_delete_tail(notify->process_queue);
	}
	io_remove(&notify->io_write);
}

void service_process_notify_deinit(struct service_process_notify **_notify)
{
	struct service_process_notify *notify = *_notify;

	*_notify = NULL;

	service_process_notify_reset(notify);
	io_remove(&notify->io_write);
	aqueue_deinit(&notify->process_queue);
	array_free(&notify->processes);
	i_free(notify);
}

void service_process_notify_add(struct service_process_notify *notify,
				struct service_process *process)
{
	if (notify->write_callback(notify->fd, process) < 0) {
		if (errno != EAGAIN)
			return;

		if (notify->io_write == NULL) {
			notify->io_write = io_add(notify->fd, IO_WRITE,
						  notify_flush, notify);
		}
		aqueue_append(notify->process_queue, &process);
		service_process_ref(process);
	}
}
