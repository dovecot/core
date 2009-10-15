/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "fd-close-on-exec.h"
#include "fd-set-nonblock.h"
#include "service.h"
#include "service-process.h"
#include "service-process-notify.h"
#include "service-anvil.h"

#include <unistd.h>

#define ANVIL_HANDSHAKE "VERSION\tanvil\t1\t0\n"

static void
service_list_anvil_discard_input_stop(struct service_list *service_list)
{
	if (service_list->anvil_io_blocking != NULL) {
		io_remove(&service_list->anvil_io_blocking);
		io_remove(&service_list->anvil_io_nonblocking);
	}
}

static void
anvil_input_fd_discard(struct service_list *service_list, int fd)
{
	char buf[1024];
	ssize_t ret;

	ret = read(fd, buf, sizeof(buf));
	if (ret <= 0) {
		i_error("read(anvil fd) failed: %m");
		service_list_anvil_discard_input_stop(service_list);
	}
}

static void anvil_input_blocking_discard(struct service_list *service_list)
{
	anvil_input_fd_discard(service_list,
			       service_list->blocking_anvil_fd[0]);
}

static void anvil_input_nonblocking_discard(struct service_list *service_list)
{
	anvil_input_fd_discard(service_list,
			       service_list->nonblocking_anvil_fd[0]);
}

static void service_list_anvil_discard_input(struct service_list *service_list)
{
	service_list->anvil_io_blocking =
		io_add(service_list->blocking_anvil_fd[0], IO_READ,
		       anvil_input_blocking_discard, service_list);
	service_list->anvil_io_nonblocking =
		io_add(service_list->nonblocking_anvil_fd[0], IO_READ,
		       anvil_input_nonblocking_discard, service_list);
}

static int anvil_send_handshake(int fd, const char **error_r)
{
	ssize_t ret;

	ret = write(fd, ANVIL_HANDSHAKE, strlen(ANVIL_HANDSHAKE));
	if (ret < 0) {
		*error_r = t_strdup_printf("write(anvil) failed: %m");
		return -1;
	}
	if (ret == 0) {
		*error_r = t_strdup_printf("write(anvil) returned EOF");
		return -1;
	}
	/* this is a pipe, it either wrote all of it or nothing */
	i_assert(ret == strlen(ANVIL_HANDSHAKE));
	return 0;
}

static int
service_process_write_anvil_kill(int fd, struct service_process *process)
{
	const char *data;

	data = t_strdup_printf("KILL\t%s\n", dec2str(process->pid));
	if (write(fd, data, strlen(data)) < 0) {
		if (errno != EAGAIN)
			i_error("write(anvil process) failed: %m");
		return -1;
	}
	return 0;
}

int service_list_init_anvil(struct service_list *service_list,
			    const char **error_r)
{
	if (pipe(service_list->blocking_anvil_fd) < 0) {
		*error_r = t_strdup_printf("pipe() failed: %m");
		return -1;
	}
	if (pipe(service_list->nonblocking_anvil_fd) < 0) {
		(void)close(service_list->blocking_anvil_fd[0]);
		(void)close(service_list->blocking_anvil_fd[1]);
		*error_r = t_strdup_printf("pipe() failed: %m");
		return -1;
	}
	fd_set_nonblock(service_list->nonblocking_anvil_fd[1], TRUE);

	fd_close_on_exec(service_list->blocking_anvil_fd[0], TRUE);
	fd_close_on_exec(service_list->blocking_anvil_fd[1], TRUE);
	fd_close_on_exec(service_list->nonblocking_anvil_fd[0], TRUE);
	fd_close_on_exec(service_list->nonblocking_anvil_fd[1], TRUE);

	i_assert(service_list->anvil_kills == NULL);
	service_list->anvil_kills =
		service_process_notify_init(service_list->nonblocking_anvil_fd[1],
					    service_process_write_anvil_kill);
	return 0;
}

void services_anvil_init(struct service_list *service_list)
{
	/* this can't be in _init_anvil() because we can't do io_add()s
	   before forking with kqueue. */
	service_list_anvil_discard_input(service_list);
}

void service_list_deinit_anvil(struct service_list *service_list)
{
	service_list_anvil_discard_input_stop(service_list);
	service_process_notify_deinit(&service_list->anvil_kills);
	if (close(service_list->blocking_anvil_fd[0]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(service_list->blocking_anvil_fd[1]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(service_list->nonblocking_anvil_fd[0]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(service_list->nonblocking_anvil_fd[1]) < 0)
		i_error("close(anvil) failed: %m");
	service_list->blocking_anvil_fd[0] = -1;
}

void service_anvil_process_created(struct service *service)
{
	struct service_list *list = service->list;
	const char *error;

	service_list_anvil_discard_input_stop(service->list);

	if (anvil_send_handshake(list->blocking_anvil_fd[1], &error) < 0 ||
	    anvil_send_handshake(list->nonblocking_anvil_fd[1], &error) < 0)
		service_error(service, "%s", error);
}

void service_anvil_process_destroyed(struct service *service)
{
	if (service->process_count == 0 &&
	    service->list->anvil_io_blocking == NULL &&
	    service->list->blocking_anvil_fd[0] != -1)
		service_list_anvil_discard_input(service->list);
}
