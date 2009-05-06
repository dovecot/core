/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "fd-close-on-exec.h"
#include "fd-set-nonblock.h"
#include "service.h"
#include "service-process.h"
#include "service-process-notify.h"
#include "service-anvil.h"

#include <unistd.h>

#define ANVIL_HANDSHAKE "VERSION\t1\t0\n"

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

	if (anvil_send_handshake(service_list->blocking_anvil_fd[1],
				 error_r) < 0)
		return -1;
	if (anvil_send_handshake(service_list->nonblocking_anvil_fd[1],
				 error_r) < 0)
		return -1;

	i_assert(service_list->anvil_kills == NULL);
	service_list->anvil_kills =
		service_process_notify_init(service_list->nonblocking_anvil_fd[1],
					    service_process_write_anvil_kill);
	return 0;
}

void service_list_deinit_anvil(struct service_list *service_list)
{
	service_process_notify_deinit(&service_list->anvil_kills);
	if (close(service_list->blocking_anvil_fd[0]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(service_list->blocking_anvil_fd[1]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(service_list->nonblocking_anvil_fd[0]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(service_list->nonblocking_anvil_fd[1]) < 0)
		i_error("close(anvil) failed: %m");
}
