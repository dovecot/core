/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "fd-close-on-exec.h"
#include "fd-set-nonblock.h"
#include "fdpass.h"
#include "service.h"
#include "service-process.h"
#include "service-process-notify.h"
#include "service-anvil.h"

#include <unistd.h>

#define ANVIL_HANDSHAKE "VERSION\tanvil\t1\t0\n"

struct service_anvil_global *service_anvil_global;

static void
service_list_anvil_discard_input_stop(struct service_anvil_global *anvil)
{
	if (anvil->io_blocking != NULL) {
		io_remove(&anvil->io_blocking);
		io_remove(&anvil->io_nonblocking);
	}
}

static void anvil_input_fd_discard(struct service_anvil_global *anvil, int fd)
{
	char buf[1024];
	ssize_t ret;

	ret = read(fd, buf, sizeof(buf));
	if (ret <= 0) {
		i_error("read(anvil fd) failed: %m");
		service_list_anvil_discard_input_stop(anvil);
	}
}

static void anvil_input_blocking_discard(struct service_anvil_global *anvil)
{
	anvil_input_fd_discard(anvil, anvil->blocking_fd[0]);
}

static void anvil_input_nonblocking_discard(struct service_anvil_global *anvil)
{
	anvil_input_fd_discard(anvil, anvil->nonblocking_fd[0]);
}

static void service_list_anvil_discard_input(struct service_anvil_global *anvil)
{
	if (anvil->io_blocking != NULL)
		return;

	anvil->io_blocking = io_add(anvil->blocking_fd[0], IO_READ,
				    anvil_input_blocking_discard, anvil);
	anvil->io_nonblocking = io_add(anvil->nonblocking_fd[0], IO_READ,
				       anvil_input_nonblocking_discard, anvil);
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
	i_assert((size_t)ret == strlen(ANVIL_HANDSHAKE));
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

void service_anvil_monitor_start(struct service_list *service_list)
{
	struct service *service;

	if (service_anvil_global->process_count == 0)
		service_list_anvil_discard_input(service_anvil_global);
	else {
		service = service_lookup_type(service_list, SERVICE_TYPE_ANVIL);
		service_process_create(service);
	}
}

void service_anvil_process_created(struct service_process *process)
{
	struct service_anvil_global *anvil = service_anvil_global;
	const char *error;

	service_anvil_global->pid = process->pid;
	service_anvil_global->uid = process->uid;
	service_anvil_global->process_count++;
	service_list_anvil_discard_input_stop(anvil);

	if (anvil_send_handshake(anvil->blocking_fd[1], &error) < 0 ||
	    anvil_send_handshake(anvil->nonblocking_fd[1], &error) < 0)
		service_error(process->service, "%s", error);
}

void service_anvil_process_destroyed(struct service_process *process)
{
	i_assert(service_anvil_global->process_count > 0);
	if (--service_anvil_global->process_count == 0)
		service_list_anvil_discard_input(service_anvil_global);

	if (service_anvil_global->pid == process->pid)
		service_anvil_global->pid = 0;
}

void service_anvil_send_log_fd(void)
{
	ssize_t ret;
	char b;

	if (service_anvil_global->process_count == 0)
		return;

	ret = fd_send(service_anvil_global->log_fdpass_fd[1],
		      services->anvil->log_fd[1], &b, 1);
	if (ret < 0)
		i_error("fd_send(anvil log fd) failed: %m");
	else if (ret == 0)
		i_error("fd_send(anvil log fd) failed: disconnected");
}

void service_anvil_global_init(void)
{
	struct service_anvil_global *anvil;

	anvil = i_new(struct service_anvil_global, 1);
	if (pipe(anvil->status_fd) < 0)
		i_fatal("pipe() failed: %m");
	if (pipe(anvil->blocking_fd) < 0)
		i_fatal("pipe() failed: %m");
	if (pipe(anvil->nonblocking_fd) < 0)
		i_fatal("pipe() failed: %m");
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, anvil->log_fdpass_fd) < 0)
		i_fatal("socketpair() failed: %m");
	fd_set_nonblock(anvil->status_fd[0], TRUE);
	fd_set_nonblock(anvil->status_fd[1], TRUE);
	fd_set_nonblock(anvil->nonblocking_fd[1], TRUE);

	fd_close_on_exec(anvil->status_fd[0], TRUE);
	fd_close_on_exec(anvil->status_fd[1], TRUE);
	fd_close_on_exec(anvil->blocking_fd[0], TRUE);
	fd_close_on_exec(anvil->blocking_fd[1], TRUE);
	fd_close_on_exec(anvil->nonblocking_fd[0], TRUE);
	fd_close_on_exec(anvil->nonblocking_fd[1], TRUE);
	fd_close_on_exec(anvil->log_fdpass_fd[0], TRUE);
	fd_close_on_exec(anvil->log_fdpass_fd[1], TRUE);

	anvil->kills =
		service_process_notify_init(anvil->nonblocking_fd[1],
					    service_process_write_anvil_kill);
	service_anvil_global = anvil;
}

void service_anvil_global_deinit(void)
{
	struct service_anvil_global *anvil = service_anvil_global;

	service_list_anvil_discard_input_stop(anvil);
	service_process_notify_deinit(&anvil->kills);
	if (close(anvil->log_fdpass_fd[0]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(anvil->log_fdpass_fd[1]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(anvil->blocking_fd[0]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(anvil->blocking_fd[1]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(anvil->nonblocking_fd[0]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(anvil->nonblocking_fd[1]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(anvil->status_fd[0]) < 0)
		i_error("close(anvil) failed: %m");
	if (close(anvil->status_fd[1]) < 0)
		i_error("close(anvil) failed: %m");
	i_free(anvil);

	service_anvil_global = NULL;
}
