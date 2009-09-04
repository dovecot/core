/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "fd-close-on-exec.h"
#include "hash.h"
#include "service.h"
#include "service-process.h"
#include "service-process-notify.h"
#include "service-log.h"
#include "service-monitor.h"

#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h>

#define SERVICE_STARTUP_FAILURE_THROTTLE_SECS 60

static void service_monitor_start_extra_avail(struct service *service);

static void service_status_input(struct service *service)
{
        struct master_status status;
        struct service_process *process;
	ssize_t ret;

	ret = read(service->status_fd[0], &status, sizeof(status));
	switch (ret) {
	case 0:
		service_error(service, "read(status) failed: EOF");
		service_monitor_stop(service);
		return;
	case -1:
		service_error(service, "read(status) failed: %m");
		service_monitor_stop(service);
		return;
	default:
		service_error(service, "child %s sent partial status update "
			      "(%d bytes)", dec2str(status.pid), (int)ret);
		return;

	case sizeof(status):
		break;
	}

	process = hash_table_lookup(service_pids, &status.pid);
	if (process == NULL) {
		/* we've probably wait()ed it away already. ignore */
		return;
	}

	if (process->uid != status.uid || process->service != service) {
		/* a) Process was closed and another process was created with
		   the same PID, but we're still receiving status update from
		   the old process.

		   b) Some process is trying to corrupt our internal state by
		   trying to pretend to be someone else. We could use stronger
		   randomness here, but the worst they can do is DoS and there
		   are already more serious problems if someone is able to do
		   this.. */
		service_error(service, "Ignoring invalid update from child %s "
			      "(UID=%u)", dec2str(status.pid), status.uid);
		return;
	}

	if (process->to_status != NULL) {
		/* first status notification */
		timeout_remove(&process->to_status);
	}

	if (process->available_count == status.available_count)
		return;

	if (process->available_count > status.available_count) {
		/* process started servicing requests */
		process->total_count +=
			process->available_count - status.available_count;
		if (status.available_count == 0) {
			i_assert(service->process_avail > 0);
			service->process_avail--;

			service_monitor_start_extra_avail(service);
			service_monitor_listen_start(service);
		}
		process->idle_start = 0;
	} else {
		/* process finished servicing requests */
		if (process->available_count == 0) {
			if (service->process_avail++ == 0)
                                service_monitor_listen_stop(service);
			i_assert(service->process_avail <=
				 service->process_count);
		}
		if (status.available_count == service->client_limit)
			process->idle_start = ioloop_time;
	}
	process->available_count = status.available_count;
}

static void service_monitor_throttle(struct service *service)
{
	if (service->to_throttle != NULL)
		return;

	service_error(service, "command startup failed, throttling");
	service_throttle(service, SERVICE_STARTUP_FAILURE_THROTTLE_SECS);
}

static void service_accept(struct service *service)
{
	i_assert(service->process_avail == 0);

	if (service->process_count == service->process_limit) {
		/* we've reached our limits, new connections will have to
		   wait until there are more processes available */
		i_warning("service(%s): process_limit reached, "
			  "connections are being dropped", service->set->name);
		service->listen_pending = TRUE;
                service_monitor_listen_stop(service);
		return;
	}

	/* create a child process and let it accept() this connection */
	if (service_process_create(service, NULL, NULL) == NULL)
		service_monitor_throttle(service);
	else
		service_monitor_listen_stop(service);
}

static void service_monitor_start_extra_avail(struct service *service)
{
	unsigned int i, count;

	if (service->process_avail >= service->set->process_min_avail)
		return;

	count = service->set->process_min_avail - service->process_avail;
	if (service->process_count + count > service->process_limit)
		count = service->process_limit - service->process_count;

	for (i = 0; i < count; i++) {
		if (service_process_create(service, NULL, NULL) == NULL) {
			service_monitor_throttle(service);
			break;
		}
	}
	if (i > 0 && service->listening) {
		/* we created some processes, they'll do the listening now */
		service_monitor_listen_stop(service);
	}
}

void service_monitor_listen_start(struct service *service)
{
	struct service_listener *const *listeners;
	unsigned int i, count;

	if (service->process_avail > 0)
		return;

	service->listening = TRUE;
	service->listen_pending = FALSE;

	listeners = array_get(&service->listeners, &count);
	for (i = 0; i < count; i++) {
		if (listeners[i]->io == NULL && listeners[i]->fd != -1) {
			listeners[i]->io = io_add(listeners[i]->fd, IO_READ,
						  service_accept, service);
		}
	}
}

void service_monitor_listen_stop(struct service *service)
{
	struct service_listener *const *listeners;
	unsigned int i, count;

	listeners = array_get(&service->listeners, &count);
	for (i = 0; i < count; i++) {
		struct service_listener *l = listeners[i];

		if (l->io != NULL)
			io_remove(&l->io);
	}
	service->listening = FALSE;
}

void services_monitor_start(struct service_list *service_list)
{
	struct service *const *services;
	unsigned int i, count;

	services_log_init(service_list);

	services = array_get(&service_list->services, &count);
	for (i = 0; i < count; i++) {
		if (services[i]->status_fd[0] == -1) {
			/* we haven't yet created status pipe */
			if (pipe(services[i]->status_fd) < 0) {
				service_error(services[i], "pipe() failed: %m");
				continue;
			}

			net_set_nonblock(services[i]->status_fd[0], TRUE);
			fd_close_on_exec(services[i]->status_fd[0], TRUE);
			net_set_nonblock(services[i]->status_fd[1], TRUE);
			fd_close_on_exec(services[i]->status_fd[1], TRUE);

			services[i]->io_status =
				io_add(services[i]->status_fd[0], IO_READ,
				       service_status_input, services[i]);
		}

		if (services[i]->status_fd[0] != -1) {
			service_monitor_start_extra_avail(services[i]);
			service_monitor_listen_start(services[i]);
		}
	}

	if (service_process_create(service_list->log, NULL, NULL) != NULL)
		service_monitor_listen_stop(service_list->log);
	if (service_process_create(service_list->config, NULL, NULL) != NULL)
		service_monitor_listen_stop(service_list->config);
}

void service_monitor_stop(struct service *service)
{
	int i;

	if (service->io_status != NULL)
		io_remove(&service->io_status);

	if (service->status_fd[0] != -1) {
		for (i = 0; i < 2; i++) {
			if (close(service->status_fd[i]) < 0) {
				service_error(service,
					      "close(status fd) failed: %m");
			}
			service->status_fd[i] = -1;
		}
	}
	service_monitor_listen_stop(service);

	if (service->to_throttle != NULL)
		timeout_remove(&service->to_throttle);
}

void services_monitor_stop(struct service_list *service_list)
{
	struct service *const *services;
	unsigned int i, count;

	services = array_get(&service_list->services, &count);
	for (i = 0; i < count; i++)
		service_monitor_stop(services[i]);

	services_log_deinit(service_list);
}

static void service_process_failure(struct service_process *process, int status)
{
	struct service *service = process->service;

	service_process_log_status_error(process, status);
	if (process->total_count == 0)
		service_monitor_throttle(service);

	if (service->list->anvil_kills != NULL)
		service_process_notify_add(service->list->anvil_kills, process);
}

void services_monitor_reap_children(void)
{
	struct service_process *process;
	struct service *service;
	pid_t pid;
	int status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		process = hash_table_lookup(service_pids, &pid);
		if (process == NULL) {
			i_error("waitpid() returned unknown PID %s",
				dec2str(pid));
			continue;
		}

		service = process->service;
		if (status == 0) {
			/* success */
			if (service->listen_pending)
				service_monitor_listen_start(service);
		} else {
			service_process_failure(process, status);
		}
		service_process_destroy(process);
		service_monitor_start_extra_avail(service);

                if (service->to_throttle == NULL)
			service_monitor_listen_start(service);
	}
}
