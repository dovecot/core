/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "fd-close-on-exec.h"
#include "hash.h"
#include "str.h"
#include "safe-mkstemp.h"
#include "service.h"
#include "service-process.h"
#include "service-process-notify.h"
#include "service-anvil.h"
#include "service-log.h"
#include "service-monitor.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>

#define SERVICE_STARTUP_FAILURE_THROTTLE_SECS 60
#define SERVICE_DROP_WARN_INTERVAL_SECS 60

static void service_monitor_start_extra_avail(struct service *service);
static void service_status_more(struct service_process *process,
				const struct master_status *status);

static void service_process_kill_idle(struct service_process *process)
{
	struct service *service = process->service;
	struct master_status status;

	i_assert(process->available_count == service->client_limit);

	if (service->process_avail <= service->set->process_min_avail) {
		/* we don't have any extra idling processes anymore. */
		timeout_remove(&process->to_idle);
	} else if (process->last_kill_sent > process->last_status_update+1) {
		service_error(service, "Process %s is ignoring idle SIGINT",
			      dec2str(process->pid));

		/* assume this process is busy */
		memset(&status, 0, sizeof(status));
		service_status_more(process, &status);
		process->available_count = 0;
	} else {
		if (kill(process->pid, SIGINT) < 0 && errno != ESRCH) {
			service_error(service, "kill(%s, SIGINT) failed: %m",
				      dec2str(process->pid));
		}
		process->last_kill_sent = ioloop_time;
	}
}

static void service_status_more(struct service_process *process,
				const struct master_status *status)
{
	struct service *service = process->service;

	process->total_count +=
		process->available_count - status->available_count;
	process->idle_start = 0;

	if (process->to_idle != NULL)
		timeout_remove(&process->to_idle);

	if (status->available_count != 0)
		return;

	/* process used up all of its clients */
	i_assert(service->process_avail > 0);
	service->process_avail--;

	if (service->type == SERVICE_TYPE_LOGIN &&
	    service->process_avail == 0 &&
	    service->process_count == service->process_limit)
		service_login_notify(service, TRUE);

	/* we may need to start more  */
	service_monitor_start_extra_avail(service);
	service_monitor_listen_start(service);
}

static void service_status_less(struct service_process *process,
				const struct master_status *status)
{
	struct service *service = process->service;

	if (process->available_count == 0) {
		/* process can accept more clients again */
		if (service->process_avail++ == 0)
			service_monitor_listen_stop(service);
		i_assert(service->process_avail <= service->process_count);
	}
	if (status->available_count == service->client_limit) {
		process->idle_start = ioloop_time;
		if (service->process_avail > service->set->process_min_avail &&
		    process->to_idle == NULL &&
		    service->idle_kill != -1U) {
			/* we have more processes than we really need.
			   add a bit of randomness so that we don't send the
			   signal to all of them at once */
			process->to_idle =
				timeout_add((service->idle_kill * 1000) +
					    (rand() % 100)*10,
					    service_process_kill_idle,
					    process);
		}
	}
	if (service->type == SERVICE_TYPE_LOGIN)
		service_login_notify(service, FALSE);
}

static void
service_status_input_one(struct service *service,
			 const struct master_status *status)
{
        struct service_process *process;

	process = hash_table_lookup(service_pids, &status->pid);
	if (process == NULL) {
		/* we've probably wait()ed it away already. ignore */
		return;
	}

	if (process->uid != status->uid || process->service != service) {
		/* a) Process was closed and another process was created with
		   the same PID, but we're still receiving status update from
		   the old process.

		   b) Some process is trying to corrupt our internal state by
		   trying to pretend to be someone else. We could use stronger
		   randomness here, but the worst they can do is DoS and there
		   are already more serious problems if someone is able to do
		   this.. */
		service_error(service, "Ignoring invalid update from child %s "
			      "(UID=%u)", dec2str(status->pid), status->uid);
		return;
	}
	process->last_status_update = ioloop_time;

	if (process->to_status != NULL) {
		/* first status notification */
		timeout_remove(&process->to_status);
	}

	if (process->available_count == status->available_count)
		return;

	if (process->available_count > status->available_count) {
		/* process started servicing some more clients */
		service_status_more(process, status);
	} else {
		/* process finished servicing some clients */
		service_status_less(process, status);
	}
	process->available_count = status->available_count;
}

static void service_status_input(struct service *service)
{
	struct master_status status[1024/sizeof(struct master_status)];
	unsigned int i, count;
	ssize_t ret;

	ret = read(service->status_fd[0], &status, sizeof(status));
	if (ret <= 0) {
		if (ret == 0)
			service_error(service, "read(status) failed: EOF");
		else
			service_error(service, "read(status) failed: %m");
		service_monitor_stop(service);
		return;
	}

	if ((ret % sizeof(struct master_status)) != 0) {
		service_error(service, "service sent partial status update "
			      "(%d bytes)", (int)ret);
		return;
	}

	count = ret / sizeof(struct master_status);
	for (i = 0; i < count; i++)
		service_status_input_one(service, &status[i]);
}

static void service_monitor_throttle(struct service *service)
{
	if (service->to_throttle != NULL)
		return;

	service_error(service, "command startup failed, throttling");
	service_throttle(service, SERVICE_STARTUP_FAILURE_THROTTLE_SECS);
}

static void service_drop_connections(struct service *service)
{
	if (service->last_drop_warning +
	    SERVICE_DROP_WARN_INTERVAL_SECS < ioloop_time) {
		service->last_drop_warning = ioloop_time;
		i_warning("service(%s): %s reached, "
			  "client connections are being dropped",
			  service->process_limit > 1 ?
			  "process_limit" : "client_limit",
			  service->set->name);
	}
	service->listen_pending = TRUE;
	service_monitor_listen_stop(service);

	if (service->type == SERVICE_TYPE_LOGIN) {
		/* reached process limit, notify processes that they
		   need to start killing existing connections if they
		   reach connection limit */
		service_login_notify(service, TRUE);
	}
}

static void service_accept(struct service *service)
{
	i_assert(service->process_avail == 0);

	if (service->process_count == service->process_limit) {
		/* we've reached our limits, new clients will have to
		   wait until there are more processes available */
		service_drop_connections(service);
		return;
	}

	/* create a child process and let it accept() this connection */
	if (service_process_create(service) == NULL)
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
		if (service_process_create(service) == NULL) {
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

	if (service->process_avail > 0 ||
	    (service->process_count == service->process_limit &&
	     service->listen_pending))
		return;

	service->listening = TRUE;
	service->listen_pending = FALSE;

	array_foreach(&service->listeners, listeners) {
		struct service_listener *l = *listeners;

		if (l->io == NULL && l->fd != -1)
			l->io = io_add(l->fd, IO_READ, service_accept, service);
	}
}

void service_monitor_listen_stop(struct service *service)
{
	struct service_listener *const *listeners;

	array_foreach(&service->listeners, listeners) {
		struct service_listener *l = *listeners;

		if (l->io != NULL)
			io_remove(&l->io);
	}
	service->listening = FALSE;
}

static int service_login_create_notify_fd(struct service *service)
{
	int fd;

	if (service->login_notify_fd != -1)
		return 0;

	T_BEGIN {
		string_t *prefix = t_str_new(128);
		const char *path;

		str_append(prefix, service->set->master_set->base_dir);
		str_append(prefix, "/login-master-notify");

		fd = safe_mkstemp(prefix, 0600, (uid_t)-1, (gid_t)-1);
		path = str_c(prefix);

		if (fd == -1) {
			service_error(service, "safe_mkstemp(%s) failed: %m",
				      path);
		} else if (unlink(path) < 0) {
			service_error(service, "unlink(%s) failed: %m", path);
		} else {
			fd_close_on_exec(fd, TRUE);
			service->login_notify_fd = fd;
		}
	} T_END;

	if (fd != service->login_notify_fd)
		(void)close(fd);
	return fd == -1 ? -1 : 0;
}

void services_monitor_start(struct service_list *service_list)
{
	struct service *const *services;

	services_log_init(service_list);
	service_anvil_monitor_start(service_list);

	array_foreach(&service_list->services, services) {
		struct service *service = *services;

		if (service->type == SERVICE_TYPE_LOGIN) {
			if (service_login_create_notify_fd(service) < 0)
				continue;
		}
		if (service->status_fd[0] == -1) {
			/* we haven't yet created status pipe */
			if (pipe(service->status_fd) < 0) {
				service_error(service, "pipe() failed: %m");
				continue;
			}

			net_set_nonblock(service->status_fd[0], TRUE);
			fd_close_on_exec(service->status_fd[0], TRUE);
			net_set_nonblock(service->status_fd[1], TRUE);
			fd_close_on_exec(service->status_fd[1], TRUE);
		}
		if (service->io_status == NULL) {
			service->io_status =
				io_add(service->status_fd[0], IO_READ,
				       service_status_input, service);
		}
		service_monitor_start_extra_avail(service);
		service_monitor_listen_start(service);
	}

	if (service_process_create(service_list->log) != NULL)
		service_monitor_listen_stop(service_list->log);

	/* start up a process for startup-services */
	array_foreach(&service_list->services, services) {
		struct service *service = *services;

		if (service->type == SERVICE_TYPE_STARTUP) {
			if (service_process_create(service) != NULL)
				service_monitor_listen_stop(service);
		}
	}
}

void service_monitor_stop(struct service *service)
{
	int i;

	if (service->io_status != NULL)
		io_remove(&service->io_status);

	if (service->status_fd[0] != -1 &&
	    service->type != SERVICE_TYPE_ANVIL) {
		for (i = 0; i < 2; i++) {
			if (close(service->status_fd[i]) < 0) {
				service_error(service,
					      "close(status fd) failed: %m");
			}
			service->status_fd[i] = -1;
		}
	}
	if (service->login_notify_fd != -1) {
		if (close(service->login_notify_fd) < 0) {
			service_error(service,
				      "close(login notify fd) failed: %m");
		}
		service->login_notify_fd = -1;
	}
	if (service->to_login_notify != NULL)
		timeout_remove(&service->to_login_notify);
	service_monitor_listen_stop(service);

	if (service->to_throttle != NULL)
		timeout_remove(&service->to_throttle);
}

void services_monitor_stop(struct service_list *service_list)
{
	struct service *const *services;

	array_foreach(&service_list->services, services)
		service_monitor_stop(*services);

	services_log_deinit(service_list);
}

static bool
service_process_failure(struct service_process *process, int status)
{
	bool throttle;

	service_process_log_status_error(process, status);
	throttle = process->total_count == 0;
	service_process_notify_add(service_anvil_global->kills, process);
	return throttle;
}

void services_monitor_reap_children(void)
{
	struct service_process *process;
	struct service *service;
	pid_t pid;
	int status;
	bool service_stopped, throttle;

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
			throttle = FALSE;
		} else {
			throttle = service_process_failure(process, status);
		}
		if (service->type == SERVICE_TYPE_ANVIL)
			service_anvil_process_destroyed(process);

		/* if we're reloading, we may get here with a service list
		   that's going to be destroyed after this process is
		   destroyed. keep the list referenced until we're done. */
		service_list_ref(service->list);
		service_process_destroy(process);

		if (throttle)
			service_monitor_throttle(service);
		service_stopped = service->status_fd[0] == -1;
		if (!service_stopped) {
			service_monitor_start_extra_avail(service);
			if (service->to_throttle == NULL)
				service_monitor_listen_start(service);
		}
		service_list_unref(service->list);
	}
}
