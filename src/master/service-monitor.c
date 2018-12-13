/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "safe-mkstemp.h"
#include "time-util.h"
#include "sleep.h"
#include "master-client.h"
#include "service.h"
#include "service-process.h"
#include "service-process-notify.h"
#include "service-anvil.h"
#include "service-log.h"
#include "service-monitor.h"

#include <unistd.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>

#define SERVICE_DROP_WARN_INTERVAL_SECS 1
#define SERVICE_DROP_TIMEOUT_MSECS (10*1000)
#define MAX_DIE_WAIT_MSECS 5000
#define SERVICE_MAX_EXIT_FAILURES_IN_SEC 10
#define SERVICE_PREFORK_MAX_AT_ONCE 10

static void service_monitor_start_extra_avail(struct service *service);
static void service_status_more(struct service_process *process,
				const struct master_status *status);
static void service_monitor_listen_start_force(struct service *service);

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
		i_zero(&status);
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

	/* we may need to start more */
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
		    service->idle_kill != UINT_MAX) {
			/* we have more processes than we really need.
			   add a bit of randomness so that we don't send the
			   signal to all of them at once */
			process->to_idle =
				timeout_add((service->idle_kill * 1000) +
					    i_rand_limit(100) * 10,
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

	process = hash_table_lookup(service_pids, POINTER_CAST(status->pid));
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

	/* first status notification */
	timeout_remove(&process->to_status);

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
		else if (errno != EAGAIN)
			service_error(service, "read(status) failed: %m");
		else
			return;
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
	if (service->to_throttle != NULL || service->list->destroying)
		return;

	i_assert(service->throttle_secs > 0);

	service_error(service, "command startup failed, throttling for %u secs",
		      service->throttle_secs);
	service_throttle(service, service->throttle_secs);
	service->throttle_secs *= 2;
	if (service->throttle_secs > SERVICE_STARTUP_FAILURE_THROTTLE_MAX_SECS)
		service->throttle_secs = SERVICE_STARTUP_FAILURE_THROTTLE_MAX_SECS;
}

static void service_drop_timeout(struct service *service)
{
	struct service_listener *const *lp;
	int fd;

	i_assert(service->process_avail == 0);

	/* drop all pending connections */
	array_foreach(&service->listeners, lp) {
		while ((fd = net_accept((*lp)->fd, NULL, NULL)) > 0)
			net_disconnect(fd);
	}

	service_monitor_listen_start_force(service);
	service->listen_pending = TRUE;
}

static void service_monitor_listen_pending(struct service *service)
{
	i_assert(service->process_avail == 0);

	service_monitor_listen_stop(service);
	service->listen_pending = TRUE;

	service->to_drop = timeout_add(SERVICE_DROP_TIMEOUT_MSECS,
				       service_drop_timeout, service);
}

static void service_drop_connections(struct service_listener *l)
{
	struct service *service = l->service;
	const char *limit_name;
	unsigned int limit;
	int fd;

	if (service->last_drop_warning +
	    SERVICE_DROP_WARN_INTERVAL_SECS <= ioloop_time) {
		service->last_drop_warning = ioloop_time;
		if (service->process_limit > 1) {
			limit_name = "process_limit";
			limit = service->process_limit;
		} else if (service->set->service_count == 1) {
			i_assert(service->client_limit == 1);
			limit_name = "client_limit/service_count";
			limit = 1;
		} else {
			limit_name = "client_limit";
			limit = service->client_limit;
		}
		i_warning("service(%s): %s (%u) reached, "
			  "client connections are being dropped",
			  service->set->name, limit_name, limit);
	}

	if (service->type == SERVICE_TYPE_LOGIN) {
		/* reached process limit, notify processes that they
		   need to start killing existing connections if they
		   reach connection limit */
		service_login_notify(service, TRUE);

		service_monitor_listen_pending(service);
	} else if (!service->listen_pending) {
		/* maybe this is a temporary peak, stop for a while and
		   see if it goes away */
		service_monitor_listen_pending(service);
	} else {
		/* this has been happening for a while now. just accept and
		   close the connection, so it's clear that this is happening
		   because of the limit, rather than because the service
		   processes aren't answering fast enough */
		fd = net_accept(l->fd, NULL, NULL);
		if (fd > 0)
			net_disconnect(fd);
	}
}

static void service_accept(struct service_listener *l)
{
	struct service *service = l->service;

	i_assert(service->process_avail == 0);

	if (service->process_count == service->process_limit) {
		/* we've reached our limits, new clients will have to
		   wait until there are more processes available */
		service_drop_connections(l);
		return;
	}

	/* create a child process and let it accept() this connection */
	if (service_process_create(service) == NULL)
		service_monitor_throttle(service);
	else
		service_monitor_listen_stop(service);
}

static bool
service_monitor_start_count(struct service *service, unsigned int limit)
{
	unsigned int i, count;

	i_assert(service->set->process_min_avail >= service->process_avail);

	count = service->set->process_min_avail - service->process_avail;
	if (service->process_count + count > service->process_limit)
		count = service->process_limit - service->process_count;
	if (count > limit)
		count = limit;

	for (i = 0; i < count; i++) {
		if (service_process_create(service) == NULL) {
			service_monitor_throttle(service);
			break;
		}
	}
	if (i > 0) {
		/* we created some processes, they'll do the listening now */
		service_monitor_listen_stop(service);
	}
	return i == count;
}

static void service_monitor_prefork_timeout(struct service *service)
{
	/* don't prefork more processes if other more important processes had
	   been forked while we were waiting for this timeout (= master seems
	   busy) */
	if (service->list->fork_counter != service->prefork_counter) {
		service->prefork_counter = service->list->fork_counter;
		return;
	}
	if (service->process_avail < service->set->process_min_avail) {
		if (service_monitor_start_count(service, SERVICE_PREFORK_MAX_AT_ONCE) &&
		    service->process_avail < service->set->process_min_avail)
			return;
	}
	timeout_remove(&service->to_prefork);
}

static void service_monitor_start_extra_avail(struct service *service)
{
	if (service->process_avail >= service->set->process_min_avail ||
	    service->list->destroying)
		return;

	if (service->process_avail == 0) {
		/* quickly start one process now */
		if (!service_monitor_start_count(service, 1))
			return;
		if (service->process_avail >= service->set->process_min_avail)
			return;
	}
	if (service->to_prefork == NULL) {
		/* ioloop handles timeouts before fds (= SIGCHLD callback),
		   so let the first timeout handler call simply update the fork
		   counter and the second one check if we're busy or not. */
		service->to_prefork =
			timeout_add_short(0, service_monitor_prefork_timeout, service);
	}
}

static void service_monitor_listen_start_force(struct service *service)
{
	struct service_listener *const *listeners;

	service->listening = TRUE;
	service->listen_pending = FALSE;
	timeout_remove(&service->to_drop);

	array_foreach(&service->listeners, listeners) {
		struct service_listener *l = *listeners;

		if (l->io == NULL && l->fd != -1)
			l->io = io_add(l->fd, IO_READ, service_accept, l);
	}
}

void service_monitor_listen_start(struct service *service)
{
	if (service->process_avail > 0 ||
	    (service->process_count == service->process_limit &&
	     service->listen_pending))
		return;

	service_monitor_listen_start_force(service);
}

void service_monitor_listen_stop(struct service *service)
{
	struct service_listener *const *listeners;

	array_foreach(&service->listeners, listeners) {
		struct service_listener *l = *listeners;

		io_remove(&l->io);
	}
	service->listening = FALSE;
	service->listen_pending = FALSE;
	timeout_remove(&service->to_drop);
}

static int service_login_create_notify_fd(struct service *service)
{
	int fd, ret;

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

	ret = fd == -1 ? -1 : 0;
	if (fd != service->login_notify_fd)
		i_close_fd(&fd);
	return ret;
}

void services_monitor_start(struct service_list *service_list)
{
	ARRAY(struct service *) listener_services;
	struct service *const *services;

	if (services_log_init(service_list) < 0)
		return;
	service_anvil_monitor_start(service_list);

	if (service_list->io_master == NULL &&
	    service_list->master_fd != -1) {
		service_list->io_master =
			io_add(service_list->master_fd, IO_READ,
			       master_client_connected, service_list);
	}

	t_array_init(&listener_services, array_count(&service_list->services));
	array_foreach(&service_list->services, services) {
		struct service *service = *services;

		if (service->type == SERVICE_TYPE_LOGIN) {
			if (service_login_create_notify_fd(service) < 0)
				continue;
		}
		if (service->master_dead_pipe_fd[0] == -1) {
			if (pipe(service->master_dead_pipe_fd) < 0) {
				service_error(service, "pipe() failed: %m");
				continue;
			}
			fd_close_on_exec(service->master_dead_pipe_fd[0], TRUE);
			fd_close_on_exec(service->master_dead_pipe_fd[1], TRUE);
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
		service_monitor_listen_start(service);
		array_push_back(&listener_services, &service);
	}

	/* create processes only after adding all listeners */
	array_foreach(&listener_services, services)
		service_monitor_start_extra_avail(*services);

	if (service_list->log->status_fd[0] != -1) {
		if (service_process_create(service_list->log) != NULL)
			service_monitor_listen_stop(service_list->log);
	}

	/* start up a process for startup-services */
	array_foreach(&service_list->services, services) {
		struct service *service = *services;

		if (service->type == SERVICE_TYPE_STARTUP &&
		    service->status_fd[0] != -1) {
			if (service_process_create(service) != NULL)
				service_monitor_listen_stop(service);
		}
	}
}

static void service_monitor_close_dead_pipe(struct service *service)
{
	if (service->master_dead_pipe_fd[0] != -1) {
		i_close_fd(&service->master_dead_pipe_fd[0]);
		i_close_fd(&service->master_dead_pipe_fd[1]);
	}
}

void service_monitor_stop(struct service *service)
{
	int i;

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
	service_monitor_close_dead_pipe(service);
	if (service->login_notify_fd != -1) {
		if (close(service->login_notify_fd) < 0) {
			service_error(service,
				      "close(login notify fd) failed: %m");
		}
		service->login_notify_fd = -1;
	}
	timeout_remove(&service->to_login_notify);
	service_monitor_listen_stop(service);

	timeout_remove(&service->to_throttle);
	timeout_remove(&service->to_prefork);
}

void service_monitor_stop_close(struct service *service)
{
	struct service_listener *const *listeners;

	service_monitor_stop(service);

	array_foreach(&service->listeners, listeners) {
		struct service_listener *l = *listeners;

		i_close_fd(&l->fd);
	}
}

static void services_monitor_wait(struct service_list *service_list)
{
	struct service *const *servicep;
	struct timeval tv_start;
	bool finished;

	io_loop_time_refresh();
	tv_start = ioloop_timeval;

	for (;;) {
		finished = TRUE;
		services_monitor_reap_children();
		array_foreach(&service_list->services, servicep) {
			if ((*servicep)->status_fd[0] != -1)
				service_status_input(*servicep);
			if ((*servicep)->process_avail > 0)
				finished = FALSE;
		}
		io_loop_time_refresh();
		if (finished ||
		    timeval_diff_msecs(&ioloop_timeval, &tv_start) > MAX_DIE_WAIT_MSECS)
			break;
		i_sleep_msecs(100);
	}
}

static bool service_processes_close_listeners(struct service *service)
{
	struct service_process *process = service->processes;
	bool ret = FALSE;

	for (; process != NULL; process = process->next) {
		if (kill(process->pid, SIGQUIT) == 0)
			ret = TRUE;
		else if (errno != ESRCH) {
			service_error(service, "kill(%s, SIGQUIT) failed: %m",
				      dec2str(process->pid));
		}
	}
	return ret;
}

static bool
service_list_processes_close_listeners(struct service_list *service_list)
{
	struct service *const *servicep;
	bool ret = FALSE;

	array_foreach(&service_list->services, servicep) {
		if (service_processes_close_listeners(*servicep))
			ret = TRUE;
	}
	return ret;
}

static void services_monitor_wait_and_kill(struct service_list *service_list)
{
	/* we've notified all children that the master is dead.
	   now wait for the children to either die or to tell that
	   they're no longer listening for new connections. */
	services_monitor_wait(service_list);

	/* Even if the waiting stopped early because all the process_avail==0,
	   it can mean that there are processes that have the listener socket
	   open (just not actively being listened to). We'll need to make sure
	   that those sockets are closed before we exit, so that a restart
	   won't fail. Do this by sending SIGQUIT to all the child processes
	   that are left, which are handled by lib-master to immediately close
	   the listener in the signal handler itself. */
	if (service_list_processes_close_listeners(service_list)) {
		/* SIGQUITs were sent. wait a little bit to make sure they're
		   also processed before quitting. */
		i_sleep_msecs(1000);
	}
}

void services_monitor_stop(struct service_list *service_list, bool wait)
{
	struct service *const *services;

	array_foreach(&service_list->services, services)
		service_monitor_close_dead_pipe(*services);

	if (wait)
		services_monitor_wait_and_kill(service_list);

	io_remove(&service_list->io_master);

	array_foreach(&service_list->services, services)
		service_monitor_stop(*services);

	services_log_deinit(service_list);
}

static bool
service_process_failure(struct service_process *process, int status)
{
	struct service *service = process->service;
	bool throttle;

	service_process_log_status_error(process, status);
	throttle = process->to_status != NULL;
	if (!throttle && !service->have_successful_exits) {
		/* this service has seen no successful exits yet.
		   try to avoid failure storms by throttling the service if it
		   only keeps failing rapidly. this is no longer done after
		   one success to avoid intentional DoSing, in case attacker
		   finds a way to quickly crash his own session. */
		if (service->exit_failure_last != ioloop_time) {
			service->exit_failure_last = ioloop_time;
			service->exit_failures_in_sec = 0;
		}
		if (++service->exit_failures_in_sec > SERVICE_MAX_EXIT_FAILURES_IN_SEC)
			throttle = TRUE;
	}
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
		process = hash_table_lookup(service_pids, POINTER_CAST(pid));
		if (process == NULL) {
			i_error("waitpid() returned unknown PID %s",
				dec2str(pid));
			continue;
		}

		service = process->service;
		if (status == 0) {
			/* success - one success resets all failures */
			service->have_successful_exits = TRUE;
			service->exit_failures_in_sec = 0;
			service->throttle_secs =
				SERVICE_STARTUP_FAILURE_THROTTLE_MIN_SECS;
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
		if (!service_stopped && !service->list->destroying) {
			service_monitor_start_extra_avail(service);
			/* if there are no longer listening processes,
			   start listening for more */
			if (service->to_throttle != NULL) {
				/* throttling */
			} else if (service == service->list->log &&
				   service->process_count == 0) {
				/* log service must always be running */
				if (service_process_create(service) == NULL)
					service_monitor_throttle(service);
			} else {
				service_monitor_listen_start(service);
			}
		}
		service_list_unref(service->list);
	}
}
