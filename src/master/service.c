/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "common.h"
#include "ioloop.h"
#include "array.h"
#include "aqueue.h"
#include "hash.h"
#include "str.h"
#include "net.h"
#include "settings.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "service.h"
#include "service-anvil.h"
#include "service-process.h"
#include "service-monitor.h"

#include <unistd.h>
#include <signal.h>

/* How long to wait after config reload before killing processes that aren't
   dying by themself. Keep this higher than
   MASTER_SERVICE_DEFAULT_DIE_TIMEOUT_MSECS, and higher than any die timeout
   set with master_service_set_die_timeout_msecs(). */
#define SERVICE_DIE_TIMEOUT_MSECS (1000*35)
#define SERVICE_LOGIN_NOTIFY_MIN_INTERVAL_SECS 2

HASH_TABLE_TYPE(pid_process) service_pids;

static struct service_listener *
service_create_file_listener(struct service *service,
			     enum service_listener_type type,
			     const struct file_listener_settings *set,
			     const char **error_r)
{
	struct service_listener *l;
	const char *set_name;
	gid_t gid;

	l = p_new(service->list->pool, struct service_listener, 1);
	l->service = service;
	l->type = type;
	l->fd = -1;
	l->set.fileset.set = set;
	l->name = strrchr(set->path, '/');
	if (l->name != NULL)
		l->name++;
	else
		l->name = set->path;

	if (get_uidgid(set->user, &l->set.fileset.uid, &gid, error_r) < 0)
		set_name = "user";
	else if (get_gid(set->group, &l->set.fileset.gid, error_r) < 0)
		set_name = "group";
	else
		return l;

	*error_r = t_strdup_printf(
		"%s (See service %s { %s_listener %s { %s } } setting)",
		*error_r, service->set->name,
		type == SERVICE_LISTENER_UNIX ? "unix" : "fifo",
		set->path, set_name);
	return NULL;
}

static int
resolve_ip(const char *address, const struct ip_addr **ips_r,
	   unsigned int *ips_count_r, const char **error_r)
{
	struct ip_addr *ip_list;
	unsigned int ips_count;
	int ret;

	if (address == NULL || strcmp(address, "*") == 0) {
		/* IPv4 any */
		ip_list = t_new(struct ip_addr, 1);
		*ip_list = net_ip4_any;
		*ips_r = ip_list;
		*ips_count_r = 1;
		return 0;
	}

	if (strcmp(address, "::") == 0 || strcmp(address, "[::]") == 0) {
		/* IPv6 any */
		ip_list = t_new(struct ip_addr, 1);
		*ip_list = net_ip6_any;
		*ips_r = ip_list;
		*ips_count_r = 1;
		return 0;
	}

	/* Return the first IP if there happens to be multiple. */
	ret = net_gethostbyname(address, &ip_list, &ips_count);
	if (ret != 0) {
		*error_r = t_strdup_printf("Can't resolve address %s: %s",
					   address, net_gethosterror(ret));
		return -1;
	}

	if (ips_count < 1) {
		*error_r = t_strdup_printf("No IPs for address: %s", address);
		return -1;
	}

	*ips_r = ip_list;
	*ips_count_r = ips_count;
	return 0;
}

static struct service_listener *
service_create_one_inet_listener(struct service *service,
				 const struct inet_listener_settings *set,
				 const char *address, const struct ip_addr *ip)
{
	struct service_listener *l;

	i_assert(set->port != 0);

	l = p_new(service->list->pool, struct service_listener, 1);
	l->service = service;
	l->type = SERVICE_LISTENER_INET;
	l->fd = -1;
	l->set.inetset.set = set;
	l->set.inetset.ip = *ip;
	l->inet_address = p_strdup(service->list->pool, address);
	l->name = set->name;

	return l;
}

static int
service_create_inet_listeners(struct service *service,
			      const struct inet_listener_settings *set,
			      const char **error_r)
{
	static struct service_listener *l;
	const char *address;
	ARRAY_TYPE(const_string) addresses;
	const struct ip_addr *ips;
	unsigned int i, ips_count;
	bool ssl_disabled = strcmp(service->list->set->ssl, "no") == 0;

	if (set->port == 0) {
		/* disabled */
		return 0;
	}

	if (!array_is_empty(&set->listen))
		addresses = set->listen;
	else {
		/* use the default listen address */
		addresses = service->list->set->listen;
	}

	array_foreach_elem(&addresses, address) {
		if (set->ssl && ssl_disabled)
			continue;

		if (resolve_ip(address, &ips, &ips_count, error_r) < 0)
			return -1;

		for (i = 0; i < ips_count; i++) {
			/* reuse_port=yes listeners create all of the processes'
			   listeners at startup. */
			unsigned int j, count;
			if (!service->set->reuse_port)
				count = 1;
			else
				count = service->process_limit;
			for (j = 0; j < count; j++) {
				l = service_create_one_inet_listener(service, set,
								     address, &ips[i]);
				l->reuse_port_process_index = j;
				array_push_back(&service->listeners, &l);
			}
		}
		service->have_inet_listeners = TRUE;
	}
	return 0;
}

static int service_get_groups(const ARRAY_TYPE(const_string) *groups, pool_t pool,
			      const char **gids_r, const char **error_r)
{
	const char *const *tmp;
	string_t *str;
	gid_t gid;

	str = t_str_new(64);
	for (tmp = settings_boollist_get(groups); *tmp != NULL; tmp++) {
		if (get_gid(*tmp, &gid, error_r) < 0)
			return -1;

		if (str_len(str) > 0)
			str_append_c(str, ',');
		str_append(str, dec2str(gid));
	}
	*gids_r = p_strdup(pool, str_c(str));
	return 0;
}

static struct service *
service_create_real(pool_t pool, struct event *event,
		    const struct service_settings *set,
		    struct service_list *service_list, const char **error_r)
{
	struct file_listener_settings *const *unix_listeners;
	struct file_listener_settings *const *fifo_listeners;
	struct inet_listener_settings *const *inet_listeners;
	struct service *service;
	struct service_listener *l;
	unsigned int i, unix_count, fifo_count, inet_count;

	service = p_new(pool, struct service, 1);
	service->list = service_list;
	service->event = event;
	service->set = set;
	service->throttle_msecs = SERVICE_STARTUP_FAILURE_THROTTLE_MIN_MSECS;

	service->client_limit = set->client_limit;
	i_assert(set->restart_request_count > 0);
	if (service->client_limit > set->restart_request_count)
		service->client_limit = set->restart_request_count;

	service->vsz_limit = set->vsz_limit;
	service->idle_kill_interval = set->idle_kill_interval;
	service->shutdown_clients_timeout = set->shutdown_clients_timeout;
	service->type = service->set->parsed_type;
	service->process_limit = set->process_limit;

	/* default gid to user's primary group */
	if (get_uidgid(set->user, &service->uid, &service->gid, error_r) < 0) {
		switch (set->user_default) {
		case SERVICE_USER_DEFAULT_NONE:
			*error_r = t_strdup_printf(
				"%s (See service %s { user } setting)",
				*error_r, set->name);
			break;
		case SERVICE_USER_DEFAULT_INTERNAL:
			*error_r = t_strconcat(*error_r,
				" (See default_internal_user setting)", NULL);
			break;
		case SERVICE_USER_DEFAULT_LOGIN:
			*error_r = t_strconcat(*error_r,
				" (See default_login_user setting)", NULL);
			break;
		}
		return NULL;
	}
	if (*set->group != '\0') {
		if (get_gid(set->group, &service->gid, error_r) < 0) {
			*error_r = t_strdup_printf(
				"%s (See service %s { group } setting)",
				*error_r, set->name);
			return NULL;
		}
	}
	if (get_gid(set->privileged_group, &service->privileged_gid,
		    error_r) < 0) {
		*error_r = t_strdup_printf(
			"%s (See service %s { privileged_group } setting)",
			*error_r, set->name);
		return NULL;
	}

	if (array_not_empty(&set->extra_groups)) {
		if (service_get_groups(&set->extra_groups, pool,
				       &service->extra_gids, error_r) < 0) {
			*error_r = t_strdup_printf(
				"%s (See service %s { extra_groups } setting)",
				*error_r, set->name);
			return NULL;
		}
	}

	/* set these later, so if something fails we don't have to worry about
	   closing them */
	service->log_fd[0] = -1;
	service->log_fd[1] = -1;
	service->status_fd[0] = -1;
	service->status_fd[1] = -1;
	service->stop_pipe_fd[0] = -1;
	service->stop_pipe_fd[1] = -1;
	service->log_process_internal_fd = -1;
	service->login_notify_fd = -1;

	if (service->type == SERVICE_TYPE_ANVIL) {
		service->status_fd[0] = service_anvil_global->status_fd[0];
		service->status_fd[1] = service_anvil_global->status_fd[1];
	}

	if (array_is_created(&set->parsed_unix_listeners))
		unix_listeners = array_get(&set->parsed_unix_listeners, &unix_count);
	else {
		unix_listeners = NULL;
		unix_count = 0;
	}
	if (array_is_created(&set->parsed_fifo_listeners))
		fifo_listeners = array_get(&set->parsed_fifo_listeners, &fifo_count);
	else {
		fifo_listeners = NULL;
		fifo_count = 0;
	}
	if (array_is_created(&set->parsed_inet_listeners))
		inet_listeners = array_get(&set->parsed_inet_listeners, &inet_count);
	else {
		inet_listeners = NULL;
		inet_count = 0;
	}

	if (unix_count == 0 && service->type == SERVICE_TYPE_CONFIG) {
		*error_r = "Service must have unix listeners";
		return NULL;
	}

	p_array_init(&service->listeners, pool,
		     unix_count + fifo_count + inet_count);
	if (unix_count > 0)
		p_array_init(&service->unix_pid_listeners, pool, 1);

	for (i = 0; i < unix_count; i++) {
		if (unix_listeners[i]->mode == 0) {
			/* disabled */
			continue;
		}

		l = service_create_file_listener(service, SERVICE_LISTENER_UNIX,
						 unix_listeners[i], error_r);
		if (l == NULL)
			return NULL;

		if (strstr(unix_listeners[i]->path, "%{pid}") == NULL)
			array_push_back(&service->listeners, &l);
		else {
			l->set.fileset.pid_listener = TRUE;
			array_push_back(&service->unix_pid_listeners, &l);
		}
	}
	for (i = 0; i < fifo_count; i++) {
		if (fifo_listeners[i]->mode == 0) {
			/* disabled */
			continue;
		}

		l = service_create_file_listener(service, SERVICE_LISTENER_FIFO,
						 fifo_listeners[i], error_r);
		if (l == NULL)
			return NULL;
		array_push_back(&service->listeners, &l);
	}
	for (i = 0; i < inet_count; i++) {
		if (service_create_inet_listeners(service, inet_listeners[i],
						  error_r) < 0)
			return NULL;
	}

	service->executable = set->executable;
	if (access(t_strcut(service->executable, ' '), X_OK) < 0) {
		*error_r = t_strdup_printf("access(%s) failed: %m",
					   t_strcut(service->executable, ' '));
		return NULL;
	}

	return service;
}

static struct service *
service_create(pool_t pool, const struct service_settings *set,
	       struct service_list *service_list, const char **error_r)
{
	struct event *event = event_create(service_list->event);
	event_set_append_log_prefix(event, t_strdup_printf(
		"service(%s): ", set->name));

	struct service *service = service_create_real(
		pool, event, set, service_list, error_r);
	if (service == NULL)
		event_unref(&event);
	return service;
}

struct service *
service_lookup(struct service_list *service_list, const char *name)
{
	struct service *service;

	array_foreach_elem(&service_list->services, service) {
		if (strcmp(service->set->name, name) == 0)
			return service;
	}
	return NULL;
}

struct service *
service_lookup_type(struct service_list *service_list, enum service_type type)
{
	struct service *service;

	array_foreach_elem(&service_list->services, service) {
		if (service->type == type)
			return service;
	}
	return NULL;
}

unsigned int service_active_process_count(struct service *service)
{
	i_assert(service->retired_process_count <= service->process_count);
	return service->process_count - service->retired_process_count;
}

static bool service_want(const struct master_settings *master_set,
			 struct service_settings *set)
{
	if (*set->executable == '\0') {
		/* silently allow service {} blocks for disabled extensions
		   (e.g. service managesieve {} block without pigeonhole
		   installed) */
		return FALSE;
	}

	if (*set->protocol == '\0')
		return TRUE;

	if (!array_is_created(&master_set->protocols))
		return FALSE;
	return array_lsearch(&master_set->protocols, &set->protocol,
			     i_strcmp_p) != NULL;
}

static int
services_create_real(const struct master_settings *set, pool_t pool,
		     struct event *event, struct service_list **services_r,
		     const char **error_r)
{
	struct service_list *service_list;
	struct service *service;
	struct service_settings *const *service_settings;
	const char *error;
	unsigned int i, count;

	service_list = p_new(pool, struct service_list, 1);
	service_list->refcount = 1;
	service_list->pool = pool;
	service_list->event = event;
	service_list->set = set;
	service_list->master_log_fd[0] = -1;
	service_list->master_log_fd[1] = -1;
	service_list->master_fd = -1;

	service_settings = array_get(&set->parsed_services, &count);
	p_array_init(&service_list->services, pool, count);

	for (i = 0; i < count; i++) {
		if (!service_want(set, service_settings[i]))
			continue;
		T_BEGIN {
			service = service_create(pool, service_settings[i],
						 service_list, &error);
		} T_END_PASS_STR_IF(service == NULL, &error);
		if (service == NULL) {
			*error_r = t_strdup_printf("service(%s) %s",
				service_settings[i]->name, error);
			return -1;
		}

		switch (service->type) {
		case SERVICE_TYPE_LOG:
			if (service_list->log != NULL) {
				*error_r = "Multiple log services specified";
				return -1;
			}
			service_list->log = service;
			break;
		case SERVICE_TYPE_CONFIG:
			if (service_list->config != NULL) {
				*error_r = "Multiple config services specified";
				return -1;
			}
			service_list->config = service;
			break;
		case SERVICE_TYPE_ANVIL:
			if (service_list->anvil != NULL) {
				*error_r = "Multiple anvil services specified";
				return -1;
			}
			service_list->anvil = service;
			break;
		default:
			if (strcmp(service->set->name, SERVICE_NAME_STATS) == 0) {
				/* Needs to outlive the rest of the generation
				   when everything is stopping - see
				   services_monitor_stop(). */
				service_list->stats = service;
			}
			break;
		}

		array_push_back(&service_list->services, &service);
	}

	if (service_list->log == NULL) {
		*error_r = "log service not specified";
		return -1;
	}

	if (service_list->config == NULL) {
		*error_r = "config process not specified";
		return -1;
	}

	*services_r = service_list;
	return 0;
}

int services_create(const struct master_settings *set,
		    struct service_list **services_r, const char **error_r)
{
	pool_t pool = pool_alloconly_create("services pool", 32768);
	struct event *event = event_create(NULL);
	if (services_create_real(set, pool, event, services_r, error_r) < 0) {
		event_unref(&event);
		pool_unref(&pool);
		return -1;
	}
	pool_ref(set->pool);
	return 0;
}

static unsigned int
service_signal_processes(struct service *service, int signo, bool expected,
			 struct service_process *processes,
			 unsigned int *uninitialized_count)
{
	struct service_process *process;
	unsigned int count = 0;

	for (process = processes; process != NULL; process = process->next) {
		i_assert(process->service == service);

		if (!SERVICE_PROCESS_IS_INITIALIZED(process) &&
		    signo != SIGKILL) {
			/* too early to signal it */
			*uninitialized_count += 1;
			continue;
		}

		if (kill(process->pid, signo) == 0)
			count++;
		else if (errno != ESRCH) {
			e_error(service->event, "kill(%s, %d) failed: %m",
				dec2str(process->pid), signo);
		}
	}
	if (count > 0 && signo != SIGUSR1) {
		const char *signame = signo == SIGTERM ? "SIGTERM" : "SIGKILL";

		if (expected) {
			/* This is the expected kill of the old generation's
			   processes, which happens on every reload. */
			e_debug(service->event, "Sent %s to %u %s processes",
				signame, count, service->set->name);
		} else {
			e_warning(service->event, "Sent %s to %u %s processes",
				  signame, count, service->set->name);
		}
	}
	return count;
}

unsigned int service_signal(struct service *service, int signo, bool expected,
			    unsigned int *uninitialized_count_r)
{
	unsigned int count = 0;

	*uninitialized_count_r = 0;
	count = service_signal_processes(service, signo, expected,
					 service->busy_processes,
					 uninitialized_count_r);
	count += service_signal_processes(service, signo, expected,
					  service->idle_processes_head,
					  uninitialized_count_r);
	return count;
}

static void service_login_notify_send(struct service *service)
{
	unsigned int uninitialized_count;

	service->last_login_notify_time = ioloop_time;
	timeout_remove(&service->to_login_notify);

	service_signal(service, SIGUSR1, TRUE, &uninitialized_count);
}

static void service_login_notify_timeout(struct service *service)
{
	service_login_notify_send(service);
}

void service_login_notify(struct service *service, bool all_processes_full)
{
	enum master_login_state state;
	int diff;

	if (service->last_login_full_notify == all_processes_full ||
	    service->login_notify_fd == -1)
		return;
	if (service->set->reuse_port) {
		/* With reuse_port=yes the processes don't care about sibling
		   processes' state. */
		return;
	}

	/* change the state always immediately. it's cheap. */
	service->last_login_full_notify = all_processes_full;
	state = all_processes_full ? MASTER_LOGIN_STATE_FULL :
		MASTER_LOGIN_STATE_NONFULL;
	if (lseek(service->login_notify_fd, state, SEEK_SET) < 0)
		e_error(service->event, "lseek(notify fd) failed: %m");

	/* but don't send signal to processes too often */
	diff = ioloop_time - service->last_login_notify_time;
	if (diff < SERVICE_LOGIN_NOTIFY_MIN_INTERVAL_SECS) {
		if (service->to_login_notify != NULL)
			return;

		diff = (SERVICE_LOGIN_NOTIFY_MIN_INTERVAL_SECS - diff) * 1000;
		service->to_login_notify =
			timeout_add(diff, service_login_notify_timeout,
				    service);
	} else {
		service_login_notify_send(service);
	}
}

/* Returns TRUE if a config reload preserves the processes of this type of
   service with their clients, instead of killing them together with the rest
   of the old generation. */
static bool service_type_is_preserved(enum service_type type)
{
	switch (type) {
	case SERVICE_TYPE_LOGIN:
	case SERVICE_TYPE_CLIENT:
		return TRUE;
	case SERVICE_TYPE_ANVIL:
		/* anvil is moved to the new service list, so it has no old
		   processes to kill. */
		return TRUE;
	case SERVICE_TYPE_LOG:
		/* The log service is handled separately: it must outlive the
		   rest of the old generation. */
		i_unreached();
	case SERVICE_TYPE_UNKNOWN:
	case SERVICE_TYPE_CONFIG:
	case SERVICE_TYPE_STARTUP:
	case SERVICE_TYPE_WORKER:
		return FALSE;
	}
	i_unreached();
}

/* Returns TRUE if the reload keeps this service's processes and their clients
   running, instead of killing them together with the internal services. */
static bool service_is_preserved(const struct service *service)
{
	return service->shutdown_clients_timeout != 0 &&
		service_type_is_preserved(service->type);
}

/* Returns the number of processes the old generation still has, excluding
   the log service. */
static unsigned int
service_list_non_log_process_count(struct service_list *service_list)
{
	struct service *service;
	unsigned int count = 0;

	array_foreach_elem(&service_list->services, service) {
		if (service->type != SERVICE_TYPE_LOG)
			count += service->process_count;
	}
	return count;
}

/* Sends SIGTERM to the old log service, or SIGKILL if it was already sent a
   SIGTERM. Does nothing while the generation still has other processes. */
static void services_kill_log(struct service_list *service_list)
{
	struct service *log_service =
		service_lookup_type(service_list, SERVICE_TYPE_LOG);
	unsigned int uninitialized_count;
	bool first_kill;
	int sig;

	if (log_service == NULL) {
		/* log service doesn't exist - shouldn't really happen */
		return;
	}
	if (service_list_non_log_process_count(service_list) > 0) {
		/* kill log service later so the last remaining processes
		   can still have a chance of logging something */
		return;
	}
	first_kill = !service_list->sigterm_sent_to_log;
	sig = first_kill ? SIGTERM : SIGKILL;
	service_list->sigterm_sent_to_log = TRUE;
	(void)service_signal(log_service, sig, first_kill,
			     &uninitialized_count);
}

/* Sends SIGTERM to the service's remaining processes, or SIGKILL if they were
   already sent a SIGTERM. kicked is TRUE when the processes were preserved
   until now and shutdown_clients_timeout expired. */
static void service_kill(struct service *service, bool kicked)
{
	unsigned int uninitialized_count, signal_count;
	string_t *str;
	bool first_kill;

	first_kill = !service->kill_sigterm_sent;
	/* The uninitialized processes couldn't be signalled, but they get
	   their SIGTERM from service_status_input_one() as soon as their
	   initial status notification arrives. */
	service->kill_sigterm_sent = TRUE;

	signal_count = service_signal(service,
				      first_kill ? SIGTERM : SIGKILL,
				      first_kill, &uninitialized_count);
	if (signal_count == 0)
		return;

	str = t_str_new(128);
	if (!first_kill) {
		str_printfa(str, "Processes aren't dying after reload, "
			    "sent SIGKILL to %u processes", signal_count);
	} else if (!service_type_is_preserved(service->type)) {
		/* The first kill is the intended one, not processes failing
		   to die. */
		str_printfa(str, "Stopping %u old processes", signal_count);
	} else {
		str_printfa(str, "Disconnecting clients from %u old processes",
			    signal_count);
		if (kicked)
			str_append(str, " after shutdown_clients_timeout");
	}
	if (uninitialized_count > 0) {
		str_printfa(str, " (%u processes still uninitialized)",
			    uninitialized_count);
	}
	if (!first_kill)
		e_warning(service->event, "%s", str_c(str));
	else if (kicked)
		e_info(service->event, "%s", str_c(str));
	else
		e_debug(service->event, "%s", str_c(str));
}

static void service_kick_timeout(struct service *service)
{
	if (service->process_count == 0) {
		/* The last process is gone. The generation's other services
		   keep the service list alive, so stop the repeating kick
		   here - there is nothing left to kill. */
		timeout_remove(&service->to_kick);
		return;
	}
	if (!service->kill_sigterm_sent) {
		/* The first timeout was the configured kick. Escalate at the
		   normal interval from now on. */
		timeout_remove(&service->to_kick);
		service->to_kick =
			timeout_add(SERVICE_DIE_TIMEOUT_MSECS,
				    service_kick_timeout, service);
	}
	service_kill(service, TRUE);
}

/* Kills the old generation's processes that the reload doesn't preserve. */
static void services_kill(struct service_list *service_list)
{
	struct service *service;

	array_foreach_elem(&service_list->services, service) {
		if (service->type == SERVICE_TYPE_LOG ||
		    service_is_preserved(service))
			continue;
		service_kill(service, FALSE);
	}
}

static void services_kill_timeout(struct service_list *service_list)
{
	services_kill(service_list);
	/* The log process normally stops by itself once the rest of the
	   generation is gone and it has written out their last log messages.
	   Kill it only if it's still around at the escalation timeout, since
	   killing it throws away the log input that hasn't been written
	   yet. */
	services_kill_log(service_list);
}

/* Disconnects the clients of the old processes: immediately for the services
   whose shutdown_clients_timeout is 0, and once the timeout has passed for the
   preserved services. The rest are left to the service list's kill. */
static void services_kick(struct service_list *service_list)
{
	struct service *service;
	unsigned int secs, msecs;

	array_foreach_elem(&service_list->services, service) {
		if (service->type == SERVICE_TYPE_LOG)
			continue;

		secs = service->shutdown_clients_timeout;
		if (secs == 0) {
			/* Disconnect the clients now, whether or not the
			   processes are the kind that could be preserved. The
			   service list's kill escalates from here on. */
			service_kill(service, FALSE);
			continue;
		}
		if (!service_type_is_preserved(service->type)) {
			/* Killed by the service list's kill timeout. */
			continue;
		}
		if (secs == SET_TIME_INFINITE) {
			/* The clients are never disconnected. The processes
			   stop once their last client is gone. */
			continue;
		}
		msecs = secs < UINT_MAX / 1000 ? secs * 1000 : UINT_MAX;
		service->to_kick = timeout_add(msecs, service_kick_timeout,
					       service);
	}
}

void services_destroy(struct service_list *service_list, bool wait)
{
	/* make sure we log if child processes died unexpectedly */
	service_list->destroying = TRUE;
	services_monitor_reap_children();

	services_monitor_stop(service_list, wait);

	if (service_list->refcount > 1) {
		/* Kill the processes that are still around when the timeout
		   expires, and escalate to SIGKILL from there on. This only
		   covers the services that aren't preserved - the preserved
		   ones are killed by their own to_kick. */
		service_list->to_kill =
			timeout_add(SERVICE_DIE_TIMEOUT_MSECS,
				    services_kill_timeout, service_list);
		if (!wait) {
			/* Reload: disconnect the clients of the services that
			   aren't preserved now, and the preserved ones once
			   their timeout expires. When the master itself is
			   stopping (wait=TRUE) the processes are stopped by
			   services_monitor_stop() and they enforce
			   shutdown_clients_timeout themselves afterwards. */
			services_kick(service_list);
		}
	}

	service_list->destroyed = TRUE;
	service_list_unref(service_list);
}

void service_list_ref(struct service_list *service_list)
{
	i_assert(service_list->refcount > 0);
	service_list->refcount++;
}

void service_list_unref(struct service_list *service_list)
{
	struct service *service;
	struct service_listener *listener;

	i_assert(service_list->refcount > 0);
	if (--service_list->refcount > 0)
		return;

	array_foreach_elem(&service_list->services, service) {
		i_assert(service->busy_processes == NULL);
		i_assert(service->idle_processes_head == NULL);
		i_assert(service->process_count == 0);
		i_assert(service->process_idling == 0);
		i_assert(service->process_avail == 0);
		array_foreach_elem(&service->listeners, listener)
			i_close_fd(&listener->fd);
		timeout_remove(&service->to_kick);
		event_unref(&service->event);
	}
	i_close_fd(&service_list->master_fd);

	timeout_remove(&service_list->to_kill);
	event_unref(&service_list->event);
	settings_free(service_list->set);
	pool_unref(&service_list->pool);
}

const char *services_get_config_socket_path(struct service_list *service_list)
{
	struct service_listener *const *listeners;
	unsigned int count;

	listeners = array_get(&service_list->config->listeners, &count);
	i_assert(count > 0);
	return listeners[0]->set.fileset.set->path;
}

static void service_throttle_timeout(struct service *service)
{
	timeout_remove(&service->to_throttle);
	service_monitor_listen_start(service);
}

static void service_drop_listener_connections(struct service *service)
{
	struct service_listener *listener;
	int fd;

	array_foreach_elem(&service->listeners, listener) {
		switch (listener->type) {
		case SERVICE_LISTENER_UNIX:
		case SERVICE_LISTENER_INET:
			if (listener->fd == -1) {
				/* already stopped listening */
				break;
			}
			while ((fd = net_accept(listener->fd,
						NULL, NULL)) >= 0)
				i_close_fd(&fd);
			break;
		case SERVICE_LISTENER_FIFO:
			break;
		}
	}
}

void service_throttle(struct service *service, unsigned int msecs)
{
	if (service->to_throttle != NULL || service->list->destroyed)
		return;

	if (service->busy_processes == NULL &&
	    service->idle_processes_head == NULL)
		service_drop_listener_connections(service);

	service_monitor_listen_stop(service);
	service->to_throttle = timeout_add(msecs, service_throttle_timeout,
					   service);
}

void services_throttle_time_sensitives(struct service_list *list,
				       unsigned int msecs)
{
	struct service *service;

	array_foreach_elem(&list->services, service) {
		if (service->type == SERVICE_TYPE_UNKNOWN)
			service_throttle(service, msecs);
	}
}

void service_pids_init(void)
{
	hash_table_create_direct(&service_pids, default_pool, 0);
}

void service_pids_deinit(void)
{
	struct hash_iterate_context *iter;
	void *key;
	struct service_process *process;

	/* free all child process information */
	iter = hash_table_iterate_init(service_pids);
	while (hash_table_iterate(iter, service_pids, &key, &process))
		service_process_destroy(process);
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&service_pids);
}
