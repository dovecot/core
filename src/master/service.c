/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "array.h"
#include "aqueue.h"
#include "hash.h"
#include "str.h"
#include "net.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "service.h"
#include "service-anvil.h"
#include "service-process.h"
#include "service-monitor.h"

#include <unistd.h>
#include <signal.h>

#define SERVICE_DIE_TIMEOUT_MSECS (1000*6)
#define SERVICE_LOGIN_NOTIFY_MIN_INTERVAL_SECS 2

HASH_TABLE_TYPE(pid_process) service_pids;

void service_error(struct service *service, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	i_error("service(%s): %s", service->set->name,
		t_strdup_vprintf(format, args));
	va_end(args);
}

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
	const char *const *tmp, *addresses;
	const struct ip_addr *ips;
	unsigned int i, ips_count;
	bool ssl_disabled = strcmp(service->set->master_set->ssl, "no") == 0;

	if (set->port == 0) {
		/* disabled */
		return 0;
	}

	if (*set->address != '\0')
		addresses = set->address;
	else {
		/* use the default listen address */
		addresses = service->set->master_set->listen;
	}

	tmp = t_strsplit_spaces(addresses, ", ");
	for (; *tmp != NULL; tmp++) {
		const char *address = *tmp;

		if (set->ssl && ssl_disabled)
			continue;

		if (resolve_ip(address, &ips, &ips_count, error_r) < 0)
			return -1;

		for (i = 0; i < ips_count; i++) {
			l = service_create_one_inet_listener(service, set,
							     address, &ips[i]);
			array_push_back(&service->listeners, &l);
		}
		service->have_inet_listeners = TRUE;
	}
	return 0;
}

static int service_get_groups(const char *groups, pool_t pool,
			      const char **gids_r, const char **error_r)
{
	const char *const *tmp;
	string_t *str;
	gid_t gid;

	str = t_str_new(64);
	for (tmp = t_strsplit(groups, ","); *tmp != NULL; tmp++) {
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
service_create(pool_t pool, const struct service_settings *set,
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
	service->set = set;
	service->throttle_msecs = SERVICE_STARTUP_FAILURE_THROTTLE_MIN_MSECS;

	service->client_limit = set->client_limit != 0 ? set->client_limit :
		set->master_set->default_client_limit;
	if (set->service_count > 0 &&
	    service->client_limit > set->service_count)
		service->client_limit = set->service_count;

	service->vsz_limit = set->vsz_limit != (uoff_t)-1 ? set->vsz_limit :
		set->master_set->default_vsz_limit;
	service->idle_kill = set->idle_kill != 0 ? set->idle_kill :
		set->master_set->default_idle_kill;
	service->type = service->set->parsed_type;

	if (set->process_limit == 0) {
		/* use default */
		service->process_limit =
			set->master_set->default_process_limit;
	} else {
		service->process_limit = set->process_limit;
	}

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

	if (*set->extra_groups != '\0') {
		if (service_get_groups(set->extra_groups, pool,
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
	service->master_dead_pipe_fd[0] = -1;
	service->master_dead_pipe_fd[1] = -1;
	service->log_process_internal_fd = -1;
	service->login_notify_fd = -1;

	if (service->type == SERVICE_TYPE_ANVIL) {
		service->status_fd[0] = service_anvil_global->status_fd[0];
		service->status_fd[1] = service_anvil_global->status_fd[1];
	}

	if (array_is_created(&set->unix_listeners))
		unix_listeners = array_get(&set->unix_listeners, &unix_count);
	else {
		unix_listeners = NULL;
		unix_count = 0;
	}
	if (array_is_created(&set->fifo_listeners))
		fifo_listeners = array_get(&set->fifo_listeners, &fifo_count);
	else {
		fifo_listeners = NULL;
		fifo_count = 0;
	}
	if (array_is_created(&set->inet_listeners))
		inet_listeners = array_get(&set->inet_listeners, &inet_count);
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
		     
	for (i = 0; i < unix_count; i++) {
		if (unix_listeners[i]->mode == 0) {
			/* disabled */
			continue;
		}

		l = service_create_file_listener(service, SERVICE_LISTENER_UNIX,
						 unix_listeners[i], error_r);
		if (l == NULL)
			return NULL;
		array_push_back(&service->listeners, &l);
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

struct service *
service_lookup(struct service_list *service_list, const char *name)
{
	struct service *const *services;

	array_foreach(&service_list->services, services) {
		struct service *service = *services;

		if (strcmp(service->set->name, name) == 0)
			return service;
	}
	return NULL;
}

struct service *
service_lookup_type(struct service_list *service_list, enum service_type type)
{
	struct service *const *services;

	array_foreach(&service_list->services, services) {
		struct service *service = *services;

		if (service->type == type)
			return service;
	}
	return NULL;
}

static bool service_want(struct service_settings *set)
{
	char *const *proto;

	if (*set->executable == '\0') {
		/* silently allow service {} blocks for disabled extensions
		   (e.g. service managesieve {} block without pigeonhole
		   installed) */
		return FALSE;
	}

	if (*set->protocol == '\0')
		return TRUE;

	for (proto = set->master_set->protocols_split; *proto != NULL; proto++) {
		if (strcmp(*proto, set->protocol) == 0)
			return TRUE;
	}
	return FALSE;
}

static int
services_create_real(const struct master_settings *set, pool_t pool,
		     struct service_list **services_r, const char **error_r)
{
	struct service_list *service_list;
	struct service *service;
	struct service_settings *const *service_settings;
	const char *error;
	unsigned int i, count;

	service_list = p_new(pool, struct service_list, 1);
	service_list->refcount = 1;
	service_list->pool = pool;
	service_list->service_set = master_service_settings_get(master_service);
	service_list->set_pool = master_service_settings_detach(master_service);
	service_list->set = set;
	service_list->master_log_fd[0] = -1;
	service_list->master_log_fd[1] = -1;
	service_list->master_fd = -1;

	service_settings = array_get(&set->services, &count);
	p_array_init(&service_list->services, pool, count);

	for (i = 0; i < count; i++) {
		if (!service_want(service_settings[i]))
			continue;
		service = service_create(pool, service_settings[i],
					 service_list, &error);
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
	pool_t pool;

	pool = pool_alloconly_create("services pool", 32768);
	if (services_create_real(set, pool, services_r, error_r) < 0) {
		pool_unref(&pool);
		return -1;
	}
	return 0;
}

unsigned int service_signal(struct service *service, int signo,
			    unsigned int *uninitialized_count_r)
{
	struct service_process *process = service->processes;
	unsigned int count = 0;

	*uninitialized_count_r = 0;
	for (; process != NULL; process = process->next) {
		i_assert(process->service == service);

		if (!SERVICE_PROCESS_IS_INITIALIZED(process) &&
		    signo != SIGKILL) {
			/* too early to signal it */
			*uninitialized_count_r += 1;
			continue;
		}
		    
		if (kill(process->pid, signo) == 0)
			count++;
		else if (errno != ESRCH) {
			service_error(service, "kill(%s, %d) failed: %m",
				      dec2str(process->pid), signo);
		}
	}
	if (count > 0) {
		i_warning("Sent %s to %u %s processes",
			  signo == SIGTERM ? "SIGTERM" : "SIGKILL",
			  count, service->set->name);
	}
	return count;
}

static void service_login_notify_send(struct service *service)
{
	unsigned int uninitialized_count;

	service->last_login_notify_time = ioloop_time;
	timeout_remove(&service->to_login_notify);

	service_signal(service, SIGUSR1, &uninitialized_count);
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

	/* change the state always immediately. it's cheap. */
	service->last_login_full_notify = all_processes_full;
	state = all_processes_full ? MASTER_LOGIN_STATE_FULL :
		MASTER_LOGIN_STATE_NONFULL;
	if (lseek(service->login_notify_fd, state, SEEK_SET) < 0)
		service_error(service, "lseek(notify fd) failed: %m");

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

static void services_kill_timeout(struct service_list *service_list)
{
	struct service *const *services, *log_service;
	unsigned int service_uninitialized, uninitialized_count = 0;
	unsigned int signal_count = 0;
	int sig;

	if (!service_list->sigterm_sent)
		sig = SIGTERM;
	else
		sig = SIGKILL;
	service_list->sigterm_sent = TRUE;

	log_service = NULL;
	array_foreach(&service_list->services, services) {
		struct service *service = *services;

		if (service->type == SERVICE_TYPE_LOG)
			log_service = service;
		else {
			signal_count += service_signal(service, sig,
						       &service_uninitialized);
			uninitialized_count += service_uninitialized;
		}
	}
	if (log_service == NULL) {
		/* log service doesn't exist - shouldn't really happen */
	} else if (signal_count > 0 || uninitialized_count > 0) {
		/* kill log service later so the last remaining processes
		   can still have a chance of logging something */
	} else {
		if (!service_list->sigterm_sent_to_log)
			sig = SIGTERM;
		else
			sig = SIGKILL;
		service_list->sigterm_sent_to_log = TRUE;
		signal_count += service_signal(log_service, sig, &service_uninitialized);
		uninitialized_count += service_uninitialized;
	}
	if (signal_count > 0) {
		string_t *str = t_str_new(128);
		str_printfa(str, "Processes aren't dying after reload, "
			    "sent %s to %u processes.",
			    sig == SIGTERM ? "SIGTERM" : "SIGKILL", signal_count);
		if (uninitialized_count > 0) {
			str_printfa(str, " (%u processes still uninitialized)",
				    uninitialized_count);
		}
		i_warning("%s", str_c(str));
	}
}

void services_destroy(struct service_list *service_list, bool wait)
{
	/* make sure we log if child processes died unexpectedly */
	service_list->destroying = TRUE;
	services_monitor_reap_children();

	services_monitor_stop(service_list, wait);

	if (service_list->refcount > 1 &&
	    service_list->service_set->shutdown_clients) {
		service_list->to_kill =
			timeout_add(SERVICE_DIE_TIMEOUT_MSECS,
				    services_kill_timeout, service_list);
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
	struct service *const *servicep;
	struct service_listener *const *listenerp;

	i_assert(service_list->refcount > 0);
	if (--service_list->refcount > 0)
		return;

	array_foreach(&service_list->services, servicep) {
		array_foreach(&(*servicep)->listeners, listenerp)
			i_close_fd(&(*listenerp)->fd);
	}
	i_close_fd(&service_list->master_fd);

	timeout_remove(&service_list->to_kill);
	pool_unref(&service_list->set_pool);
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
	struct service_listener *const *listenerp;
	int fd;

	array_foreach(&service->listeners, listenerp) {
		switch ((*listenerp)->type) {
		case SERVICE_LISTENER_UNIX:
		case SERVICE_LISTENER_INET:
			if ((*listenerp)->fd == -1) {
				/* already stopped listening */
				break;
			}
			while ((fd = net_accept((*listenerp)->fd,
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

	if (service->processes == NULL)
		service_drop_listener_connections(service);

	service_monitor_listen_stop(service);
	service->to_throttle = timeout_add(msecs, service_throttle_timeout,
					   service);
}

void services_throttle_time_sensitives(struct service_list *list,
				       unsigned int msecs)
{
	struct service *const *services;

	array_foreach(&list->services, services) {
		struct service *service = *services;

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
