/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "aqueue.h"
#include "hash.h"
#include "str.h"
#include "service.h"
#include "service-process.h"
#include "service-monitor.h"

#include <unistd.h>
#include <signal.h>

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
	gid_t gid;

	l = p_new(service->list->pool, struct service_listener, 1);
	l->service = service;
	l->type = type;
	l->fd = -1;
	l->set.fileset.set = set;

	if (get_uidgid(set->user, &l->set.fileset.uid, &gid, error_r) < 0)
		return NULL;
	if (get_gid(set->group, &l->set.fileset.gid, error_r) < 0)
		return NULL;
	return l;
}

static int
resolve_ip(const char *address, struct ip_addr *ip_r, const char **error_r)
{
	struct ip_addr *ip_list;
	unsigned int ips_count;
	int ret;

	if (address == NULL || strcmp(address, "*") == 0) {
		/* IPv4 any */
		net_get_ip_any4(ip_r);
		return 0;
	}

	if (strcmp(address, "::") == 0) {
		/* IPv6 any */
		net_get_ip_any6(ip_r);
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
	if (ips_count > 1) {
		*error_r = t_strdup_printf("Multiple IPs for address: %s",
					   address);
		return -1;
	}

	*ip_r = ip_list[0];
	return 0;
}

static struct service_listener *
service_create_inet_listener(struct service *service,
			     const struct inet_listener_settings *set,
			     const char **error_r)
{
	struct service_listener *l;

	l = p_new(service->list->pool, struct service_listener, 1);
	l->service = service;
	l->type = SERVICE_LISTENER_INET;
	l->fd = -1;
	l->set.inetset.set = set;

	if (resolve_ip(set->address, &l->set.inetset.ip, error_r) < 0)
		return NULL;

	if (set->port == 0) {
		*error_r = "Port not given";
		return NULL;
	}
	if (set->port > 65535) {
		*error_r = t_strdup_printf("Invalid port: %u", set->port);
		return NULL;
	}

	return l;
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
	const char *const *tmp;
	string_t *str;
	unsigned int i, unix_count, fifo_count, inet_count;

	service = p_new(pool, struct service, 1);
	service->list = service_list;
	service->set = set;

	service->type = SERVICE_TYPE_UNKNOWN;
	if (*set->type != '\0') {
		if (strcmp(set->type, "log") == 0)
			service->type = SERVICE_TYPE_LOG;
		else if (strcmp(set->type, "config") == 0)
			service->type = SERVICE_TYPE_CONFIG;
		else if (strcmp(set->type, "auth") == 0)
			service->type = SERVICE_TYPE_AUTH_SERVER;
	}

	if (*set->auth_dest_service != '\0')
		service->type = SERVICE_TYPE_AUTH_SOURCE;

	if (set->process_limit == 0) {
		/* unlimited */
		service->process_limit = INT_MAX;
	} else if (set->process_limit == (unsigned int)-1) {
		/* use default */
		service->process_limit =
			set->master_set->default_process_limit;
	} else {
		service->process_limit = set->process_limit;
	}

	if (set->executable == NULL) {
		*error_r = "executable not given";
		return NULL;
	}

	/* default gid to user's primary group */
	if (get_uidgid(set->user, &service->uid, &service->gid, error_r) < 0)
		return NULL;
	if (*set->group != '\0') {
		if (get_gid(set->group, &service->gid, error_r) < 0)
			return NULL;
	}
	if (get_gid(set->privileged_group, &service->privileged_gid,
		    error_r) < 0)
		return NULL;

	if (*set->extra_groups != '\0') {
		str = t_str_new(64);
		tmp = t_strsplit(set->extra_groups, ",");
		for (; *tmp != NULL; tmp++) {
			gid_t gid;

			if (get_gid(*tmp, &gid, error_r) < 0)
				return NULL;

			if (str_len(str) > 0)
				str_append_c(str, ',');
			str_append(str, dec2str(gid));
		}
		service->extra_gids = p_strdup(pool, str_c(str));
	}

	if (*set->executable == '/')
		service->executable = set->executable;
	else {
		service->executable =
			p_strconcat(pool, set->master_set->libexec_dir, "/",
				    set->executable, NULL);
	}
	if (access(t_strcut(service->executable, ' '), X_OK) < 0) {
		*error_r = t_strdup_printf("access(%s) failed: %m",
					   t_strcut(service->executable, ' '));
		return NULL;
	}

	/* set these later, so if something fails we don't have to worry about
	   closing them */
	service->log_fd[0] = -1;
	service->log_fd[1] = -1;
	service->status_fd[0] = -1;
	service->status_fd[1] = -1;
	service->log_process_internal_fd = -1;

	if (array_is_created(&set->unix_listeners))
		unix_listeners = array_get(&set->unix_listeners, &unix_count);
	else {
		unix_listeners = NULL;
		unix_count = 0;
	}
	if (array_is_created(&set->fifo_listeners))
		fifo_listeners = array_get(&set->unix_listeners, &fifo_count);
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
		l = service_create_file_listener(service, SERVICE_LISTENER_UNIX,
						 unix_listeners[i], error_r);
		if (l == NULL)
			return NULL;
		array_append(&service->listeners, &l, 1);
	}
	for (i = 0; i < fifo_count; i++) {
		l = service_create_file_listener(service, SERVICE_LISTENER_UNIX,
						 fifo_listeners[i], error_r);
		if (l == NULL)
			return NULL;
		array_append(&service->listeners, &l, 1);
	}
	for (i = 0; i < inet_count; i++) {
		l = service_create_inet_listener(service, inet_listeners[i],
						 error_r);
		if (l == NULL)
			return NULL;
		array_append(&service->listeners, &l, 1);
	}

	return service;
}

static unsigned int pid_hash(const void *p)
{
	const pid_t *pid = p;

	return (unsigned int)*pid;
}

static int pid_hash_cmp(const void *p1, const void *p2)
{
	const pid_t *pid1 = p1, *pid2 = p2;

	return *pid1 < *pid2 ? -1 :
		*pid1 > *pid2 ? 1 : 0;
}

static struct service *
service_lookup(struct service_list *service_list, const char *name)
{
	struct service *const *services;
	unsigned int i, count;

	services = array_get(&service_list->services, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(services[i]->set->name, name) == 0)
			return services[i];
	}
	return NULL;
}

struct service_list *
services_create(const struct master_settings *set,
		const char *const *child_process_env, const char **error_r)
{
	struct service_list *service_list;
	struct service *service, *const *services;
	struct service_settings *const *service_settings;
	pool_t pool;
	const char *error;
	unsigned int i, count;

	pool = pool_alloconly_create("services pool", 4096);

	service_list = p_new(pool, struct service_list, 1);
	service_list->pool = pool;
	service_list->child_process_env = child_process_env;
	service_list->master_log_fd[0] = -1;
	service_list->master_log_fd[1] = -1;

	service_settings = array_get(&set->services, &count);
	p_array_init(&service_list->services, pool, count);

	for (i = 0; i < count; i++) {
		service = service_create(pool, service_settings[i],
					 service_list, &error);
		if (service == NULL) {
			*error_r = t_strdup_printf("service(%s) %s",
				service_settings[i]->name, error);
			return NULL;
		}

		switch (service->type) {
		case SERVICE_TYPE_LOG:
			if (service_list->log != NULL) {
				*error_r = "Multiple log services specified";
				return NULL;
			}
			service_list->log = service;
			break;
		case SERVICE_TYPE_CONFIG:
			if (service_list->config != NULL) {
				*error_r = "Multiple config services specified";
				return NULL;
			}
			service_list->config = service;
			break;
		default:
			break;
		}

		array_append(&service_list->services, &service, 1);
	}

	/* resolve service dependencies */
	services = array_get(&service_list->services, &count);
	for (i = 0; i < count; i++) {
		if (services[i]->type == SERVICE_TYPE_AUTH_SOURCE) {
			const char *dest_service =
				services[i]->set->auth_dest_service;
			services[i]->auth_dest_service =
				service_lookup(service_list, dest_service);
			if (services[i]->auth_dest_service == NULL) {
				*error_r = t_strdup_printf(
					"auth_dest_service doesn't exist: %s",
					dest_service);
				return NULL;
			}
		}
	}

	if (service_list->log == NULL) {
		*error_r = "log service not specified";
		return NULL;
	}

	if (service_list->config == NULL) {
		*error_r = "config process not specified";
		return NULL;
	}

	service_list->pids = hash_table_create(default_pool, pool, 0,
					       pid_hash, pid_hash_cmp);
	p_array_init(&service_list->bye_arr, pool, 64);
	service_list->bye_queue = aqueue_init(&service_list->bye_arr.arr);
	return service_list;
}

void service_signal(struct service *service, int signo)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_table_iterate_init(service->list->pids);
	while (hash_table_iterate(iter, &key, &value)) {
		struct service_process *process = value;

		if (process->service != service)
			continue;

		if (kill(process->pid, signo) < 0 && errno != ESRCH) {
			service_error(service, "kill(%s, %d) failed: %m",
				      dec2str(process->pid), signo);
		}
	}
	hash_table_iterate_deinit(&iter);
}

void services_destroy(struct service_list *service_list)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	/* make sure we log if child processes died unexpectedly */
        services_monitor_reap_children(service_list);

	services_monitor_stop(service_list);

	/* free all child process information */
	iter = hash_table_iterate_init(service_list->pids);
	while (hash_table_iterate(iter, &key, &value))
		service_process_destroy(value);
	hash_table_iterate_deinit(&iter);

	hash_table_destroy(&service_list->pids);
	aqueue_deinit(&service_list->bye_queue);
	pool_unref(&service_list->pool);
}
