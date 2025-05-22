/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "env-util.h"
#include "istream.h"
#include "net.h"
#include "str.h"
#include "ipwd.h"
#include "mkdir-parents.h"
#include "safe-mkdir.h"
#include "restrict-process-size.h"
#include "settings.h"
#include "master-settings.h"

#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

static bool master_settings_ext_check(struct event *event, void *_set,
				      pool_t pool, const char **error_r);

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("unix_listener_"#name, name, struct file_listener_settings)
static const struct setting_define unix_listener_setting_defines[] = {
	DEF(STR_NOVARS, path),
	DEF(STR, type),
	DEF(UINT_OCT, mode),
	DEF(STR, user),
	DEF(STR, group),

	SETTING_DEFINE_LIST_END
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("fifo_listener_"#name, name, struct file_listener_settings)
static const struct setting_define fifo_listener_setting_defines[] = {
	DEF(STR_NOVARS, path),
	DEF(STR, type),
	DEF(UINT_OCT, mode),
	DEF(STR, user),
	DEF(STR, group),

	SETTING_DEFINE_LIST_END
};

static const struct file_listener_settings file_listener_default_settings = {
	.path = "",
	.type = "",
	.mode = 0600,
	.user = "",
	.group = "",
};

const struct setting_parser_info unix_listener_setting_parser_info = {
	.name = "unix_listener",

	.defines = unix_listener_setting_defines,
	.defaults = &file_listener_default_settings,

	.struct_size = sizeof(struct file_listener_settings),
	.pool_offset1 = 1 + offsetof(struct file_listener_settings, pool),
};

const struct setting_parser_info fifo_listener_setting_parser_info = {
	.name = "fifo_listener",

	.defines = fifo_listener_setting_defines,
	.defaults = &file_listener_default_settings,

	.struct_size = sizeof(struct file_listener_settings),
	.pool_offset1 = 1 + offsetof(struct file_listener_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("inet_listener_"#name, name, struct inet_listener_settings)

static const struct setting_define inet_listener_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, type),
	DEF(IN_PORT, port),
	DEF(BOOL, ssl),
	DEF(BOOL, reuse_port),
	DEF(BOOL, haproxy),

	SETTING_DEFINE_LIST_END
};

static const struct inet_listener_settings inet_listener_default_settings = {
	.name = "",
	.type = "",
	.port = 0,
	.ssl = FALSE,
	.reuse_port = FALSE,
	.haproxy = FALSE
};

const struct setting_parser_info inet_listener_setting_parser_info = {
	.name = "inet_listener",

	.defines = inet_listener_setting_defines,
	.defaults = &inet_listener_default_settings,

	.struct_size = sizeof(struct inet_listener_settings),
	.pool_offset1 = 1 + offsetof(struct inet_listener_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("service_"#name, name, struct service_settings)

static const struct setting_define service_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, protocol),
	DEF(STR, type),
	DEF(STR, executable),
	DEF(STR, user),
	DEF(STR, group),
	DEF(STR, privileged_group),
	DEF(BOOLLIST, extra_groups),
	DEF(STR, chroot),

	DEF(BOOL, drop_priv_before_exec),

	DEF(UINT, process_min_avail),
	DEF(UINT, process_limit),
	DEF(UINT, client_limit),
	DEF(UINT, restart_request_count),
	DEF(TIME, idle_kill_interval),
	DEF(SIZE, vsz_limit),

	{ .type = SET_FILTER_ARRAY, .key = "unix_listener",
	  .offset = offsetof(struct service_settings, unix_listeners),
	  .filter_array_field_name = "unix_listener_path", },
	{ .type = SET_FILTER_ARRAY, .key = "fifo_listener",
	  .offset = offsetof(struct service_settings, fifo_listeners),
	  .filter_array_field_name = "fifo_listener_path", },
	{ .type = SET_FILTER_ARRAY, .key = "inet_listener",
	  .offset = offsetof(struct service_settings, inet_listeners),
	  .filter_array_field_name = "inet_listener_name", },

	SETTING_DEFINE_LIST_END
};

static const struct service_settings service_default_settings = {
	.name = "",
	.protocol = "",
	.type = "",
	.executable = "",
	.user = "",
	.group = "",
	.privileged_group = "",
	.extra_groups = ARRAY_INIT,
	.chroot = "",

	.drop_priv_before_exec = FALSE,

	.process_min_avail = 0,
	.process_limit = 0,
	.client_limit = 0,
	.restart_request_count = SET_UINT_UNLIMITED,
	.idle_kill_interval = 0,
	.vsz_limit = 0,

	.unix_listeners = ARRAY_INIT,
	.fifo_listeners = ARRAY_INIT,
	.inet_listeners = ARRAY_INIT
};

const struct setting_parser_info service_setting_parser_info = {
	.name = "service",

	.defines = service_setting_defines,
	.defaults = &service_default_settings,

	.struct_size = sizeof(struct service_settings),
	.pool_offset1 = 1 + offsetof(struct service_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct master_settings)

static const struct setting_define master_setting_defines[] = {
	DEF(STR_HIDDEN, base_dir),
	DEF(STR_HIDDEN, state_dir),
	DEF(STR_HIDDEN, libexec_dir),
	DEF(STR, instance_name),
	DEF(BOOLLIST, protocols),
	DEF(BOOLLIST, listen),
	DEF(ENUM, ssl),
	DEF(STR, default_internal_user),
	DEF(STR, default_internal_group),
	DEF(STR, default_login_user),
	DEF(UINT, default_process_limit),
	DEF(UINT, default_client_limit),
	DEF(TIME, default_idle_kill_interval),
	DEF(SIZE, default_vsz_limit),

	DEF(BOOL, version_ignore),

	DEF(UINT, first_valid_uid),
	DEF(UINT, last_valid_uid),
	DEF(UINT, first_valid_gid),
	DEF(UINT, last_valid_gid),

	{ .type = SET_FILTER_ARRAY, .key = "service",
	  .offset = offsetof(struct master_settings, services),
	  .filter_array_field_name = "service_name", },

	SETTING_DEFINE_LIST_END
};

static const struct master_settings master_default_settings = {
	.base_dir = PKG_RUNDIR,
	.state_dir = PKG_STATEDIR,
	.libexec_dir = PKG_LIBEXECDIR,
	.instance_name = PACKAGE,
	.ssl = "yes:no:required",
	.default_internal_user = "dovecot",
	.default_internal_group = "dovecot",
	.default_login_user = "dovenull",
	.default_process_limit = 100,
	.default_client_limit = 1000,
	.default_idle_kill_interval = 60,
#ifdef DOVECOT_PRO_EDITION
	.default_vsz_limit = 1024*1024*1024,
#else
	.default_vsz_limit = 256*1024*1024,
#endif

	.version_ignore = FALSE,

	.first_valid_uid = 500,
	.last_valid_uid = 0,
	.first_valid_gid = 1,
	.last_valid_gid = 0,

	.services = ARRAY_INIT
};
static const struct setting_keyvalue master_default_settings_keyvalue[] = {
	{ "protocols", "" },
	{ "listen", "* ::" },
	{ NULL, NULL }
};

const struct setting_parser_info master_setting_parser_info = {
	.name = "master",

	.defines = master_setting_defines,
	.defaults = &master_default_settings,
	.default_settings = master_default_settings_keyvalue,

	.struct_size = sizeof(struct master_settings),
	.pool_offset1 = 1 + offsetof(struct master_settings, pool),
	.ext_check_func = master_settings_ext_check
};

/* <settings checks> */
static void
expand_user(const char **user, enum service_user_default *default_r,
	    const struct master_settings *set)
{
	/* $variable expansion is typically done by doveconf, but these
	   variables can come from built-in settings, so we need to expand
	   them here */
	if (strcmp(*user, "$SET:default_internal_user") == 0) {
		*user = set->default_internal_user;
		*default_r = SERVICE_USER_DEFAULT_INTERNAL;
	} else if (strcmp(*user, "$SET:default_login_user") == 0) {
		*user = set->default_login_user;
		*default_r = SERVICE_USER_DEFAULT_LOGIN;
	} else {
		*default_r = SERVICE_USER_DEFAULT_NONE;
	}
}

static void
expand_group(const char **group, const struct master_settings *set)
{
	/* $variable expansion is typically done by doveconf, but these
	   variables can come from built-in settings, so we need to expand
	   them here */
	if (strcmp(*group, "$SET:default_internal_group") == 0)
		*group = set->default_internal_group;
}

static void
expand_groups(ARRAY_TYPE(const_string) *groups, const struct master_settings *set)
{
	const char **group;
	if (array_is_empty(groups))
		return;
	array_foreach_modifiable(groups, group)
		expand_group(group, set);
}

static bool
fix_file_listener_paths(ARRAY_TYPE(file_listener_settings) *l,
			pool_t pool, const struct master_settings *master_set,
			ARRAY_TYPE(const_string) *all_listeners,
			const char **error_r)
{
	struct file_listener_settings *set;
	size_t base_dir_len = strlen(master_set->base_dir);
	enum service_user_default user_default;

	if (!array_is_created(l))
		return TRUE;

	array_foreach_elem(l, set) {
		if (set->path[0] == '\0') {
			*error_r = "path must not be empty";
			return FALSE;
		}

		expand_user(&set->user, &user_default, master_set);
		expand_group(&set->group, master_set);
		if (*set->path != '/') {
			set->path = p_strconcat(pool, master_set->base_dir, "/",
						set->path, NULL);
		} else if (strncmp(set->path, master_set->base_dir,
				   base_dir_len) == 0 &&
			   set->path[base_dir_len] == '/') {
			i_warning("You should remove base_dir prefix from "
				  "unix_listener: %s", set->path);
		}
		if (set->mode != 0)
			array_push_back(all_listeners, &set->path);
	}
	return TRUE;
}

static void add_inet_listeners(ARRAY_TYPE(inet_listener_settings) *l,
			       ARRAY_TYPE(const_string) *all_listeners)
{
	struct inet_listener_settings *set;
	const char *str;
	const char *address;

	if (!array_is_created(l))
		return;

	array_foreach_elem(l, set) {
		if (set->port != 0) {
			array_foreach_elem(&set->listen, address) {
				str = t_strdup_printf("%u:%s", set->port, address);
				array_push_back(all_listeners, &str);
			}
		}
	}
}

static bool master_settings_parse_type(struct service_settings *set,
				       const char **error_r)
{
	if (*set->type == '\0')
		set->parsed_type = SERVICE_TYPE_UNKNOWN;
	else if (strcmp(set->type, "log") == 0)
		set->parsed_type = SERVICE_TYPE_LOG;
	else if (strcmp(set->type, "config") == 0)
		set->parsed_type = SERVICE_TYPE_CONFIG;
	else if (strcmp(set->type, "anvil") == 0)
		set->parsed_type = SERVICE_TYPE_ANVIL;
	else if (strcmp(set->type, "login") == 0)
		set->parsed_type = SERVICE_TYPE_LOGIN;
	else if (strcmp(set->type, "startup") == 0)
		set->parsed_type = SERVICE_TYPE_STARTUP;
	else if (strcmp(set->type, "worker") == 0)
		set->parsed_type = SERVICE_TYPE_WORKER;
	else {
		*error_r = t_strconcat("Unknown service type: ",
				       set->type, NULL);
		return FALSE;
	}
	return TRUE;
}

static void service_set_login_dump_core(struct service_settings *set)
{
	const char *p;

	if (set->parsed_type != SERVICE_TYPE_LOGIN)
		return;

	p = strstr(set->executable, " -D");
	if (p != NULL && (p[3] == '\0' || p[3] == ' '))
		set->login_dump_core = TRUE;
}

static bool
services_have_protocol(struct master_settings *set, const char *name)
{
	struct service_settings *service;

	array_foreach_elem(&set->parsed_services, service) {
		if (strcmp(service->protocol, name) == 0)
			return TRUE;
	}
	return FALSE;
}

#ifdef CONFIG_BINARY
static const struct service_settings *
master_default_settings_get_service(const char *name)
{
	for (unsigned int i = 0; config_all_services[i].set != NULL; i++) {
		if (strcmp(config_all_services[i].set->name, name) == 0)
			return config_all_services[i].set;
	}
	return NULL;
}
#endif

static unsigned int
service_get_client_limit(struct master_settings *set, const char *name)
{
	struct service_settings *service;

	array_foreach_elem(&set->parsed_services, service) {
		if (strcmp(service->name, name) == 0)
			return service->client_limit;
	}
	i_panic("Unexpectedly didn't find service %s", name);
}

static bool service_is_enabled(const struct master_settings *set,
			       struct service_settings *service)
{
	if (service->protocol[0] == '\0')
		return TRUE;
	return array_is_created(&set->protocols) &&
		array_lsearch(&set->protocols, &service->protocol, i_strcmp_p) != NULL;
}

static bool
master_service_get_file_listeners(pool_t pool, struct event *event,
				  const char *set_name, const char *service_name,
				  const struct setting_parser_info *info,
				  const ARRAY_TYPE(const_string) *listener_names,
				  ARRAY_TYPE(file_listener_settings) *parsed_listeners,
				  const char **error_r)
{
	const struct file_listener_settings *listener_set;
	const char *name, *error;
	bool ret = TRUE;

	if (!array_is_created(listener_names))
		return TRUE;

	event = event_create(event);
	settings_event_add_list_filter_name(event, "service", service_name);

	p_array_init(parsed_listeners, pool, array_count(listener_names));
	array_foreach_elem(listener_names, name) {
		if (settings_get_filter(event, set_name, name, info,
					0, &listener_set, &error) < 0) {
			*error_r = t_strdup_printf("Failed to get %s %s: %s",
						   set_name, name, error);
			ret = FALSE;
			break;
		}
		struct file_listener_settings *listener_set_dup =
			p_memdup(pool, listener_set, sizeof(*listener_set));

		pool_add_external_ref(pool, listener_set->pool);
		array_push_back(parsed_listeners, &listener_set_dup);
		settings_free(listener_set);
	}
	event_unref(&event);
	return ret;
}

static bool
master_service_get_inet_listeners(struct service_settings *service_set,
				  const char *service_name,
				  pool_t pool, struct event *event,
				  const char **error_r)
{
	const struct inet_listener_settings *listener_set;
	const struct master_settings *master_set;
	const char *name, *error;
	bool ret = TRUE;

	if (!array_is_created(&service_set->inet_listeners))
		return TRUE;

	event = event_create(event);
	settings_event_add_list_filter_name(event, "service", service_name);

	p_array_init(&service_set->parsed_inet_listeners, pool,
		     array_count(&service_set->inet_listeners));
	array_foreach_elem(&service_set->inet_listeners, name) {
		if (settings_get_filter(event, "inet_listener", name,
					&inet_listener_setting_parser_info,
					0, &listener_set, &error) < 0) {
			*error_r = t_strdup_printf(
				"Failed to get inet_listener %s: %s",
				name, error);
			ret = FALSE;
			break;
		}

		struct event *event2 = event_create(event);
		settings_event_add_list_filter_name(event2, "inet_listener",
						    name);
		if (settings_get(event2, &master_setting_parser_info,
				 SETTINGS_GET_FLAG_NO_CHECK,
				 &master_set, &error) < 0) {
			*error_r = t_strdup_printf(
				"Failed to get inet_listener %s: %s",
				name, error);
			ret = FALSE;
			settings_free(listener_set);
			event_unref(&event2);
			break;
		}
		event_unref(&event2);

		struct inet_listener_settings *listener_set_dup =
			p_memdup(pool, listener_set, sizeof(*listener_set));
		unsigned int listeners = array_count(&master_set->listen);
		p_array_init(&listener_set_dup->listen, pool, listeners);

		pool_add_external_ref(pool, listener_set->pool);
		const char *address;
		array_foreach_elem(&master_set->listen, address) {
			const char **address_copy =
				array_append_space(&listener_set_dup->listen);
			*address_copy = p_strdup(listener_set_dup->pool, address);
		}
		settings_free(master_set);

		array_push_back(&service_set->parsed_inet_listeners,
				&listener_set_dup);
		settings_free(listener_set);
	}
	event_unref(&event);
	return ret;
}

static int
master_settings_get_services(struct master_settings *set, pool_t pool,
			     struct event *event, const char **error_r)
{
	const struct service_settings *service_set;
	const char *service_name, *error;

	p_array_init(&set->parsed_services, pool,
		     array_count(&set->services));
	array_foreach_elem(&set->services, service_name) {
		if (settings_get_filter(event, "service", service_name,
					&service_setting_parser_info,
					0, &service_set, &error) < 0) {
			if (event_find_field_recursive(event,
					SETTINGS_EVENT_NO_EXPAND) != NULL)
				return 0;
			*error_r = t_strdup_printf("Failed to get service %s: %s",
						   service_name, error);
			return -1;
		}
		struct service_settings *service_set_dup =
			p_memdup(pool, service_set, sizeof(*service_set));

		pool_add_external_ref(pool, service_set->pool);
		array_push_back(&set->parsed_services, &service_set_dup);
		settings_free(service_set);

		if (!master_service_get_file_listeners(pool, event,
				"unix_listener", service_name,
				&unix_listener_setting_parser_info,
				&service_set_dup->unix_listeners,
				&service_set_dup->parsed_unix_listeners,
				error_r))
			return -1;
		if (!master_service_get_file_listeners(pool, event,
				"fifo_listener", service_name,
				&fifo_listener_setting_parser_info,
				&service_set_dup->fifo_listeners,
				&service_set_dup->parsed_fifo_listeners,
				error_r))
			return -1;
		if (!master_service_get_inet_listeners(service_set_dup,
						       service_name, pool,
						       event, error_r))
			return -1;
	}
	return 1;
}

static bool
master_settings_ext_check(struct event *event, void *_set,
			  pool_t pool, const char **error_r)
{
	static bool warned_auth = FALSE, warned_anvil = FALSE;
	struct master_settings *set = _set;
	struct service_settings *const *services;
	const char *const *strings, *proto;
	ARRAY_TYPE(const_string) all_listeners;
	struct passwd pw;
	unsigned int i, j, count, client_limit, process_limit;
	unsigned int max_auth_client_processes, max_anvil_client_processes;
	string_t *max_auth_client_processes_reason = t_str_new(64);
	string_t *max_anvil_client_processes_reason = t_str_new(64);
	size_t len;
	int ret;
#ifdef CONFIG_BINARY
	const struct service_settings *default_service;
#else
	rlim_t fd_limit;
	const char *max_client_limit_source = "BUG";
	unsigned int max_client_limit = 0;
#endif


	len = strlen(set->base_dir);
	if (len > 0 && set->base_dir[len-1] == '/') {
		/* drop trailing '/' */
		set->base_dir = p_strndup(pool, set->base_dir, len - 1);
	}

	if (set->last_valid_uid != 0 &&
	    set->first_valid_uid > set->last_valid_uid) {
		*error_r = "first_valid_uid can't be larger than last_valid_uid";
		return FALSE;
	}
	if (set->last_valid_gid != 0 &&
	    set->first_valid_gid > set->last_valid_gid) {
		*error_r = "first_valid_gid can't be larger than last_valid_gid";
		return FALSE;
	}

	if (i_getpwnam(set->default_login_user, &pw) == 0) {
		*error_r = t_strdup_printf("default_login_user doesn't exist: %s",
					   set->default_login_user);
		return FALSE;
	}
	if (i_getpwnam(set->default_internal_user, &pw) == 0) {
		*error_r = t_strdup_printf("default_internal_user doesn't exist: %s",
					   set->default_internal_user);
		return FALSE;
	}

	/* check that we have at least one service. the actual service
	   structure validity is checked later while creating them. */
	if (!array_is_created(&set->services) ||
	    array_count(&set->services) == 0) {
#ifdef CONFIG_BINARY
		return TRUE;
#else
		*error_r = "No services defined";
		return FALSE;
#endif
	}
	if (array_is_empty(&set->listen)) {
		*error_r = "listen can't be set empty";
		return FALSE;
	}
	if ((ret = master_settings_get_services(set, pool, event, error_r)) <= 0)
		return ret == 0;
	services = array_get(&set->parsed_services, &count);
	for (i = 0; i < count; i++) {
		struct service_settings *service = services[i];

		if (*service->name == '\0') {
			*error_r = t_strdup_printf(
				"Service #%d is missing name", i);
			return FALSE;
		}
		if (!master_settings_parse_type(service, error_r))
			return FALSE;
		for (j = 0; j < i; j++) {
			if (strcmp(service->name, services[j]->name) == 0) {
				*error_r = t_strdup_printf(
					"Duplicate service name: %s",
					service->name);
				return FALSE;
			}
		}
		expand_user(&service->user, &service->user_default, set);
		expand_groups(&service->extra_groups, set);
		service_set_login_dump_core(service);
	}

	if (array_is_created(&set->protocols)) {
		array_foreach_elem(&set->protocols, proto) {
			if (!services_have_protocol(set, proto)) {
				*error_r = t_strdup_printf("protocols: "
					"Unknown protocol: %s", proto);
				return FALSE;
			}
		}
	}
	t_array_init(&all_listeners, 64);
	max_auth_client_processes = 0;
	max_anvil_client_processes = 2; /* blocking, nonblocking pipes */
	for (i = 0; i < count; i++) {
		struct service_settings *service = services[i];

		if (!service_is_enabled(set, service)) {
			/* protocol not enabled, ignore its settings */
			continue;
		}

		if (*service->executable != '/' &&
		    *service->executable != '\0') {
			service->executable =
				p_strconcat(pool, set->libexec_dir, "/",
					    service->executable, NULL);
		}
		if (*service->chroot != '/' && *service->chroot != '\0') {
			service->chroot =
				p_strconcat(pool, set->base_dir, "/",
					    service->chroot, NULL);
		}
		if (service->drop_priv_before_exec &&
		    *service->chroot != '\0') {
			*error_r = t_strdup_printf("service(%s): "
				"drop_priv_before_exec=yes can't be "
				"used with chroot", service->name);
			return FALSE;
		}
		process_limit = service->process_limit;
		if (process_limit == 0) {
			*error_r = t_strdup_printf("service(%s): "
				"process_limit must be greater than 0",
				service->name);
			return FALSE;
		}
		if (service->process_min_avail > process_limit) {
			*error_r = t_strdup_printf("service(%s): "
				"process_min_avail is greater than process_limit",
				service->name);
			return FALSE;
		}
		if (service->client_limit == 0) {
			*error_r = t_strdup_printf("service(%s): "
				"client_limit must be greater than 0",
				service->name);
			return FALSE;
		}
		if (service->restart_request_count == 0) {
			*error_r = t_strdup_printf("service(%s): "
				"restart_request_count must be greater than 0 "
				"(did you mean \"unlimited\"?)",
				service->name);
			return FALSE;
		}
		if (service->idle_kill_interval == 0) {
			*error_r = t_strdup_printf("service(%s): "
				"idle_kill_interval must be greater than 0 "
				"(did you mean \"unlimited\"?)",
				service->name);
			return FALSE;
		}
		if (service->vsz_limit < 1024*1024) {
			*error_r = t_strdup_printf("service(%s): "
				"vsz_limit is too low "
				"(did you mean \"unlimited\"?)", service->name);
			return FALSE;
		}

#ifdef CONFIG_BINARY
		default_service =
			master_default_settings_get_service(service->name);
		if (default_service != NULL &&
		    default_service->process_limit_1 && process_limit > 1) {
			*error_r = t_strdup_printf("service(%s): "
				"process_limit must be 1", service->name);
			return FALSE;
		}
#else
		if (max_client_limit < service->client_limit) {
			max_client_limit = service->client_limit;
			max_client_limit_source = t_strdup_printf(
				"service %s { client_limit }", service->name);
		}
#endif

		if (*service->protocol != '\0') {
			/* each imap/pop3/lmtp process can use up a connection,
			   although if restart_request_count=1 it's only temporary.
			   imap-hibernate doesn't do any auth lookups. */
			if ((service->restart_request_count != 1 ||
			     strcmp(service->type, "login") == 0) &&
			    strcmp(service->name, "imap-hibernate") != 0) {
				str_printfa(max_auth_client_processes_reason,
					    " + service %s { process_limit=%u }",
					    service->name, process_limit);
				max_auth_client_processes += process_limit;
			}
		}
		if (strcmp(service->type, "login") == 0 ||
		    strcmp(service->name, "auth") == 0) {
			max_anvil_client_processes += process_limit;
			str_printfa(max_anvil_client_processes_reason,
				    " + service %s { process_limit=%u }",
				    service->name, process_limit);
		}

		if (!fix_file_listener_paths(&service->parsed_unix_listeners, pool,
					     set, &all_listeners, error_r)) {
			*error_r = t_strdup_printf("service(%s): unix_listener: %s",
						   service->name, *error_r);
			return FALSE;
		}
		if (!fix_file_listener_paths(&service->parsed_fifo_listeners, pool,
					     set, &all_listeners, error_r)) {
			*error_r = t_strdup_printf("service(%s): fifo_listener: %s",
						   service->name, *error_r);
			return FALSE;
		}
		add_inet_listeners(&service->parsed_inet_listeners, &all_listeners);
	}

	client_limit = service_get_client_limit(set, "auth");
	if (client_limit < max_auth_client_processes && !warned_auth) {
		warned_auth = TRUE;
		str_delete(max_auth_client_processes_reason, 0, 3);
		i_warning("service auth { client_limit=%u } is lower than "
			  "required under max. load (%u). "
			  "Counted for protocol services with restart_request_count != 1: %s",
			  client_limit, max_auth_client_processes,
			  str_c(max_auth_client_processes_reason));
	}

	client_limit = service_get_client_limit(set, "anvil");
	if (client_limit < max_anvil_client_processes && !warned_anvil) {
		warned_anvil = TRUE;
		str_delete(max_anvil_client_processes_reason, 0, 3);
		i_warning("service anvil { client_limit=%u } is lower than "
			  "required under max. load (%u). Counted with: %s",
			  client_limit, max_anvil_client_processes,
			  str_c(max_anvil_client_processes_reason));
	}
#ifndef CONFIG_BINARY
	if (restrict_get_fd_limit(&fd_limit) == 0 &&
	    fd_limit < (rlim_t)max_client_limit) {
		i_warning("fd limit (ulimit -n) is lower than required "
			  "under max. load (%u < %u), because of %s",
			  (unsigned int)fd_limit, max_client_limit,
			  max_client_limit_source);
	}
#endif

	/* check for duplicate listeners */
	array_sort(&all_listeners, i_strcmp_p);
	strings = array_get(&all_listeners, &count);
	for (i = 1; i < count; i++) {
		if (strcmp(strings[i-1], strings[i]) == 0) {
			*error_r = t_strdup_printf("duplicate listener: %s",
						   strings[i]);
			return FALSE;
		}
	}
	return TRUE;
}
/* </settings checks> */

static bool
login_want_core_dumps(const struct master_settings *set, gid_t *gid_r)
{
	struct service_settings *service;
	const char *error;
	bool cores = FALSE;
	uid_t uid;

	*gid_r = (gid_t)-1;

	array_foreach_elem(&set->parsed_services, service) {
		if (service->parsed_type == SERVICE_TYPE_LOGIN) {
			if (service->login_dump_core)
				cores = TRUE;
			(void)get_uidgid(service->user, &uid, gid_r, &error);
			if (*service->group != '\0')
				(void)get_gid(service->group, gid_r, &error);
		}
	}
	return cores;
}

static void unlink_sockets(const char *path, const char *prefix)
{
	DIR *dirp;
	struct dirent *dp;
	struct stat st;
	string_t *str;
	size_t prefix_len;

	dirp = opendir(path);
	if (dirp == NULL) {
		i_error("opendir(%s) failed: %m", path);
		return;
	}

	prefix_len = strlen(prefix);
	str = t_str_new(256);
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;

		if (strncmp(dp->d_name, prefix, prefix_len) != 0)
			continue;

		str_truncate(str, 0);
		str_printfa(str, "%s/%s", path, dp->d_name);
		if (lstat(str_c(str), &st) < 0) {
			if (errno != ENOENT)
				i_error("lstat(%s) failed: %m", str_c(str));
			continue;
		}
		if (!S_ISSOCK(st.st_mode))
			continue;

		/* try to avoid unlinking sockets if someone's already
		   listening in them. do this only at startup, because
		   when SIGHUPing a child process might catch the new
		   connection before it notices that it's supposed
		   to die. */
		if (!startup_finished) {
			int fd = net_connect_unix(str_c(str));
			if (fd != -1 || errno != ECONNREFUSED) {
				i_fatal("Dovecot is already running? "
					"Socket already exists: %s",
					str_c(str));
			}
		}

		i_unlink_if_exists(str_c(str));
	}
	(void)closedir(dirp);
}

static void
mkdir_login_dir(const struct master_settings *set, const char *login_dir)
{
	mode_t mode;
	gid_t gid;

	/* Make sure the login directory exists with correct permissions and it's
	   empty. */
	mode = login_want_core_dumps(set, &gid) ? 0770 : 0750;
	if (safe_mkdir(login_dir, mode, master_uid, gid) == 0) {
		i_warning("Corrected permissions for login directory "
			  "%s", login_dir);
	}

	unlink_sockets(login_dir, "");
}

static void mkdir_listener(const struct file_listener_settings *set,
			   const char *dir, unsigned int mode)
{
	const char *error;
	uid_t uid;
	gid_t gid;

	/* Use the specified permissions for the parent directory, but only
	   if the directory doesn't already exist. It's likely not important
	   enough to change permissions for an existing directory and it might
	   cause problems if the permissions are intentionally different. */
	if (get_uidgid(set->user, &uid, &gid, &error) < 0 ||
	    get_gid(set->group, &gid, &error) < 0)
		i_fatal("%s (for creating directory %s)", error, dir);
	else if (mkdir(dir, mode) == 0) {
		if (chown(dir, uid, gid) < 0)
			i_fatal("chown(%s) failed: %m", dir);
	} else if (errno != EEXIST) {
		i_fatal("mkdir(%s) failed: %m", dir);
	}
}

static int
file_listener_settings_cmp_path(struct file_listener_settings *const *f1,
				struct file_listener_settings *const *f2)
{
	return strcmp((*f1)->path, (*f2)->path);
}

static void
subdir_add(ARRAY_TYPE(file_listener_settings) *subdir_listeners,
	   struct file_listener_settings *f, const char *base_prefix)
{
	if (!str_begins_with(f->path, base_prefix)) {
		/* not under base_dir */
		return;
	}

	const char *rel_path = f->path + strlen(base_prefix);
	if (strchr(rel_path, '/') == NULL) {
		/* not under a subdirectory */
		return;
	}

	if (str_begins_with(rel_path, "login/") ||
	    str_begins_with(rel_path, "token-login/")) {
		/* these are handled specially */
		return;
	}
	array_push_back(subdir_listeners, &f);
}

static void mkdir_listener_subdirs(const struct master_settings *set)
{
	struct service_settings *service;
	ARRAY_TYPE(file_listener_settings) subdir_listeners;
	struct file_listener_settings *f, *const *files;
	unsigned int i, count, files_mode, dir_mode;
	const char *p1, *p2, *last_group, *base_prefix;
	size_t dir1_len, dir2_len;

	/* First gather all unix/fifo listeners that have directories under
	   base_dir. */
	t_array_init(&subdir_listeners, 16);
	base_prefix = t_strconcat(set->base_dir, "/", NULL);
	array_foreach_elem(&set->parsed_services, service) {
		if (!service_is_enabled(set, service))
			continue;

		if (array_is_created(&service->parsed_unix_listeners)) {
			array_foreach_elem(&service->parsed_unix_listeners, f)
				subdir_add(&subdir_listeners, f, base_prefix);
		}
		if (array_is_created(&service->parsed_fifo_listeners)) {
			array_foreach_elem(&service->parsed_fifo_listeners, f)
				subdir_add(&subdir_listeners, f, base_prefix);
		}
	}
	/* Sort the listeners by path, so the listeners with same directories
	   are next to each others. */
	array_sort(&subdir_listeners, file_listener_settings_cmp_path);
	files = array_get(&subdir_listeners, &count);
	files_mode = 0; last_group = NULL;
	for (i = 0; i < count; i++) {
		p1 = strrchr(files[i]->path, '/');
		i_assert(p1 != NULL);
		dir1_len = p1 - files[i]->path;
		/* Create the directory permissions based on the union of its
		   file listeners permissions. */
		files_mode |= files[i]->mode;
		if ((files[i]->mode & 0070) != 0)
			last_group = files[i]->group;

		if (i+1 < count) {
			/* Delay creating the directory if the next listener
			   has the same directory. */
			p2 = strrchr(files[i+1]->path, '/');
			i_assert(p2 != NULL);
			dir2_len = p2 - files[i+1]->path;
			if (dir1_len == dir2_len &&
			    memcmp(files[i]->path, files[i+1]->path, dir1_len) == 0) {
				/* If the user or group differs, add more
				   permission bits to the mode. */
				if (strcmp(files[i]->user, files[i+1]->user) != 0)
					files_mode |= 0006;
				if (last_group != NULL &&
				    (files[i+1]->mode & 0070) != 0 &&
				    strcmp(files[i]->group, last_group) != 0)
					files_mode |= 0006;
				continue;
			}
		}
		/* keep the owner permissions +rwx, but group and other
		   permissions only as +rx. */
		dir_mode = 0700;
		if ((files_mode & 0070) != 0) dir_mode |= 0050;
		if ((files_mode & 0007) != 0) dir_mode |= 0005;
		mkdir_listener(files[i], t_strndup(files[i]->path, dir1_len),
			       dir_mode);
		files_mode = 0; last_group = NULL;
	}
}

void master_settings_do_fixes(const struct master_settings *set)
{
	const char *empty_dir;
	struct stat st;

	/* since base dir is under /var/run by default, it may have been
	   deleted. */
	if (mkdir_parents(set->base_dir, 0755) < 0 && errno != EEXIST)
		i_fatal("mkdir(%s) failed: %m", set->base_dir);
	/* allow base_dir to be a symlink, so don't use lstat() */
	if (stat(set->base_dir, &st) < 0)
		i_fatal("stat(%s) failed: %m", set->base_dir);
	if (!S_ISDIR(st.st_mode))
		i_fatal("%s is not a directory", set->base_dir);
	if ((st.st_mode & 0755) != 0755) {
		i_warning("Fixing permissions of %s to be world-readable",
			  set->base_dir);
		if (chmod(set->base_dir, 0755) < 0)
			i_error("chmod(%s) failed: %m", set->base_dir);
	}

	/* Make sure our permanent state directory exists */
	if (mkdir_parents(set->state_dir, 0755) < 0 && errno != EEXIST)
		i_fatal("mkdir(%s) failed: %m", set->state_dir);

	mkdir_login_dir(set, t_strconcat(set->base_dir, "/login", NULL));
	mkdir_login_dir(set, t_strconcat(set->base_dir, "/token-login", NULL));
	mkdir_listener_subdirs(set);

	empty_dir = t_strconcat(set->base_dir, "/empty", NULL);
	if (safe_mkdir(empty_dir, 0755, master_uid, getegid()) == 0) {
		i_warning("Corrected permissions for empty directory "
			  "%s", empty_dir);
	}
}
