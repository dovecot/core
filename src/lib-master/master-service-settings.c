/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "event-filter.h"
#include "path-util.h"
#include "fdpass.h"
#include "write-full.h"
#include "str.h"
#include "syslog-util.h"
#include "eacces-error.h"
#include "env-util.h"
#include "execv-const.h"
#include "settings.h"
#include "settings-parser.h"
#include "stats-client.h"
#include "master-service-private.h"
#include "master-service-ssl-settings.h"
#include "master-service-settings.h"

#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

#define DOVECOT_CONFIG_BIN_PATH BINDIR"/doveconf"
#define DOVECOT_CONFIG_SOCKET_PATH PKG_RUNDIR"/config"

#define CONFIG_READ_TIMEOUT_SECS 10
#define CONFIG_HANDSHAKE "VERSION\tconfig\t3\t0\n"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct master_service_settings)

static bool
master_service_settings_check(void *_set, pool_t pool, const char **error_r);

static const struct setting_define master_service_setting_defines[] = {
	DEF(STR, base_dir),
	DEF(STR, state_dir),
	DEF(STR, instance_name),
	DEF(STR, log_path),
	DEF(STR, info_log_path),
	DEF(STR, debug_log_path),
	DEF(STR, log_timestamp),
	DEF(STR, log_debug),
	DEF(STR, log_core_filter),
	DEF(STR, process_shutdown_filter),
	DEF(STR, syslog_facility),
	DEF(STR, import_environment),
	DEF(STR, stats_writer_socket_path),
	DEF(BOOL, version_ignore),
	DEF(BOOL, shutdown_clients),
	DEF(BOOL, verbose_proctitle),

	DEF(STR, haproxy_trusted_networks),
	DEF(TIME, haproxy_timeout),

	SETTING_DEFINE_LIST_END
};

/* <settings checks> */
#ifdef HAVE_LIBSYSTEMD
#  define ENV_SYSTEMD " LISTEN_PID LISTEN_FDS NOTIFY_SOCKET"
#else
#  define ENV_SYSTEMD ""
#endif
#ifdef DEBUG
#  define ENV_GDB " GDB DEBUG_SILENT"
#else
#  define ENV_GDB ""
#endif
/* </settings checks> */

static const struct master_service_settings master_service_default_settings = {
	.base_dir = PKG_RUNDIR,
	.state_dir = PKG_STATEDIR,
	.instance_name = PACKAGE,
	.log_path = "syslog",
	.info_log_path = "",
	.debug_log_path = "",
	.log_timestamp = DEFAULT_FAILURE_STAMP_FORMAT,
	.log_debug = "",
	.log_core_filter = "",
	.process_shutdown_filter = "",
	.syslog_facility = "mail",
	.import_environment = "TZ CORE_OUTOFMEM CORE_ERROR PATH" ENV_SYSTEMD ENV_GDB,
	.stats_writer_socket_path = "stats-writer",
	.version_ignore = FALSE,
	.shutdown_clients = TRUE,
	.verbose_proctitle = FALSE,

	.haproxy_trusted_networks = "",
	.haproxy_timeout = 3
};

const struct setting_parser_info master_service_setting_parser_info = {
	.name = "master_service",

	.defines = master_service_setting_defines,
	.defaults = &master_service_default_settings,

	.pool_offset1 = 1 + offsetof(struct master_service_settings, pool),
	.struct_size = sizeof(struct master_service_settings),
	.check_func = master_service_settings_check
};

/* <settings checks> */
static bool
setting_filter_parse(const char *set_name, const char *set_value,
		     void (*handle_filter)(struct event_filter *) ATTR_UNUSED,
		     const char **error_r)
{
	struct event_filter *filter;
	const char *error;

	if (set_value[0] == '\0')
		return TRUE;

	filter = event_filter_create();
	if (event_filter_parse(set_value, filter, &error) < 0) {
		*error_r = t_strdup_printf("Invalid %s: %s", set_name, error);
		event_filter_unref(&filter);
		return FALSE;
	}
#ifndef CONFIG_BINARY
	handle_filter(filter);
#endif
	event_filter_unref(&filter);
	return TRUE;
}

static void
master_service_set_process_shutdown_filter_wrapper(struct event_filter *filter)
{
	master_service_set_process_shutdown_filter(master_service, filter);
}

static bool
master_service_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			      const char **error_r)
{
	struct master_service_settings *set = _set;
	int facility;

	if (*set->log_path == '\0') {
		/* default to syslog logging */
		set->log_path = "syslog";
	}
	if (!syslog_facility_find(set->syslog_facility, &facility)) {
		*error_r = t_strdup_printf("Unknown syslog_facility: %s",
					   set->syslog_facility);
		return FALSE;
	}

	if (!setting_filter_parse("log_debug", set->log_debug,
				  event_set_global_debug_log_filter, error_r))
		return FALSE;
	if (!setting_filter_parse("log_core_filter", set->log_core_filter,
				  event_set_global_core_log_filter, error_r))
		return FALSE;
	if (!setting_filter_parse("process_shutdown_filter",
				  set->process_shutdown_filter,
				  master_service_set_process_shutdown_filter_wrapper,
				  error_r))
		return FALSE;
	return TRUE;
}
/* </settings checks> */

static void strarr_push(ARRAY_TYPE(const_string) *argv, const char *str)
{
	array_push_back(argv, &str);
}

static void ATTR_NORETURN
master_service_exec_config(struct master_service *service,
			   const struct master_service_settings_input *input)
{
	ARRAY_TYPE(const_string) conf_argv;
	const char *binary_path = service->argv[0];
	const char *error = NULL;

	if (!t_binary_abspath(&binary_path, &error)) {
		i_fatal("t_binary_abspath(%s) failed: %s", binary_path, error);
	}

	if (!service->keep_environment && !input->preserve_environment) {
		if (input->preserve_home)
			master_service_import_environment("HOME");
		if (input->preserve_user)
			master_service_import_environment("USER");
		if ((service->flags & MASTER_SERVICE_FLAG_STANDALONE) != 0)
			master_service_import_environment(DOVECOT_LOG_STDERR_TIMESTAMP_ENV);

		/* doveconf empties the environment before exec()ing us back
		   if DOVECOT_PRESERVE_ENVS is set, so make sure it is. */
		if (getenv(DOVECOT_PRESERVE_ENVS_ENV) == NULL)
			env_put(DOVECOT_PRESERVE_ENVS_ENV, "");
	} else {
		/* make sure doveconf doesn't remove any environment */
		env_remove(DOVECOT_PRESERVE_ENVS_ENV);
	}
	if (input->use_sysexits)
		env_put("USE_SYSEXITS", "1");

	if (input->protocol != NULL)
		env_put("DOVECONF_PROTOCOL", input->protocol);

	t_array_init(&conf_argv, 11 + (service->argc + 1) + 1);
	strarr_push(&conf_argv, DOVECOT_CONFIG_BIN_PATH);
	strarr_push(&conf_argv, "-c");
	strarr_push(&conf_argv, service->config_path);

	if (input->check_full_config)
		strarr_push(&conf_argv, "-C");
	if (input->hide_obsolete_warnings)
		strarr_push(&conf_argv, "-w");
	strarr_push(&conf_argv, "-F");
	strarr_push(&conf_argv, binary_path);
	array_append(&conf_argv, (const char *const *)service->argv + 1,
		     service->argc);
	array_append_zero(&conf_argv);

	const char *const *argv = array_front(&conf_argv);
	execv_const(argv[0], argv);
}

static void
config_error_update_path_source(struct master_service *service,
				const struct master_service_settings_input *input,
				const char **error)
{
	if (input->config_path == NULL && service->config_path_from_master) {
		*error = t_strdup_printf("%s (path is from %s environment)",
					 *error, MASTER_CONFIG_FILE_ENV);
	}
}

static void
config_exec_fallback(struct master_service *service,
		     const struct master_service_settings_input *input,
		     const char **error)
{
	const char *path, *stat_error;
	struct stat st;
	int saved_errno = errno;

	if (input->never_exec) {
		*error = t_strdup_printf(
			"%s - doveconf execution fallback is disabled", *error);
		return;
	}

	path = input->config_path != NULL ? input->config_path :
		master_service_get_config_path(service);
	if (stat(path, &st) < 0)
		stat_error = t_strdup_printf("stat(%s) failed: %m", path);
	else if (S_ISSOCK(st.st_mode))
		stat_error = t_strdup_printf("%s is a UNIX socket", path);
	else if (S_ISFIFO(st.st_mode))
		stat_error = t_strdup_printf("%s is a FIFO", path);
	else {
		/* it's a file, not a socket/pipe */
		master_service_exec_config(service, input);
	}
	*error = t_strdup_printf(
		"%s - Also failed to read config by executing doveconf: %s",
		*error, stat_error);
	config_error_update_path_source(service, input, error);
	errno = saved_errno;
}

static int
master_service_open_config(struct master_service *service,
			   const struct master_service_settings_input *input,
			   const char **path_r, const char **error_r)
{
	struct stat st;
	const char *path;
	int fd = -1;

	*path_r = path = input->config_path != NULL ? input->config_path :
		master_service_get_config_path(service);

	if (!service->config_path_from_master &&
	    !service->config_path_changed_with_param &&
	    !input->always_exec &&
	    input->config_path == NULL) {
		/* first try to connect to the default config socket.
		   configuration may contain secrets, so in default config
		   this fails because the socket is 0600. it's useful for
		   developers though. :) */
		fd = net_connect_unix(DOVECOT_CONFIG_SOCKET_PATH);
		if (fd >= 0)
			*path_r = DOVECOT_CONFIG_SOCKET_PATH;
		else {
			/* fallback to executing doveconf */
		}
	}

	if (fd == -1) {
		if (stat(path, &st) < 0) {
			*error_r = errno == EACCES ?
				eacces_error_get("stat", path) :
				t_strdup_printf("stat(%s) failed: %m", path);
			config_error_update_path_source(service, input, error_r);
			return -1;
		}

		if (!S_ISSOCK(st.st_mode) && !S_ISFIFO(st.st_mode)) {
			/* it's not an UNIX socket, don't even try to connect */
			fd = -1;
			errno = ENOTSOCK;
		} else {
			fd = net_connect_unix_with_retries(path, 1000);
		}
		if (fd < 0) {
			*error_r = t_strdup_printf(
				"net_connect_unix(%s) failed: %m", path);
			config_exec_fallback(service, input, error_r);
			return -1;
		}
	}
	net_set_nonblock(fd, FALSE);
	string_t *str = t_str_new(128);
	str_append(str, CONFIG_HANDSHAKE"REQ");
	if (input->reload_config)
		str_append(str, "\treload");
	str_append_c(str, '\n');
	alarm(CONFIG_READ_TIMEOUT_SECS);
	int ret = write_full(fd, str_data(str), str_len(str));
	if (ret < 0)
		*error_r = t_strdup_printf("write_full(%s) failed: %m", path);
	else
		*error_r = NULL;

	int config_fd = -1;
	if (ret == 0) {
		/* read the config fd as reply */
		char buf[1024];
		ret = fd_read(fd, buf, sizeof(buf)-1, &config_fd);
		if (ret < 0)
			*error_r = t_strdup_printf("fd_read() failed: %m");
		else if (ret > 0 && buf[0] == '+' && buf[1] == '\n') {
			/* success, if fd was received */
			if (config_fd == -1)
				*error_r = "Failed to read config: FD not received";
		} else if (ret > 0 && buf[0] == '-') {
			buf[ret] = '\0';
			*error_r = t_strdup_printf("Failed to read config: %s",
						   t_strcut(buf+1, '\n'));
			i_close_fd(&config_fd);
		} else {
			buf[ret] = '\0';
			*error_r = t_strdup_printf(
				"Failed to read config: Unexpected reply '%s'",
				t_strcut(buf, '\n'));
			i_close_fd(&config_fd);
		}
	}
	alarm(0);
	i_close_fd(&fd);

	if (config_fd == -1) {
		i_assert(*error_r != NULL);
		config_exec_fallback(service, input, error_r);
		return -1;
	}
	return config_fd;
}

static void
master_service_append_config_overrides(struct master_service *service)
{
	const char *const *cli_overrides;
	unsigned int i, count;

	if (!array_is_created(&service->config_overrides))
		return;

	cli_overrides = array_get(&service->config_overrides, &count);
	for (i = 0; i < count; i++) {
		const char *key, *value;
		t_split_key_value_eq(cli_overrides[i], &key, &value);

		settings_root_override(service->settings_root, key, value,
				       SETTINGS_OVERRIDE_TYPE_CLI_PARAM);
	}
}

int master_service_settings_read(struct master_service *service,
				 const struct master_service_settings_input *input,
				 struct master_service_settings_output *output_r,
				 const char **error_r)
{
	const char *path = NULL, *value, *error;
	int ret, fd = -1;

	i_zero(output_r);
	output_r->config_fd = -1;

	if (input->config_fd > 0) {
		/* unit test */
		fd = input->config_fd;
		path = t_strdup_printf("<input fd %d>", fd);
	} else if (settings_has_mmap(service->settings_root) &&
		   !input->reload_config) {
		/* config was already read once */
	} else if ((value = getenv(DOVECOT_CONFIG_FD_ENV)) != NULL) {
		/* doveconf -F parameter already executed us back.
		   The configuration is in DOVECOT_CONFIG_FD. */
		if (str_to_int(value, &fd) < 0 || fd < 0)
			i_fatal("Invalid "DOVECOT_CONFIG_FD_ENV": %s", value);
		path = t_strdup_printf("<"DOVECOT_CONFIG_FD_ENV" %d>", fd);
	} else if ((service->flags & MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS) == 0) {
		/* Open config via socket if possible. If it doesn't work,
		   execute doveconf -F. */
		T_BEGIN {
			fd = master_service_open_config(service, input, &path,
							&error);
		} T_END_PASS_STR_IF(fd == -1, &error);
		if (fd == -1) {
			if (errno == EACCES)
				output_r->permission_denied = TRUE;
			*error_r = t_strdup_printf(
				"Failed to read configuration: %s", error);
			return -1;
		}
	}
	if (!settings_has_mmap(service->settings_root)) {
		/* first time reading settings */
		master_service_append_config_overrides(service);
	}
	if (fd != -1) {
		const char *service_name = input->no_service_filter ?
			NULL : service->name;
		const char *protocol_name = input->protocol != NULL ?
			input->protocol : service->name;
		enum settings_read_flags read_flags =
			!input->no_protocol_filter ? 0 :
			SETTINGS_READ_NO_PROTOCOL_FILTER;
		ret = settings_read(service->settings_root, fd, path,
				    service_name, protocol_name, read_flags,
				    &output_r->specific_services,
				    &error);
		if (input->return_config_fd)
			output_r->config_fd = fd;
		else
			i_close_fd(&fd);
		if (ret < 0) {
			if (getenv(DOVECOT_CONFIG_FD_ENV) != NULL) {
				i_fatal("Failed to parse config from fd %d: %s",
					fd, error);
			}
			*error_r = t_strdup_printf(
				"Failed to parse configuration: %s", error);
			return -1;
		}
		env_remove(DOVECOT_CONFIG_FD_ENV);
	}

	/* Create event for matching config filters */
	struct event *event = event_create(NULL);
	event_add_str(event, "protocol", input->protocol != NULL ?
		      input->protocol : service->name);

	settings_free(service->set);
	ret = settings_get(event, &master_service_setting_parser_info,
			   !input->no_key_validation ? 0 :
			   SETTINGS_GET_NO_KEY_VALIDATION,
			   &service->set, error_r);
	event_unref(&event);
	if (ret < 0)
		return -1;

	if (service->set->version_ignore &&
	    (service->flags & MASTER_SERVICE_FLAG_STANDALONE) != 0) {
		/* running standalone. we want to ignore plugin versions. */
		service->version_string = NULL;
	}
	if ((service->flags & MASTER_SERVICE_FLAG_DONT_SEND_STATS) == 0 &&
	    (service->flags & MASTER_SERVICE_FLAG_STANDALONE) != 0) {
		/* When running standalone (e.g. doveadm) try to connect to the
		   stats socket, but don't log an error if it's not running.
		   It may be intentional. Non-standalone stats-client
		   initialization was already done earlier. */
		master_service_init_stats_client(service, TRUE);
	}

	if (service->set->shutdown_clients)
		master_service_set_die_with_master(master_service, TRUE);
	return 0;
}

int master_service_settings_read_simple(struct master_service *service,
					const char **error_r)
{
	struct master_service_settings_input input;
	struct master_service_settings_output output;

	i_zero(&input);
	return master_service_settings_read(service, &input, &output, error_r);
}

const struct master_service_settings *
master_service_get_service_settings(struct master_service *service)
{
	return service->set;
}
