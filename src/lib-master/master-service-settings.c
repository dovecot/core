/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "event-filter.h"
#include "path-util.h"
#include "istream.h"
#include "fdpass.h"
#include "write-full.h"
#include "str.h"
#include "strescape.h"
#include "syslog-util.h"
#include "eacces-error.h"
#include "env-util.h"
#include "execv-const.h"
#include "settings-parser.h"
#include "stats-client.h"
#include "master-service-private.h"
#include "master-service-ssl-settings.h"
#include "master-service-settings.h"

#include <stddef.h>
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
	DEF(SIZE, config_cache_size),
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
	.import_environment = "TZ CORE_OUTOFMEM CORE_ERROR" ENV_SYSTEMD ENV_GDB,
	.stats_writer_socket_path = "stats-writer",
	.config_cache_size = 1024*1024,
	.version_ignore = FALSE,
	.shutdown_clients = TRUE,
	.verbose_proctitle = FALSE,

	.haproxy_trusted_networks = "",
	.haproxy_timeout = 3
};

const struct setting_parser_info master_service_setting_parser_info = {
	.module_name = "master",
	.defines = master_service_setting_defines,
	.defaults = &master_service_default_settings,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct master_service_settings),

	.parent_offset = SIZE_MAX,
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
			master_service_import_environment("LOG_STDERR_TIMESTAMP");

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

	t_array_init(&conf_argv, 11 + (service->argc + 1) + 1);
	strarr_push(&conf_argv, DOVECOT_CONFIG_BIN_PATH);
	strarr_push(&conf_argv, "-c");
	strarr_push(&conf_argv, service->config_path);

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

	if (service->config_fd != -1 && input->config_path == NULL &&
	    !service->config_path_changed_with_param) {
		/* use the already opened config socket */
		fd = service->config_fd;
		service->config_fd = -1;
		return fd;
	}

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
	const char *str = !input->reload_config ?
		CONFIG_HANDSHAKE"REQ\n" :
		CONFIG_HANDSHAKE"REQ\treload\n";
	alarm(CONFIG_READ_TIMEOUT_SECS);
	int ret = write_full(fd, str, strlen(str));
	if (ret < 0)
		*error_r = t_strdup_printf("write_full(%s) failed: %m", path);

	int config_fd = -1;
	if (ret == 0) {
		/* read the config fd as reply */
		char buf[1024];
		ret = fd_read(fd, buf, sizeof(buf)-1, &config_fd);
		if (ret < 0)
			*error_r = t_strdup_printf("fd_read() failed: %m");
		else if (ret > 0 && buf[0] == '+' && buf[1] == '\n')
			; /* success */
		else if (ret > 0 && buf[0] == '-') {
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
		config_exec_fallback(service, input, error_r);
		return -1;
	}
	return config_fd;
}

static int
master_service_apply_config_overrides(struct master_service *service,
				      struct setting_parser_context *parser,
				      const char **error_r)
{
	const char *const *overrides;
	unsigned int i, count;

	overrides = array_get(&service->config_overrides, &count);
	for (i = 0; i < count; i++) {
		if (settings_parse_line(parser, overrides[i]) < 0) {
			*error_r = t_strdup_printf(
				"Invalid -o parameter %s: %s", overrides[i],
				settings_parser_get_error(parser));
			return -1;
		}
		settings_parse_set_key_expanded(parser, service->set_pool,
						t_strcut(overrides[i], '='));
	}
	return 0;
}

void master_service_config_socket_try_open(struct master_service *service)
{
	struct master_service_settings_input input;
	const char *path, *error;
	int fd;

	/* we'll get here before command line parameters have been parsed,
	   so -O, -c and -i parameters haven't been handled yet at this point.
	   this means we could end up opening config socket connection
	   unnecessarily, but this isn't a problem. we'll just have to
	   ignore it later on. (unfortunately there isn't a master_service_*()
	   call where this function would be better called.) */
	if (getenv("DOVECONF_ENV") != NULL ||
	    getenv(DOVECOT_CONFIG_FD_ENV) != NULL ||
	    (service->flags & MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS) != 0)
		return;

	i_zero(&input);
	input.never_exec = TRUE;
	fd = master_service_open_config(service, &input, &path, &error);
	if (fd != -1) {
		service->config_fd = fd;
		fd_close_on_exec(service->config_fd, TRUE);
	}
}

static void
filter_string_parse_protocol(const char *filter_string,
			     ARRAY_TYPE(const_string) *protocols)
{
	const char *p = strstr(filter_string, "protocol=\"");
	if (p == NULL)
		return;
	const char *p2 = strchr(p + 10, '"');
	if (p2 == NULL)
		return;
	const char *protocol = t_strdup_until(p + 10, p2);
	if (p - filter_string > 4 && strcmp(p - 4, "NOT ") == 0)
		protocol = t_strconcat("!", protocol, NULL);
	array_push_back(protocols, &protocol);
}

static int
master_service_settings_read_stream(struct setting_parser_context *parser,
				    struct event *event, struct istream *input,
				    struct master_service_settings_output *output_r,
				    const char **error_r)
{
	const char *line, *filter_string, *error;
	unsigned int linenum = 0;
	ARRAY_TYPE(const_string) protocols;
	bool filter_match = TRUE;
	int ret;

	t_array_init(&protocols, 8);
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG,
	};
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (*line == '\0') {
			/* empty line finishes it */
			if (array_count(&protocols) > 0) {
				array_append_zero(&protocols);
				output_r->specific_services =
					array_front(&protocols);
			}
			return 0;
		}
		linenum++;
		if (str_begins(line, ":FILTER ", &filter_string)) {
			struct event_filter *filter = event_filter_create();
			filter_string_parse_protocol(filter_string, &protocols);
			if (event_filter_parse(filter_string, filter, &error) < 0) {
				*error_r = t_strdup_printf(
					"Line %u: Received invalid FILTER %s: %s",
					linenum, filter_string, error);
				ret = -1;
			} else {
				ret = 0;
				filter_match = filter_string[0] == '\0' ||
					event_filter_match(filter, event,
							   &failure_ctx);
			}
			event_filter_unref(&filter);
			if (ret < 0)
				return -1;
			continue;
		}
		if (!filter_match)
			continue;

		T_BEGIN {
			line = t_str_tabunescape(line);
			ret = settings_parse_line(parser, line);
		} T_END;

		if (ret < 0) {
			*error_r = t_strdup_printf("Line %u: %s", linenum,
				settings_parser_get_error(parser));
			return -1;
		}
	}

	if (input->stream_errno != 0) {
		*error_r = t_strdup_printf("read(%s) failed: %s",
					   i_stream_get_name(input),
					   i_stream_get_error(input));
	} else if (input->v_offset == 0) {
		*error_r = t_strdup_printf(
			"read(%s) returned EOF before receiving any data",
			i_stream_get_name(input));
	} else {
		*error_r = t_strdup_printf(
			"read(%s) returned EOF before receiving end-of-settings line",
			i_stream_get_name(input));
	}
	return -1;
}

int master_service_settings_read(struct master_service *service,
				 const struct master_service_settings_input *input,
				 struct master_service_settings_output *output_r,
				 const char **error_r)
{
	ARRAY(const struct setting_parser_info *) all_roots;
	const struct setting_parser_info *tmp_root;
	struct setting_parser_context *parser;
	struct istream *istream;
	const char *path = NULL, *value, *error;
	unsigned int i;
	int ret, fd = -1;
	bool use_environment = FALSE;

	i_zero(output_r);

	if (service->config_fd != -1 && !input->reload_config) {
		/* config was already read once */
		fd = service->config_fd;
		if (lseek(fd, 0, SEEK_SET) < 0)
			i_fatal("lseek(config fd) failed: %m");
		path = "<config fd>";
	} else if ((value = getenv(DOVECOT_CONFIG_FD_ENV)) != NULL) {
		/* doveconf -F parameter already executed us back.
		   The configuration is in DOVECOT_CONFIG_FD. */
		if (str_to_int(value, &fd) < 0 || fd < 0)
			i_fatal("Invalid "DOVECOT_CONFIG_FD_ENV": %s", value);
		path = t_strdup_printf("<"DOVECOT_CONFIG_FD_ENV" %d>", fd);
	} else if (getenv("DOVECONF_ENV") != NULL) {
		use_environment = (service->flags &
				   MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS) == 0;
	} else if ((service->flags & MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS) == 0) {
		/* Open config via socket if possible. If it doesn't work,
		   execute doveconf -F. */
		fd = master_service_open_config(service, input, &path, error_r);
		if (fd == -1) {
			if (errno == EACCES)
				output_r->permission_denied = TRUE;
			return -1;
		}
	}

	if (service->set_pool != NULL) {
		if (service->set_parser != NULL)
			settings_parser_unref(&service->set_parser);
		p_clear(service->set_pool);
	} else {
		service->set_pool =
			pool_alloconly_create("master service settings", 16384);
	}

	/* Create event for matching config filters */
	struct event *event = event_create(NULL);
	event_add_str(event, "protocol", input->service);
	event_add_str(event, "user", input->username);
	event_add_str(event, "local_name", input->local_name);
	event_add_ip(event, "local_ip", &input->local_ip);
	event_add_ip(event, "remote_ip", &input->remote_ip);

	p_array_init(&all_roots, service->set_pool, 8);
	tmp_root = &master_service_setting_parser_info;
	array_push_back(&all_roots, &tmp_root);
	tmp_root = &master_service_ssl_setting_parser_info;
	array_push_back(&all_roots, &tmp_root);
	if (service->want_ssl_server) {
		tmp_root = &master_service_ssl_server_setting_parser_info;
		array_push_back(&all_roots, &tmp_root);
	}
	if (input->roots != NULL) {
		for (i = 0; input->roots[i] != NULL; i++)
			array_push_back(&all_roots, &input->roots[i]);
	}

	parser = settings_parser_init_list(service->set_pool,
			array_front(&all_roots), array_count(&all_roots),
			SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);

	if (fd != -1) {
		istream = i_stream_create_fd(fd, SIZE_MAX);
		i_stream_set_name(istream, path);
		ret = master_service_settings_read_stream(parser, event,
				istream, output_r, error_r);
		i_stream_unref(&istream);

		if (ret < 0) {
			if (getenv(DOVECOT_CONFIG_FD_ENV) != NULL) {
				i_fatal("Failed to read config from fd %d: %s",
					fd, *error_r);
			}
			i_close_fd(&fd);
			config_exec_fallback(service, input, error_r);
			settings_parser_unref(&parser);
			event_unref(&event);
			return -1;
		}

		if (input->config_path == NULL) {
			i_assert(service->config_fd == -1 ||
				 service->config_fd == fd);
			service->config_fd = fd;
			fd_close_on_exec(service->config_fd, TRUE);
		} else {
			i_close_fd(&fd);
		}
		env_remove(DOVECOT_CONFIG_FD_ENV);
	}
	event_unref(&event);

	if (use_environment || service->keep_environment) {
		if (settings_parse_environ(parser) < 0) {
			*error_r = t_strdup(settings_parser_get_error(parser));
			settings_parser_unref(&parser);
			return -1;
		}
	}

	if (array_is_created(&service->config_overrides)) {
		if (master_service_apply_config_overrides(service, parser,
							  error_r) < 0) {
			settings_parser_unref(&parser);
			return -1;
		}
	}

	if (!settings_parser_check(parser, service->set_pool, &error)) {
		*error_r = t_strdup_printf("Invalid settings: %s", error);
		settings_parser_unref(&parser);
		return -1;
	}

	service->set = settings_parser_get_root_set(parser,
				&master_service_setting_parser_info);
	service->set_parser = parser;

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

	/* if we change any settings afterwards, they're in expanded form.
	   especially all settings from userdb are already expanded. */
	settings_parse_set_expanded(service->set_parser, TRUE);
	return 0;
}

int master_service_settings_read_simple(struct master_service *service,
					const struct setting_parser_info **roots,
					const char **error_r)
{
	struct master_service_settings_input input;
	struct master_service_settings_output output;

	i_zero(&input);
	input.roots = roots;
	return master_service_settings_read(service, &input, &output, error_r);
}

pool_t master_service_settings_detach(struct master_service *service)
{
	pool_t pool = service->set_pool;

	settings_parser_unref(&service->set_parser);
	service->set_pool = NULL;
	return pool;
}

const struct master_service_settings *
master_service_settings_get(struct master_service *service)
{
	return settings_parser_get_root_set(service->set_parser,
		&master_service_setting_parser_info);
}

void *master_service_settings_get_root_set(struct master_service *service,
					   const struct setting_parser_info *root)
{
	return settings_parser_get_root_set(service->set_parser,  root);
}

void *master_service_settings_get_root_set_dup(struct master_service *service,
	const struct setting_parser_info *root, pool_t pool)
{
	return settings_dup(root,
		master_service_settings_get_root_set(service, root), pool);
}

struct setting_parser_context *
master_service_get_settings_parser(struct master_service *service)
{
	return service->set_parser;
}

int master_service_set(struct master_service *service, const char *line)
{
	return settings_parse_line(service->set_parser, line);
}

bool master_service_set_has_config_override(struct master_service *service,
					    const char *key)
{
	const char *override, *key_root;
	bool ret;

	if (!array_is_created(&service->config_overrides))
		return FALSE;

	key_root = settings_parse_unalias(service->set_parser, key);
	if (key_root == NULL)
		key_root = key;

	array_foreach_elem(&service->config_overrides, override) {
		T_BEGIN {
			const char *okey, *okey_root;

			okey = t_strcut(override, '=');
			okey_root = settings_parse_unalias(service->set_parser,
							   okey);
			if (okey_root == NULL)
				okey_root = okey;
			ret = strcmp(okey_root, key_root) == 0;
		} T_END;

		if (ret)
			return TRUE;
	}
	return FALSE;
}
