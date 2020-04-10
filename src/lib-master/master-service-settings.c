/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "event-filter.h"
#include "path-util.h"
#include "istream.h"
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
#define CONFIG_HANDSHAKE "VERSION\tconfig\t2\t0\n"

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
	if (input->service != NULL) {
		strarr_push(&conf_argv, "-f");
		strarr_push(&conf_argv,
			    t_strconcat("service=", input->service, NULL));
	}
	strarr_push(&conf_argv, "-c");
	strarr_push(&conf_argv, service->config_path);
	if (input->module != NULL) {
		strarr_push(&conf_argv, "-m");
		strarr_push(&conf_argv, input->module);
	}
	if (input->extra_modules != NULL) {
		for (unsigned int i = 0; input->extra_modules[i] != NULL; i++) {
			strarr_push(&conf_argv, "-m");
			strarr_push(&conf_argv, input->extra_modules[i]);
		}
	}
	if ((service->flags & MASTER_SERVICE_FLAG_DISABLE_SSL_SET) == 0 &&
	    (input->module != NULL || input->extra_modules != NULL)) {
		strarr_push(&conf_argv, "-m");
		if (service->want_ssl_server)
			strarr_push(&conf_argv, "ssl-server");
		else
			strarr_push(&conf_argv, "ssl");
	}
	if (input->parse_full_config)
		strarr_push(&conf_argv, "-p");

	strarr_push(&conf_argv, "-e");
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
	int fd;

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
	    input->config_path == NULL) {
		/* first try to connect to the default config socket.
		   configuration may contain secrets, so in default config
		   this fails because the socket is 0600. it's useful for
		   developers though. :) */
		fd = net_connect_unix(DOVECOT_CONFIG_SOCKET_PATH);
		if (fd >= 0) {
			*path_r = DOVECOT_CONFIG_SOCKET_PATH;
			net_set_nonblock(fd, FALSE);
			return fd;
		}
		/* fallback to executing doveconf */
	}

	if (stat(path, &st) < 0) {
		*error_r = errno == EACCES ? eacces_error_get("stat", path) :
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
		*error_r = t_strdup_printf("net_connect_unix(%s) failed: %m",
					   path);
		config_exec_fallback(service, input, error_r);
		return -1;
	}
	net_set_nonblock(fd, FALSE);
	return fd;
}

static void
config_build_request(struct master_service *service, string_t *str,
		     const struct master_service_settings_input *input)
{
	str_append(str, "REQ");
	if (input->module != NULL)
		str_printfa(str, "\tmodule=%s", input->module);
	if (input->extra_modules != NULL) {
		for (unsigned int i = 0; input->extra_modules[i] != NULL; i++)
			str_printfa(str, "\tmodule=%s", input->extra_modules[i]);
	}
	if ((service->flags & MASTER_SERVICE_FLAG_DISABLE_SSL_SET) == 0 &&
	    (input->module != NULL || input->extra_modules != NULL)) {
		str_printfa(str, "\tmodule=%s",
			    service->want_ssl_server ? "ssl-server" : "ssl");
	}
	if (input->no_ssl_ca)
		str_append(str, "\texclude=ssl_ca\texclude=ssl_verify_client_cert");
	if (input->service != NULL)
		str_printfa(str, "\tservice=%s", input->service);
	if (input->username != NULL)
		str_printfa(str, "\tuser=%s", input->username);
	if (input->local_ip.family != 0)
		str_printfa(str, "\tlip=%s", net_ip2addr(&input->local_ip));
	if (input->remote_ip.family != 0)
		str_printfa(str, "\trip=%s", net_ip2addr(&input->remote_ip));
	if (input->local_name != NULL)
		str_printfa(str, "\tlname=%s", input->local_name);
	str_append_c(str, '\n');
}

static int
config_send_request(struct master_service *service,
		    const struct master_service_settings_input *input,
		    int fd, const char *path, const char **error_r)
{
	int ret;

	T_BEGIN {
		string_t *str;

		str = t_str_new(128);
		str_append(str, CONFIG_HANDSHAKE);
		config_build_request(service, str, input);
		ret = write_full(fd, str_data(str), str_len(str));
	} T_END;
	if (ret < 0) {
		*error_r = t_strdup_printf("write_full(%s) failed: %m", path);
		return -1;
	}
	return 0;
}

static int
config_send_filters_request(int fd, const char *path, const char **error_r)
{
	int ret;
	ret = write_full(fd, CONFIG_HANDSHAKE"FILTERS\n", strlen(CONFIG_HANDSHAKE"FILTERS\n"));
	if (ret < 0) {
		*error_r = t_strdup_printf("write_full(%s) failed: %m", path);
		return -1;
	}
	return 0;
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

static int
config_read_reply_header(struct istream *istream, const char *path, pool_t pool,
			 const struct master_service_settings_input *input,
			 struct master_service_settings_output *output_r,
			 const char **error_r)
{
	const char *line;
	ssize_t ret;

	while ((ret = i_stream_read(istream)) > 0) {
		line = i_stream_next_line(istream);
		if (line != NULL)
			break;
	}
	if (ret <= 0) {
		if (ret == 0)
			return 1;
		*error_r = istream->stream_errno != 0 ?
			t_strdup_printf("read(%s) failed: %s", path,
					i_stream_get_error(istream)) :
			t_strdup_printf("read(%s) failed: EOF", path);
		return -1;
	}

	T_BEGIN {
		const char *value, *const *arg = t_strsplit_tabescaped(line);
		ARRAY_TYPE(const_string) services;

		p_array_init(&services, pool, 8);
		for (; *arg != NULL; arg++) {
			if (strcmp(*arg, "service-uses-local") == 0)
				output_r->service_uses_local = TRUE;
			else if (strcmp(*arg, "service-uses-remote") == 0)
				output_r->service_uses_remote = TRUE;
			if (strcmp(*arg, "used-local") == 0)
				output_r->used_local = TRUE;
			else if (strcmp(*arg, "used-remote") == 0)
				output_r->used_remote = TRUE;
			else if (str_begins(*arg, "service=", &value)) {
				const char *name = p_strdup(pool, value);
				array_push_back(&services, &name);
			 }
		}
		if (input->service == NULL) {
			array_append_zero(&services);
			output_r->specific_services = array_front(&services);
		}
	} T_END;
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
	    (service->flags & MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS) != 0)
		return;

	i_zero(&input);
	input.never_exec = TRUE;
	fd = master_service_open_config(service, &input, &path, &error);
	if (fd != -1)
		service->config_fd = fd;
}

int master_service_settings_get_filters(struct master_service *service,
					const char *const **filters,
					const char **error_r)
{
	struct master_service_settings_input input;
	int fd;
	bool retry = TRUE;
	const char *path = NULL;
	ARRAY_TYPE(const_string) filters_tmp;
	t_array_init(&filters_tmp, 8);
	i_zero(&input);

	if (getenv("DOVECONF_ENV") == NULL &&
	    (service->flags & MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS) == 0) {
		retry = service->config_fd != -1;
		for (;;) {
			fd = master_service_open_config(service, &input, &path, error_r);
			if (fd == -1) {
				return -1;
			}
			if (config_send_filters_request(fd, path, error_r) == 0)
				break;

			i_close_fd(&fd);
			if (!retry)
				return -1;
			retry = FALSE;
		}
		service->config_fd = fd;
		struct istream *is = i_stream_create_fd(fd, SIZE_MAX);
		const char *line;
		/* try read response */
		while((line = i_stream_read_next_line(is)) != NULL) {
			if (*line == '\0')
				break;
			if (str_begins(line, "FILTER\t", &line)) {
				line = t_strdup(line);
				array_push_back(&filters_tmp, &line);
			}
		}
		i_stream_unref(&is);
	}

	array_append_zero(&filters_tmp);
	*filters = array_front(&filters_tmp);
	return 0;
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
	const char *path = NULL, *error;
	void **sets;
	unsigned int i;
	int ret, fd = -1;
	time_t now, timeout;
	bool use_environment, retry;

	i_zero(output_r);

	if (getenv("DOVECONF_ENV") == NULL &&
	    (service->flags & MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS) == 0) {
		retry = service->config_fd != -1;
		for (;;) {
			fd = master_service_open_config(service, input,
							&path, error_r);
			if (fd == -1) {
				if (errno == EACCES)
					output_r->permission_denied = TRUE;
				return -1;
			}

			if (config_send_request(service, input, fd,
						path, error_r) == 0)
				break;
			i_close_fd(&fd);
			if (!retry) {
				config_exec_fallback(service, input, error_r);
				return -1;
			}
			/* config process died, retry connecting */
			retry = FALSE;
		}
	}

	if (service->set_pool != NULL) {
		if (service->set_parser != NULL)
			settings_parser_deinit(&service->set_parser);
		p_clear(service->set_pool);
	} else {
		service->set_pool =
			pool_alloconly_create("master service settings", 16384);
	}

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
		now = time(NULL);
		timeout = now + CONFIG_READ_TIMEOUT_SECS;
		do {
			alarm(timeout - now);
			ret = config_read_reply_header(istream, path,
						       service->set_pool, input,
						       output_r, error_r);
			if (ret == 0) {
				ret = settings_parse_stream_read(parser,
								 istream);
				if (ret < 0)
					*error_r = t_strdup(
						settings_parser_get_error(parser));
			}
			alarm(0);
			if (ret <= 0)
				break;

			/* most likely timed out, but just in case some other
			   signal was delivered early check if we need to
			   continue */
			now = time(NULL);
		} while (now < timeout);
		i_stream_unref(&istream);

		if (ret != 0) {
			if (ret > 0) {
				*error_r = t_strdup_printf(
					"Timeout reading config from %s", path);
			}
			i_close_fd(&fd);
			config_exec_fallback(service, input, error_r);
			settings_parser_deinit(&parser);
			return -1;
		}

		if ((service->flags & MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN) != 0 &&
		    service->config_fd == -1 && input->config_path == NULL)
			service->config_fd = fd;
		else
			i_close_fd(&fd);
		use_environment = FALSE;
	} else {
		use_environment = TRUE;
	}

	if (use_environment || service->keep_environment) {
		if (settings_parse_environ(parser) < 0) {
			*error_r = t_strdup(settings_parser_get_error(parser));
			settings_parser_deinit(&parser);
			return -1;
		}
	}

	if (array_is_created(&service->config_overrides)) {
		if (master_service_apply_config_overrides(service, parser,
							  error_r) < 0) {
			settings_parser_deinit(&parser);
			return -1;
		}
	}

	if (!settings_parser_check(parser, service->set_pool, &error)) {
		*error_r = t_strdup_printf("Invalid settings: %s", error);
		settings_parser_deinit(&parser);
		return -1;
	}

	sets = settings_parser_get_list(parser);
	service->set = sets[0];
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
	input.module = service->name;
	return master_service_settings_read(service, &input, &output, error_r);
}

pool_t master_service_settings_detach(struct master_service *service)
{
	pool_t pool = service->set_pool;

	settings_parser_deinit(&service->set_parser);
	service->set_pool = NULL;
	return pool;
}

const struct master_service_settings *
master_service_settings_get(struct master_service *service)
{
	void **sets;

	sets = settings_parser_get_list(service->set_parser);
	return sets[0];
}

void **master_service_settings_get_others(struct master_service *service)
{
	return master_service_settings_parser_get_others(service,
							 service->set_parser);
}

void **master_service_settings_parser_get_others(struct master_service *service,
						 const struct setting_parser_context *set_parser)
{
	return settings_parser_get_list(set_parser) + 2 +
		(service->want_ssl_server ? 1 : 0);
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
