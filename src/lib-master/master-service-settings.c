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
	{ type, #name, offsetof(struct master_service_settings, name), NULL }

static bool
master_service_settings_check(void *_set, pool_t pool, const char **error_r);

static const struct setting_define master_service_setting_defines[] = {
	DEF(SET_STR, base_dir),
	DEF(SET_STR, state_dir),
	DEF(SET_STR, log_path),
	DEF(SET_STR, info_log_path),
	DEF(SET_STR, debug_log_path),
	DEF(SET_STR, log_timestamp),
	DEF(SET_STR, log_debug),
	DEF(SET_STR, log_core_filter),
	DEF(SET_STR, syslog_facility),
	DEF(SET_STR, import_environment),
	DEF(SET_STR, stats_writer_socket_path),
	DEF(SET_SIZE, config_cache_size),
	DEF(SET_BOOL, version_ignore),
	DEF(SET_BOOL, shutdown_clients),
	DEF(SET_BOOL, verbose_proctitle),

	DEF(SET_STR, haproxy_trusted_networks),
	DEF(SET_TIME, haproxy_timeout),

	SETTING_DEFINE_LIST_END
};

/* <settings checks> */
#ifdef HAVE_SYSTEMD
#  define ENV_SYSTEMD " LISTEN_PID LISTEN_FDS"
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
	.log_path = "syslog",
	.info_log_path = "",
	.debug_log_path = "",
	.log_timestamp = DEFAULT_FAILURE_STAMP_FORMAT,
	.log_debug = "",
	.log_core_filter = "",
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

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct master_service_settings),

	.parent_offset = (size_t)-1,
	.check_func = master_service_settings_check
};

/* <settings checks> */
static int parse_query(const char *str, struct event_filter_query *query_r,
		       const char **error_r)
{
	ARRAY_TYPE(const_string) categories = ARRAY_INIT;
	ARRAY(struct event_filter_field) fields = ARRAY_INIT;

	i_zero(query_r);
	do {
		while (*str == ' ')
			str++;
		const char *p = strchr(str, ' ');
		if (p != NULL)
			str = t_strdup_until(str, p++);

		if (strncmp(str, "event:", 6) == 0) {
			query_r->name = str+6;
		} else if (strncmp(str, "source:", 7) == 0) {
			const char *linep = strchr(str+7, ':');
			if (linep == NULL) {
				/* filename only - match to all line numbers */
				query_r->source_filename = str+7;
			} else {
				query_r->source_filename = t_strdup_until(str+7, linep);
				if (str_to_uint(linep+1, &query_r->source_linenum) < 0) {
					*error_r = t_strdup_printf(
						"Invalid line number in '%s'", str);
					return -1;
				}
			}
		} else if (strncmp(str, "field:", 6) == 0) {
			const char *value = strchr(str+6, '=');
			if (value == NULL) {
				*error_r = t_strdup_printf(
					"Missing '=' in '%s'", str);
				return -1;
			}
			if (!array_is_created(&fields))
				t_array_init(&fields, 4);
			struct event_filter_field *field =
				array_append_space(&fields);
			field->key = t_strdup_until(str+6, value);
			field->value = value+1;
		} else if (strncmp(str, "cat:", 4) == 0 ||
			   strncmp(str, "category:", 9) == 0) {
			if (!array_is_created(&categories))
				t_array_init(&categories, 4);
			str = strchr(str, ':');
			i_assert(str != NULL);
			str++;
			array_append(&categories, &str, 1);
		} else {
			*error_r = t_strdup_printf("Unknown event '%s'", str);
			return -1;
		}
		str = p;
	} while (str != NULL);

	if (array_is_created(&categories)) {
		array_append_zero(&categories);
		query_r->categories = array_first(&categories);
	}
	if (array_is_created(&fields)) {
		array_append_zero(&fields);
		query_r->fields = array_first(&fields);
	}
	return 0;
}

int master_service_log_filter_parse(struct event_filter *filter, const char *str,
				    const char **error_r)
{
	struct event_filter_query query;
	const char *p;

	while (*str != '\0') {
		if (*str == ' ') {
			str++;
			continue;
		}

		if (*str == '(') {
			/* everything inside (...) is a single query */
			str++;
			p = strchr(str, ')');
			if (p == NULL) {
				*error_r = "Missing ')'";
				return -1;
			}
			if (parse_query(t_strdup_until(str, p), &query, error_r) < 0)
				return -1;
			str = p+1;
		} else if ((p = strchr(str, ' ')) != NULL) {
			/* parse a single-word query in the middle */
			if (parse_query(t_strdup_until(str, p), &query, error_r) < 0)
				return -1;
			str = p+1;
		} else {
			/* single-word last query */
			if (parse_query(str, &query, error_r) < 0)
				return -1;
			str = "";
		}
		event_filter_add(filter, &query);
	}

	*error_r = NULL;
	return 0;
}

static bool
log_filter_parse(const char *set_name, const char *set_value,
		 struct event_filter **filter_r, const char **error_r)
{
	const char *error;

	if (set_value[0] == '\0') {
		*filter_r = NULL;
		return TRUE;
	}

	*filter_r = event_filter_create();
	if (master_service_log_filter_parse(*filter_r, set_value, &error) < 0) {
		*error_r = t_strdup_printf("Invalid %s: %s", set_name, error);
		event_filter_unref(filter_r);
		return FALSE;
	}
	return TRUE;
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

	struct event_filter *filter;
	if (!log_filter_parse("log_debug", set->log_debug, &filter, error_r))
		return FALSE;
	if (filter != NULL) {
#ifndef CONFIG_BINARY
		event_set_global_debug_log_filter(filter);
#endif
		event_filter_unref(&filter);
	}

	if (!log_filter_parse("log_core_filter", set->log_core_filter,
			      &filter, error_r))
		return FALSE;
	if (filter != NULL) {
#ifndef CONFIG_BINARY
		event_set_global_core_log_filter(filter);
#endif
		event_filter_unref(&filter);
	}
	return TRUE;
}
/* </settings checks> */

static void ATTR_NORETURN
master_service_exec_config(struct master_service *service,
			   const struct master_service_settings_input *input)
{
	const char **conf_argv, *binary_path = service->argv[0];
	const char *error = NULL;
	unsigned int i, argv_max_count;

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
			env_put(DOVECOT_PRESERVE_ENVS_ENV"=");
	} else {
		/* make sure doveconf doesn't remove any environment */
		env_remove(DOVECOT_PRESERVE_ENVS_ENV);
	}
	if (input->use_sysexits)
		env_put("USE_SYSEXITS=1");

	/* @UNSAFE */
	i = 0;
	argv_max_count = 11 + (service->argc + 1) + 1;
	conf_argv = t_new(const char *, argv_max_count);
	conf_argv[i++] = DOVECOT_CONFIG_BIN_PATH;
	if (input->service != NULL) {
		conf_argv[i++] = "-f";
		conf_argv[i++] = t_strconcat("service=", input->service, NULL);
	}
	conf_argv[i++] = "-c";
	conf_argv[i++] = service->config_path;
	if (input->module != NULL) {
		conf_argv[i++] = "-m";
		conf_argv[i++] = input->module;
		if (service->want_ssl_settings) {
			conf_argv[i++] = "-m";
			conf_argv[i++] = "ssl";
		}
	}
	if (input->parse_full_config)
		conf_argv[i++] = "-p";

	conf_argv[i++] = "-e";
	conf_argv[i++] = binary_path;
	memcpy(conf_argv+i, service->argv + 1,
	       (service->argc) * sizeof(conf_argv[0]));
	i += service->argc;

	i_assert(i < argv_max_count);
	execv_const(conf_argv[0], conf_argv);
}

static void
config_exec_fallback(struct master_service *service,
		     const struct master_service_settings_input *input)
{
	const char *path;
	struct stat st;
	int saved_errno = errno;

	if (input->never_exec)
		return;

	path = input->config_path != NULL ? input->config_path :
		master_service_get_config_path(service);
	if (stat(path, &st) == 0 &&
	    !S_ISSOCK(st.st_mode) && !S_ISFIFO(st.st_mode)) {
		/* it's a file, not a socket/pipe */
		master_service_exec_config(service, input);
	}
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
		config_exec_fallback(service, input);
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
	if (input->module != NULL) {
		str_printfa(str, "\tmodule=%s", input->module);
		if (service->want_ssl_settings)
			str_append(str, "\tmodule=ssl");
	}
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
		const char *const *arg = t_strsplit_tabescaped(line);
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
			else if (str_begins(*arg, "service=")) {
				const char *name = p_strdup(pool, *arg + 8);
				array_append(&services, &name, 1);
			 }
		}
		if (input->service == NULL) {
			array_append_zero(&services);
			output_r->specific_services = array_first(&services);
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
		struct istream *is = i_stream_create_fd(fd, (size_t)-1);
		const char *line;
		/* try read response */
		while((line = i_stream_read_next_line(is)) != NULL) {
			if (*line == '\0')
				break;
			if (str_begins(line, "FILTER\t")) {
				line = t_strdup(line+7);
				array_append(&filters_tmp, &line, 1);
			}
		}
		i_stream_unref(&is);
	}

	array_append_zero(&filters_tmp);
	*filters = array_first(&filters_tmp);
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
				config_exec_fallback(service, input);
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
	array_append(&all_roots, &tmp_root, 1);
	if (service->want_ssl_settings) {
		tmp_root = &master_service_ssl_setting_parser_info;
		array_append(&all_roots, &tmp_root, 1);
	}
	if (input->roots != NULL) {
		for (i = 0; input->roots[i] != NULL; i++)
			array_append(&all_roots, &input->roots[i], 1);
	}

	parser = settings_parser_init_list(service->set_pool,
			array_first(&all_roots), array_count(&all_roots),
			SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);

	if (fd != -1) {
		istream = i_stream_create_fd(fd, (size_t)-1);
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
			config_exec_fallback(service, input);
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
	return settings_parser_get_list(set_parser) + 1 +
		(service->want_ssl_settings ? 1 : 0);
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
	const char *const *override, *key_root;
	bool ret;

	if (!array_is_created(&service->config_overrides))
		return FALSE;

	key_root = settings_parse_unalias(service->set_parser, key);
	if (key_root == NULL)
		key_root = key;

	array_foreach(&service->config_overrides, override) {
		T_BEGIN {
			const char *okey, *okey_root;

			okey = t_strcut(*override, '=');
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
