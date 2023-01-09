/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "event-filter.h"
#include "path-util.h"
#include "mmap-util.h"
#include "fdpass.h"
#include "write-full.h"
#include "str.h"
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

	if (input->service != NULL)
		env_put("DOVECONF_SERVICE", input->service);

	t_array_init(&conf_argv, 11 + (service->argc + 1) + 1);
	strarr_push(&conf_argv, DOVECOT_CONFIG_BIN_PATH);
	strarr_push(&conf_argv, "-c");
	strarr_push(&conf_argv, service->config_path);

	if (input->disable_check_settings)
		strarr_push(&conf_argv, "-E");
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
	if (input->disable_check_settings)
		str_append(str, "\tdisable-check-settings");
	str_append_c(str, '\n');
	alarm(CONFIG_READ_TIMEOUT_SECS);
	int ret = write_full(fd, str_data(str), str_len(str));
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
master_service_settings_read_mmap(struct setting_parser_context *parser,
				  struct event *event,
				  const unsigned char *mmap_base,
				  size_t mmap_size,
				  struct master_service_settings_output *output_r,
				  const char **error_r)
{
	/*
	   DOVECOT-CONFIG <TAB> 1.0 <LF>

	   <64bit big-endian global settings blob size>
	   [ key <NUL> value <NUL>, ... ]

	   <64bit big-endian filter settings blob size>
	   filter_string <NUL>
	   [ key <NUL> value <NUL>, ... ]

	   ... more filters ...

	   Settings are read until the blob size is reached. There is no
	   padding/alignment. The mmaped data comes from a trusted source
	   (if we can't trust the config, what can we trust?), so for
	   performance and simplicity we trust the mmaped data to be properly
	   NUL-terminated. If it's not, it can cause a segfault. */
	ARRAY_TYPE(const_string) protocols;

	t_array_init(&protocols, 8);
	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG,
	};

	const char *magic_prefix = "DOVECOT-CONFIG\t";
	const unsigned int magic_prefix_len = strlen(magic_prefix);
	const unsigned char *eol = memchr(mmap_base, '\n', mmap_size);
	if (mmap_size < magic_prefix_len ||
	    memcmp(magic_prefix, mmap_base, magic_prefix_len) != 0 ||
	    eol == NULL) {
		*error_r = "File header doesn't begin with DOVECOT-CONFIG line";
		return -1;
	}
	if (mmap_base[magic_prefix_len] != '1' ||
	    mmap_base[magic_prefix_len+1] != '.') {
		*error_r = t_strdup_printf(
			"Unsupported config file version '%s'",
			t_strdup_until(mmap_base + magic_prefix_len, eol));
		return -1;
	}

	size_t start_offset = eol - mmap_base + 1;
	uoff_t offset = start_offset;
	do {
		/* <blob size> */
		uint64_t blob_size;
		if (offset + sizeof(blob_size) > mmap_size) {
			*error_r = t_strdup_printf(
				"Config file size too small "
				"(offset=%zu, file_size=%zu)", offset, mmap_size);
			return -1;
		}
		blob_size = be64_to_cpu_unaligned(mmap_base + offset);
		if (offset + blob_size > mmap_size) {
			*error_r = t_strdup_printf(
				"Settings blob points outside file "
				"(offset=%zu, blob_size=%"PRIu64", file_size=%zu)",
				offset, blob_size, mmap_size);
			return -1;
		}
		size_t end_offset = offset + blob_size;
		offset += sizeof(blob_size);

		/* <filter> */
		if (offset > start_offset + sizeof(blob_size)) {
			const char *filter_string =
				(const char *)mmap_base + offset;
			offset += strlen(filter_string) + 1;
			if (offset > end_offset) {
				*error_r = t_strdup_printf(
					"Filter points outside blob "
					"(offset=%zu, end_offset=%zu, file_size=%zu)",
					offset, end_offset, mmap_size);
				return -1;
			}

			struct event_filter *filter = event_filter_create();
			const char *error;
			filter_string_parse_protocol(filter_string, &protocols);
			if (event_filter_parse(filter_string, filter, &error) < 0) {
				*error_r = t_strdup_printf(
					"Received invalid filter '%s': %s",
					filter_string, error);
				event_filter_unref(&filter);
				return -1;
			}
			bool match = filter_string[0] == '\0' ||
				event_filter_match(filter, event,
						   &failure_ctx);
			event_filter_unref(&filter);
			if (!match) {
				/* Filter didn't match. Jump to the next one. */
				offset = end_offset;
				continue;
			}
		}

		/* list of settings: key, value, ... */
		while (offset < end_offset) {
			const char *key = (const char *)mmap_base + offset;
			offset += strlen(key)+1;
			const char *value = (const char *)mmap_base + offset;
			offset += strlen(value)+1;
			if (offset > end_offset) {
				*error_r = t_strdup_printf(
					"Settings key/value points outside blob "
					"(offset=%zu, end_offset=%zu, file_size=%zu)",
					offset, end_offset, mmap_size);
				return -1;
			}
			int ret;
			T_BEGIN {
				ret = settings_parse_keyvalue(parser, key, value);
				if (ret < 0)
					*error_r = t_strdup(settings_parser_get_error(parser));
			} T_END_PASS_STR_IF(ret < 0, error_r);
			if (ret < 0)
				return -1;
		}
	} while (offset < mmap_size);

	if (array_count(&protocols) > 0) {
		array_append_zero(&protocols);
		output_r->specific_services = array_front(&protocols);
	}
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
	const char *path = NULL, *value, *error;
	unsigned int i;
	int ret, fd = -1;

	i_zero(output_r);
	output_r->config_fd = -1;

	if (service->config_mmap_base != NULL && !input->reload_config) {
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
		fd = master_service_open_config(service, input, &path, error_r);
		if (fd == -1) {
			if (errno == EACCES)
				output_r->permission_denied = TRUE;
			return -1;
		}
	}
	if (fd != -1) {
		if (service->config_mmap_base != NULL) {
			i_assert(input->reload_config);
			if (munmap(service->config_mmap_base,
				   service->config_mmap_size) < 0)
				i_error("munmap(<config>) failed: %m");
		}

		service->config_mmap_base =
			mmap_ro_file(fd, &service->config_mmap_size);
		if (service->config_mmap_base == MAP_FAILED)
			i_fatal("Failed to read config: mmap(%s) failed: %m", path);
		if (service->config_mmap_size == 0)
			i_fatal("Failed to read config: %s file size is empty", path);

		if (input->return_config_fd)
			output_r->config_fd = fd;
		else
			i_close_fd(&fd);
		env_remove(DOVECOT_CONFIG_FD_ENV);
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

	/* config_mmap_base is NULL only if
	   MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS is used */
	if (service->config_mmap_base != NULL) {
		ret = master_service_settings_read_mmap(parser, event,
			service->config_mmap_base, service->config_mmap_size,
			output_r, error_r);

		if (ret < 0) {
			if (getenv(DOVECOT_CONFIG_FD_ENV) != NULL) {
				i_fatal("Failed to parse config from fd %d: %s",
					fd, *error_r);
			}
			settings_parser_unref(&parser);
			event_unref(&event);
			return -1;
		}
	}
	event_unref(&event);

	if (array_is_created(&service->config_overrides)) {
		if (master_service_apply_config_overrides(service, parser,
							  error_r) < 0) {
			settings_parser_unref(&parser);
			return -1;
		}
	}

	if (!input->disable_check_settings) {
		if (!settings_parser_check(parser, service->set_pool, &error)) {
			*error_r = t_strdup_printf("Invalid settings: %s", error);
			settings_parser_unref(&parser);
			return -1;
		}
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
