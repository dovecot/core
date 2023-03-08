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
#include "var-expand.h"
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

struct master_service_mmap_filter {
	struct event_filter *filter;
	bool empty_filter;

	size_t start_offset, end_offset;
};

struct master_settings_mmap {
	int refcount;
	void *mmap_base;
	size_t mmap_size;

	size_t set_start_offset, set_end_offset;
	ARRAY(struct master_service_mmap_filter) filters;
};

struct master_service_set {
	int type;
	bool append;
	const char *key, *value;
};
ARRAY_DEFINE_TYPE(master_service_set, struct master_service_set);

struct master_service_settings_instance {
	pool_t pool;
	struct master_service *service;
	ARRAY_TYPE(master_service_set) settings;
};

static const char *master_service_set_type_names[] = {
	"userdb", "-o parameter", "hardcoded"
};
static_assert_array_size(master_service_set_type_names,
			 MASTER_SERVICE_SET_TYPE_COUNT);

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
	.module_name = "master",
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

static void
master_service_append_config_overrides(struct master_service *service,
				       ARRAY_TYPE(master_service_set) *settings)
{
	const char *const *overrides;
	unsigned int i, count;

	if (!array_is_created(&service->config_overrides))
		return;

	overrides = array_get(&service->config_overrides, &count);
	for (i = 0; i < count; i++) {
		const char *key, *value;
		t_split_key_value_eq(overrides[i], &key, &value);
		struct master_service_set *set = array_append_space(settings);
		set->type = MASTER_SERVICE_SET_TYPE_CLI_PARAM;
		set->key = key;
		set->value = value;
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
master_service_settings_mmap_parse(struct master_settings_mmap *config_mmap,
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
	const unsigned char *mmap_base = config_mmap->mmap_base;
	size_t mmap_size = config_mmap->mmap_size;
	ARRAY_TYPE(const_string) protocols;

	t_array_init(&protocols, 8);

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

	struct master_service_mmap_filter *config_filter;
	array_foreach_modifiable(&config_mmap->filters, config_filter)
		event_filter_unref(&config_filter->filter);
	array_clear(&config_mmap->filters);

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

		if (offset <= start_offset + sizeof(blob_size)) {
			/* base settings */
			config_mmap->set_start_offset = offset;
			config_mmap->set_end_offset = end_offset;
		} else {
			/* <filter> */
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

			config_filter = array_append_space(&config_mmap->filters);
			config_filter->filter = event_filter_create();
			config_filter->empty_filter = filter_string[0] == '\0';
			config_filter->start_offset = offset;
			config_filter->end_offset = end_offset;

			const char *error;
			filter_string_parse_protocol(filter_string, &protocols);
			if (event_filter_parse(filter_string,
					       config_filter->filter, &error) < 0) {
				*error_r = t_strdup_printf(
					"Received invalid filter '%s': %s",
					filter_string, error);
				return -1;
			}
		}

		/* skip the actual settings here */
		offset = end_offset;
	} while (offset < mmap_size);

	if (array_count(&protocols) > 0) {
		array_append_zero(&protocols);
		output_r->specific_services = array_front(&protocols);
	}
	return 0;
}

static int
master_service_settings_mmap_apply_blob(struct master_settings_mmap *config_mmap,
					struct setting_parser_context *parser,
					size_t start_offset, size_t end_offset,
					const char **error_r)
{
	size_t offset = start_offset;

	/* list of settings: key, value, ... */
	while (offset < end_offset) {
		const char *key = (const char *)config_mmap->mmap_base + offset;
		offset += strlen(key)+1;
		const char *value = (const char *)config_mmap->mmap_base + offset;
		offset += strlen(value)+1;
		if (offset > end_offset) {
			*error_r = t_strdup_printf(
				"Settings key/value points outside blob "
				"(offset=%zu, end_offset=%zu, file_size=%zu)",
				offset, end_offset, config_mmap->mmap_size);
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
	return 0;
}

static int
master_service_settings_mmap_apply(struct master_settings_mmap *config_mmap,
				   struct event *event,
				   struct setting_parser_context *parser,
				   const char **error_r)
{
	if (master_service_settings_mmap_apply_blob(config_mmap, parser,
						    config_mmap->set_start_offset,
						    config_mmap->set_end_offset,
						    error_r) < 0)
		return -1;

	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG,
	};

	const struct master_service_mmap_filter *config_filter;
	array_foreach(&config_mmap->filters, config_filter) {
		if (config_filter->empty_filter ||
		    event_filter_match(config_filter->filter, event,
				       &failure_ctx)) {
			if (master_service_settings_mmap_apply_blob(
					config_mmap, parser,
					config_filter->start_offset,
					config_filter->end_offset,
					error_r) < 0)
				return -1;
		}
	}
	return 0;

}

void master_settings_mmap_ref(struct master_settings_mmap *mmap)
{
	i_assert(mmap->refcount > 0);

	mmap->refcount++;
}

void master_settings_mmap_unref(struct master_settings_mmap **_mmap)
{
	struct master_settings_mmap *mmap = *_mmap;
	if (mmap == NULL)
		return;
	i_assert(mmap->refcount > 0);

	*_mmap = NULL;
	if (--mmap->refcount > 0)
		return;

	struct master_service_mmap_filter *config_filter;
	array_foreach_modifiable(&mmap->filters, config_filter)
		event_filter_unref(&config_filter->filter);
	array_free(&mmap->filters);

	if (munmap(mmap->mmap_base, mmap->mmap_size) < 0)
		i_error("munmap(<config>) failed: %m");
	i_free(mmap);
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

	if (service->config_mmap != NULL && !input->reload_config) {
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
	if (fd != -1) {
		struct master_settings_mmap *config_mmap;
		master_settings_mmap_unref(&service->config_mmap);
		config_mmap = i_new(struct master_settings_mmap, 1);
		config_mmap->refcount = 1;
		config_mmap->mmap_base =
			mmap_ro_file(fd, &config_mmap->mmap_size);
		if (config_mmap->mmap_base == MAP_FAILED)
			i_fatal("Failed to read config: mmap(%s) failed: %m", path);
		if (config_mmap->mmap_size == 0)
			i_fatal("Failed to read config: %s file size is empty", path);
		i_array_init(&config_mmap->filters, 32);

		service->config_mmap = config_mmap;

		if (input->return_config_fd)
			output_r->config_fd = fd;
		else
			i_close_fd(&fd);
		env_remove(DOVECOT_CONFIG_FD_ENV);
	}

	/* Remember the protocol for following settings instance lookups */
	i_free(service->set_protocol_name);
	service->set_protocol_name = i_strdup(input->service);

	/* Create event for matching config filters */
	struct event *event = event_create(NULL);
	event_add_str(event, "protocol", input->service);

	/* config_mmap is NULL only if MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS
	   is used */
	if (service->config_mmap != NULL) {
		ret = master_service_settings_mmap_parse(service->config_mmap,
			output_r, &error);
		if (ret < 0) {
			if (getenv(DOVECOT_CONFIG_FD_ENV) != NULL) {
				i_fatal("Failed to parse config from fd %d: %s",
					fd, *error_r);
			}
			*error_r = t_strdup_printf(
				"Failed to parse configuration: %s", error);
			event_unref(&event);
			return -1;
		}
	}

	master_service_settings_free(service->set);
	ret = master_service_settings_get(event,
			&master_service_setting_parser_info, 0,
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

struct master_settings_pool {
	struct pool pool;
	int refcount;

	pool_t parent_pool;
	struct master_settings_mmap *mmap;
};

static const char *pool_master_settings_get_name(pool_t pool)
{
	struct master_settings_pool *mpool =
		container_of(pool, struct master_settings_pool, pool);

	return pool_get_name(mpool->parent_pool);
}

static void pool_master_settings_ref(pool_t pool)
{
	struct master_settings_pool *mpool =
		container_of(pool, struct master_settings_pool, pool);

	i_assert(mpool->refcount > 0);
	mpool->refcount++;
}

static void pool_master_settings_unref(pool_t *pool)
{
	struct master_settings_pool *mpool =
		container_of(*pool, struct master_settings_pool, pool);

	i_assert(mpool->refcount > 0);
	*pool = NULL;
	if (--mpool->refcount > 0)
		return;

	master_settings_mmap_unref(&mpool->mmap);
	pool_unref(&mpool->parent_pool);
}

static void *pool_master_settings_malloc(pool_t pool, size_t size)
{
	struct master_settings_pool *mpool =
		container_of(pool, struct master_settings_pool, pool);

	return p_malloc(mpool->parent_pool, size);
}

static void pool_master_settings_free(pool_t pool, void *mem)
{
	struct master_settings_pool *mpool =
		container_of(pool, struct master_settings_pool, pool);

	p_free(mpool->parent_pool, mem);
}

static void *pool_master_settings_realloc(pool_t pool, void *mem,
					  size_t old_size, size_t new_size)
{
	struct master_settings_pool *mpool =
		container_of(pool, struct master_settings_pool, pool);

	return p_realloc(mpool->parent_pool, mem, old_size, new_size);
}

static void pool_master_settings_clear(pool_t pool ATTR_UNUSED)
{
	i_panic("pool_master_settings_clear() must not be called");
}

static size_t pool_master_settings_get_max_easy_alloc_size(pool_t pool)
{
	struct master_settings_pool *mpool =
		container_of(pool, struct master_settings_pool, pool);

	return p_get_max_easy_alloc_size(mpool->parent_pool);
}

static struct pool_vfuncs static_master_settings_pool_vfuncs = {
	pool_master_settings_get_name,

	pool_master_settings_ref,
	pool_master_settings_unref,

	pool_master_settings_malloc,
	pool_master_settings_free,

	pool_master_settings_realloc,

	pool_master_settings_clear,
	pool_master_settings_get_max_easy_alloc_size
};

static pool_t master_settings_pool_create(struct master_settings_mmap *mmap)
{
	struct master_settings_pool *mpool;
	pool_t parent_pool =
		pool_alloconly_create("master service settings", 256);

	mpool = p_new(parent_pool, struct master_settings_pool, 1);
	mpool->pool.v = &static_master_settings_pool_vfuncs;
	mpool->pool.alloconly_pool = TRUE;
	mpool->refcount = 1;
	mpool->parent_pool = parent_pool;
	mpool->mmap = mmap;
	if (mmap != NULL)
		master_settings_mmap_ref(mmap);
	return &mpool->pool;
}

static void
master_service_var_expand_init(struct event *event,
			       const struct var_expand_table **tab_r,
			       const struct var_expand_func_table **func_tab_r,
			       void **func_context_r)
{
	*tab_r = NULL;
	*func_tab_r = NULL;

	while (event != NULL) {
		master_service_settings_var_expand_t *callback =
			event_get_ptr(event, MASTER_SERVICE_VAR_EXPAND_CALLBACK);
		if (callback != NULL) {
			callback(event, tab_r, func_tab_r);
			break;
		}

		*tab_r = event_get_ptr(event, MASTER_SERVICE_VAR_EXPAND_TABLE);
		*func_tab_r = event_get_ptr(event, MASTER_SERVICE_VAR_EXPAND_FUNC_TABLE);
		if (*tab_r != NULL || *func_tab_r != NULL)
			break;
		event = event_get_parent(event);
	}
	if (*tab_r == NULL)
		*tab_r = t_new(struct var_expand_table, 1);
	*func_context_r = event == NULL ? NULL :
		event_get_ptr(event, MASTER_SERVICE_VAR_EXPAND_FUNC_CONTEXT);
}

static int master_service_set_cmp(const struct master_service_set *set1,
				  const struct master_service_set *set2)
{
	return set1->type - set2->type;
}

static int
master_service_set_get_value(struct setting_parser_context *parser,
			     const struct master_service_set *set,
			     const char **key_r, const char **value_r,
			     const char **error_r)
{
	const char *key = set->key;
	enum setting_type value_type;
	/* FIXME: Do this lookup only with set->append once plugin/ check is
	   no longer needed. */
	const void *old_value = settings_parse_get_value(parser, key, &value_type);
	if (old_value == NULL && !str_begins_with(key, "plugin/") &&
	    set->type == MASTER_SERVICE_SET_TYPE_USERDB) {
		/* FIXME: Setting is unknown in this parser. Since the parser
		   doesn't know all settings, we can't be sure if it's because
		   it should simply be ignored or because it's a plugin setting.
		   Just assume it's a plugin setting for now. This code will get
		   removed eventually once all plugin settings have been
		   converted away. */
		key = t_strconcat("plugin/", key, NULL);
		old_value = settings_parse_get_value(parser, key, &value_type);
	}
	if (!set->append || old_value == NULL) {
		*key_r = key;
		*value_r = set->value;
		return 1;
	}

	if (value_type != SET_STR) {
		*error_r = t_strdup_printf(
			"%s setting is not a string - can't use '+'", key);
		return -1;
	}
	const char *const *strp = old_value;
	*key_r = key;
	*value_r = t_strconcat(*strp, set->value, NULL);
	return 1;
}

static int
master_service_settings_instance_override(
	struct master_service_settings_instance *instance,
	struct setting_parser_context *parser,
	const char **error_r)
{
	ARRAY_TYPE(master_service_set) settings;

	t_array_init(&settings, 64);
	if (array_is_created(&instance->settings))
		array_append_array(&settings, &instance->settings);
	master_service_append_config_overrides(instance->service, &settings);
	array_sort(&settings, master_service_set_cmp);

	const struct master_service_set *set;
	array_foreach(&settings, set) {
		const char *key, *value;
		int ret = master_service_set_get_value(parser, set, &key,
						       &value, error_r);
		if (ret < 0)
			return -1;
		if (ret > 0 &&
		    settings_parse_keyvalue(parser, key, value) < 0) {
			*error_r = t_strdup_printf(
				"Failed to override configuration from %s: "
				"Invalid %s=%s: %s",
				master_service_set_type_names[set->type],
				key, value, settings_parser_get_error(parser));
			return -1;
		}
	}
	return 0;
}

#undef master_service_settings_instance_get
int master_service_settings_instance_get(struct event *event,
					 struct master_service_settings_instance *instance,
					 const struct setting_parser_info *info,
					 enum master_service_settings_get_flags flags,
					 const void **set_r, const char **error_r)
{
	struct master_service *service = instance->service;
	const char *error;
	int ret;

	i_assert(info->pool_offset1 != 0);

	event = event_create(event);
	if (event_find_field_recursive(event, "protocol") == NULL) {
		event_add_str(event, "protocol",
			      instance->service->set_protocol_name);
	}

	pool_t set_pool = master_settings_pool_create(master_service->config_mmap);
	struct setting_parser_context *parser =
		settings_parser_init(set_pool, info,
				     SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);

	if (service->config_mmap != NULL) {
		ret = master_service_settings_mmap_apply(service->config_mmap,
				event, parser, &error);
		if (ret < 0) {
			*error_r = t_strdup_printf(
				"Failed to parse configuration: %s", error);
			settings_parser_unref(&parser);
			pool_unref(&set_pool);
			event_unref(&event);
			return -1;
		}
	}

	/* if we change any settings afterwards, they're in expanded form.
	   especially all settings from userdb are already expanded. */
	settings_parse_set_expanded(parser, TRUE);

	T_BEGIN {
		ret = master_service_settings_instance_override(
			instance, parser, error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	if (ret < 0) {
		settings_parser_unref(&parser);
		pool_unref(&set_pool);
		event_unref(&event);
		return -1;
	}

	void *set = settings_parser_get_root_set(parser, info);

	pool_t *pool_p = PTR_OFFSET(set, info->pool_offset1 - 1);
	*pool_p = set_pool;

	/* settings are now referenced, but the parser is no longer needed */
	settings_parser_unref(&parser);

	if ((flags & MASTER_SERVICE_SETTINGS_GET_FLAG_NO_CHECK) == 0) {
		if (!settings_check(info, *pool_p, set, error_r)) {
			*error_r = t_strdup_printf("Invalid %s settings: %s",
						   info->module_name, *error_r);
			pool_unref(&set_pool);
			event_unref(&event);
			return -1;
		}
	}

	if ((flags & MASTER_SERVICE_SETTINGS_GET_FLAG_NO_EXPAND) != 0)
		ret = 1;
	else T_BEGIN {
		const struct var_expand_table *tab;
		const struct var_expand_func_table *func_tab;
		void *func_context;

		master_service_var_expand_init(event, &tab, &func_tab,
					       &func_context);
		ret = settings_var_expand_with_funcs(info, set, *pool_p, tab,
						     func_tab, func_context,
						     error_r);
	} T_END_PASS_STR_IF(ret <= 0, error_r);
	if (ret <= 0) {
		*error_r = t_strdup_printf(
			"Failed to expand %s setting variables: %s",
			info->module_name, *error_r);
		pool_unref(&set_pool);
		event_unref(&event);
		return -1;
	}

	*set_r = set;
	event_unref(&event);
	return 0;
}

#undef master_service_settings_get
int master_service_settings_get(struct event *event,
				const struct setting_parser_info *info,
				enum master_service_settings_get_flags flags,
				const void **set_r, const char **error_r)
{
	/* no instance-specific settings */
	struct master_service_settings_instance instance = {
		.service = master_service,
	};

	return master_service_settings_instance_get(event, &instance,
		info, flags, set_r, error_r);
}

const void *
master_service_settings_get_or_fatal(struct event *event,
				     const struct setting_parser_info *info)
{
	const void *set;
	const char *error;

	if (master_service_settings_get(event, info, 0, &set, &error) < 0)
		i_fatal("%s", error);
	return set;
}

int master_service_set(struct master_service_settings_instance *instance,
		       const char *key, const char *value,
		       enum master_service_set_type type,
		       const char **error_r ATTR_UNUSED)
{
	if (!array_is_created(&instance->settings))
		p_array_init(&instance->settings, instance->pool, 16);
	struct master_service_set *set =
		array_append_space(&instance->settings);
	set->type = type;
	size_t len = strlen(key);
	if (len > 0 && key[len-1] == '+') {
		/* key+=value */
		set->append = TRUE;
		set->key = p_strndup(instance->pool, key, len-1);
	} else {
		set->key = p_strdup(instance->pool, key);
	}
	set->value = p_strdup(instance->pool, value);
	return 1;
}

struct master_service_settings_instance *
master_service_settings_instance_new(struct master_service *service)
{
	pool_t pool = pool_alloconly_create("master service settings instance", 1024);
	struct master_service_settings_instance *instance =
		p_new(pool, struct master_service_settings_instance, 1);
	instance->pool = pool;
	instance->service = service;
	return instance;
}

struct master_service_settings_instance *
master_service_settings_instance_dup(const struct master_service_settings_instance *src)
{
	struct master_service_settings_instance *dest =
		master_service_settings_instance_new(src->service);
	if (!array_is_created(&src->settings))
		return dest;

	p_array_init(&dest->settings, dest->pool,
		     array_count(&src->settings) + 8);
	const struct master_service_set *src_set;
	array_foreach(&src->settings, src_set) {
		struct master_service_set *dest_set =
			array_append_space(&dest->settings);
		dest_set->type = src_set->type;
		dest_set->append = src_set->append;
		dest_set->key = p_strdup(dest->pool, src_set->key);
		dest_set->value = p_strdup(dest->pool, src_set->value);
	}
	return dest;
}

void master_service_settings_instance_free(
	struct master_service_settings_instance **_instance)
{
	struct master_service_settings_instance *instance = *_instance;

	*_instance = NULL;

	pool_unref(&instance->pool);
}
