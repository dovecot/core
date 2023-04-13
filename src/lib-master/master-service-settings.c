/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "event-filter.h"
#include "path-util.h"
#include "mmap-util.h"
#include "fdpass.h"
#include "write-full.h"
#include "hash.h"
#include "llist.h"
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

struct settings_mmap_filter {
	struct event_filter *filter;
	bool empty_filter;

	const char *error; /* if non-NULL, accessing the block must fail */
	size_t start_offset, end_offset;
};

struct settings_mmap_block {
	const char *name;

	const char *error; /* if non-NULL, accessing the block must fail */
	size_t base_start_offset, base_end_offset;
	ARRAY(struct settings_mmap_filter) filters;
};

struct settings_mmap {
	int refcount;
	struct master_service *service;

	void *mmap_base;
	size_t mmap_size;

	HASH_TABLE(const char *, struct settings_mmap_block *) blocks;
};

struct master_service_set {
	int type;
	bool append;
	const char *key, *value;
};
ARRAY_DEFINE_TYPE(master_service_set, struct master_service_set);

struct settings_instance {
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
				       ARRAY_TYPE(master_service_set) *settings,
				       pool_t set_pool)
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
		set->key = p_strdup(set_pool, key);
		set->value = p_strdup(set_pool, value);
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
	if (array_lsearch(protocols, &protocol, i_strcmp_p) == NULL)
		array_push_back(protocols, &protocol);
}

static int
settings_block_read_size(struct settings_mmap *mmap,
			 size_t *offset, size_t end_offset,
			 const char *name, uint64_t *size_r,
			 const char **error_r)
{
	if (*offset + sizeof(*size_r) > end_offset) {
		*error_r = t_strdup_printf(
			"Area too small when reading size of '%s' "
			"(offset=%zu, end_offset=%zu, file_size=%zu)", name,
			*offset, end_offset, mmap->mmap_size);
		return -1;
	}
	*size_r = be64_to_cpu_unaligned(CONST_PTR_OFFSET(mmap->mmap_base, *offset));
	if (*size_r > end_offset - *offset - sizeof(*size_r)) {
		*error_r = t_strdup_printf(
			"'%s' points outside area "
			"(offset=%zu, size=%"PRIu64", end_offset=%zu, file_size=%zu)",
			name, *offset, *size_r, end_offset,
			mmap->mmap_size);
		return -1;
	}
	*offset += sizeof(*size_r);
	return 0;
}

static int
settings_block_read_str(struct settings_mmap *mmap,
			uoff_t *offset, uoff_t end_offset, const char *name,
			const char **str_r, const char **error_r)
{
	*str_r = (const char *)mmap->mmap_base + *offset;
	*offset += strlen(*str_r) + 1;
	if (*offset > end_offset) {
		*error_r = t_strdup_printf("'%s' points outside area "
			"(offset=%zu, end_offset=%zu, file_size=%zu)",
			name, *offset, end_offset, mmap->mmap_size);
		return -1;
	}
	return 0;
}

static int
settings_block_read(struct settings_mmap *mmap, uoff_t *_offset,
		    ARRAY_TYPE(const_string) *protocols, const char **error_r)
{
	uoff_t offset = *_offset;
	size_t block_size_offset = offset;
	const char *error;

	/* <block size> */
	uint64_t block_size;
	if (settings_block_read_size(mmap, &offset, mmap->mmap_size,
				     "block size", &block_size, error_r) < 0)
		return -1;
	size_t block_end_offset = offset + block_size;

	/* Verify that block ends with NUL. This way we can safely use strlen()
	   later on and we know it won't read past the mmaped memory area and
	   cause a crash. The NUL is either from the last settings value or
	   from the last error string. */
	if (((const char *)mmap->mmap_base)[block_end_offset-1] != '\0') {
		*error_r = t_strdup_printf(
			"Settings block doesn't end with NUL at offset %zu",
			block_end_offset-1);
		return -1;
	}

	/* <block name> */
	const char *block_name;
	if (settings_block_read_str(mmap, &offset, block_end_offset,
				    "block name", &block_name, error_r) < 0)
		return -1;

	struct settings_mmap_block *block =
		hash_table_lookup(mmap->blocks, block_name);
	if (block != NULL) {
		*error_r = t_strdup_printf(
			"Duplicate block name '%s' (offset=%zu)",
			block_name, block_size_offset);
		return -1;
	}
	block = i_new(struct settings_mmap_block, 1);
	block->name = block_name;
	hash_table_insert(mmap->blocks, block->name, block);

	/* <base settings size> */
	uint64_t base_settings_size;
	if (settings_block_read_size(mmap, &offset, block_end_offset,
				     "base settings size", &base_settings_size,
				     error_r) < 0)
		return -1;
	block->base_end_offset = offset + base_settings_size;

	/* <base settings error string> */
	if (settings_block_read_str(mmap, &offset,
				    block->base_end_offset,
				    "base settings error", &error,
				    error_r) < 0)
		return -1;
	if (error[0] != '\0')
		block->error = error;
	block->base_start_offset = offset;

	/* skip over the key-value pairs */
	offset = block->base_end_offset;

	/* filters */
	while (offset < block_end_offset) {
		/* <filter settings size> */
		uint64_t filter_settings_size;
		if (settings_block_read_size(mmap, &offset,
				block_end_offset, "filter settings size",
				&filter_settings_size, error_r) < 0)
			return -1;
		uint64_t filter_end_offset = offset + filter_settings_size;

		/* <filter string> */
		const char *filter_string;
		if (settings_block_read_str(mmap, &offset,
					    filter_end_offset, "filter string",
					    &filter_string, error_r) < 0)
			return -1;

		/* <filter settings error string> */
		const char *filter_error;
		if (settings_block_read_str(mmap, &offset,
					    filter_end_offset,
					    "filter settings error",
					    &filter_error, error_r) < 0)
			return -1;

		if (!array_is_created(&block->filters))
			i_array_init(&block->filters, 4);

		struct settings_mmap_filter *config_filter =
			array_append_space(&block->filters);
		config_filter->filter = event_filter_create();
		config_filter->empty_filter = filter_string[0] == '\0';
		config_filter->error = filter_error[0] == '\0' ?
			NULL : filter_error;
		config_filter->start_offset = offset;
		config_filter->end_offset = filter_end_offset;

		if (event_filter_parse(filter_string,
				       config_filter->filter, &error) < 0) {
			*error_r = t_strdup_printf(
				"Received invalid filter '%s': %s (offset=%zu)",
				filter_string, error, offset);
			return -1;
		}
		filter_string_parse_protocol(filter_string, protocols);

		/* skip over the key-value pairs */
		offset = filter_end_offset;
	}
	i_assert(offset == block_end_offset);
	*_offset = offset;
	return 0;
}

static void settings_mmap_free_blocks(struct settings_mmap *mmap)
{
	struct hash_iterate_context *iter =
		hash_table_iterate_init(mmap->blocks);
	const char *name;
	struct settings_mmap_block *block;

	while (hash_table_iterate(iter, mmap->blocks, &name, &block)) {
		if (array_is_created(&block->filters)) {
			struct settings_mmap_filter *config_filter;
			array_foreach_modifiable(&block->filters, config_filter)
				event_filter_unref(&config_filter->filter);
			array_free(&block->filters);
		}
		i_free(block);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_clear(mmap->blocks, FALSE);
}

static int
settings_mmap_parse(struct settings_mmap *mmap,
		    struct master_service_settings_output *output_r,
		    const char **error_r)
{
	/*
	   See ../config/config-dump-full.c for the binary config file format
	   description.

	   Settings are read until the blob size is reached. There is no
	   padding/alignment. */
	const unsigned char *mmap_base = mmap->mmap_base;
	size_t mmap_size = mmap->mmap_size;
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

	/* <settings full size> */
	settings_mmap_free_blocks(mmap);

	size_t full_size_offset = eol - mmap_base + 1;
	uint64_t settings_full_size =
		be64_to_cpu_unaligned(mmap_base + full_size_offset);
	if (full_size_offset + sizeof(settings_full_size) +
	    settings_full_size != mmap_size) {
		*error_r = t_strdup_printf("Full size mismatch: "
			"Expected %zu + %zu + %"PRIu64", but file size is %zu",
			full_size_offset, sizeof(settings_full_size),
			settings_full_size, mmap_size);
		return -1;
	}

	uoff_t offset = full_size_offset + sizeof(settings_full_size);
	do {
		if (settings_block_read(mmap, &offset,
					&protocols, error_r) < 0)
			return -1;
	} while (offset < mmap_size);

	if (array_count(&protocols) > 0) {
		array_append_zero(&protocols);
		output_r->specific_services = array_front(&protocols);
	}
	return 0;
}

static int
settings_mmap_apply_blob(struct settings_mmap *mmap,
			 struct setting_parser_context *parser,
			 size_t start_offset, size_t end_offset,
			 const char **error_r)
{
	size_t offset = start_offset;

	/* list of settings: key, value, ... */
	while (offset < end_offset) {
		/* We already checked that settings blob ends with NUL, so
		   strlen() can be used safely. */
		const char *key = (const char *)mmap->mmap_base + offset;
		offset += strlen(key)+1;
		if (offset >= end_offset) {
			/* if offset==end_offset, the value is missing. */
			*error_r = t_strdup_printf(
				"Settings key/value points outside blob "
				"(offset=%zu, end_offset=%zu, file_size=%zu)",
				offset, end_offset, mmap->mmap_size);
			return -1;
		}
		const char *value = (const char *)mmap->mmap_base + offset;
		offset += strlen(value)+1;
		if (offset > end_offset) {
			*error_r = t_strdup_printf(
				"Settings value points outside blob "
				"(offset=%zu, end_offset=%zu, file_size=%zu)",
				offset, end_offset, mmap->mmap_size);
			return -1;
		}
		int ret;
		T_BEGIN {
			/* value points to mmap()ed memory, which is kept
			   referenced by the set_pool for the life time of the
			   settings struct. */
			ret = settings_parse_keyvalue_nodup(parser, key, value);
			if (ret < 0)
				*error_r = t_strdup(settings_parser_get_error(parser));
		} T_END_PASS_STR_IF(ret < 0, error_r);
		if (ret < 0)
			return -1;
	}
	return 0;
}

static int
settings_mmap_apply(struct settings_mmap *mmap, struct event *event,
		    struct setting_parser_context *parser,
		    const struct setting_parser_info *info,
		    const char **error_r)
{
	struct settings_mmap_block *block =
		hash_table_lookup(mmap->blocks, info->name);
	if (block == NULL) {
		*error_r = t_strdup_printf(
			"BUG: Configuration has no settings struct named '%s'",
			info->name);
		return -1;
	}
	if (block->error != NULL) {
		*error_r = block->error;
		return -1;
	}

	if (settings_mmap_apply_blob(mmap, parser,
				     block->base_start_offset,
				     block->base_end_offset, error_r) < 0)
		return -1;

	const struct failure_context failure_ctx = {
		.type = LOG_TYPE_DEBUG,
	};

	if (!array_is_created(&block->filters))
		return 0;

	const struct settings_mmap_filter *config_filter;
	array_foreach(&block->filters, config_filter) {
		if (config_filter->empty_filter ||
		    event_filter_match(config_filter->filter, event,
				       &failure_ctx)) {
			if (config_filter->error != NULL) {
				*error_r = config_filter->error;
				return -1;
			}
			if (settings_mmap_apply_blob(mmap, parser,
					config_filter->start_offset,
					config_filter->end_offset,
					error_r) < 0)
				return -1;
		}
	}
	return 0;

}

void settings_mmap_ref(struct settings_mmap *mmap)
{
	i_assert(mmap->refcount > 0);

	mmap->refcount++;
}

void settings_mmap_unref(struct settings_mmap **_mmap)
{
	struct settings_mmap *mmap = *_mmap;
	if (mmap == NULL)
		return;
	i_assert(mmap->refcount > 0);

	*_mmap = NULL;
	if (--mmap->refcount > 0)
		return;

	settings_mmap_free_blocks(mmap);
	hash_table_destroy(&mmap->blocks);

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

	if (input->config_fd > 0) {
		/* unit test */
		fd = input->config_fd;
		path = t_strdup_printf("<input fd %d>", fd);
	} else if (service->config_mmap != NULL && !input->reload_config) {
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
		struct settings_mmap *mmap;
		settings_mmap_unref(&service->config_mmap);
		mmap = i_new(struct settings_mmap, 1);
		mmap->refcount = 1;
		mmap->service = service;
		mmap->mmap_base = mmap_ro_file(fd, &mmap->mmap_size);
		if (mmap->mmap_base == MAP_FAILED)
			i_fatal("Failed to read config: mmap(%s) failed: %m", path);
		if (mmap->mmap_size == 0)
			i_fatal("Failed to read config: %s file size is empty", path);

		service->config_mmap = mmap;
		hash_table_create(&mmap->blocks, default_pool, 0,
				  str_hash, strcmp);

		if (input->return_config_fd)
			output_r->config_fd = fd;
		else
			i_close_fd(&fd);
		env_remove(DOVECOT_CONFIG_FD_ENV);
	}

	/* Remember the protocol for following settings instance lookups */
	i_free(service->set_protocol_name);
	service->set_protocol_name = i_strdup(input->protocol);

	/* Create event for matching config filters */
	struct event *event = event_create(NULL);
	event_add_str(event, "protocol", input->protocol != NULL ?
		      input->protocol : service->name);

	/* config_mmap is NULL only if MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS
	   is used */
	if (service->config_mmap != NULL) {
		ret = settings_mmap_parse(service->config_mmap,
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

	struct master_settings_pool *prev, *next;

	const char *source_filename;
	unsigned int source_linenum;

	pool_t extra_pool_ref;
	pool_t parent_pool;
	struct settings_mmap *mmap;
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

	DLLIST_REMOVE(&master_service->settings_pools, mpool);

	settings_mmap_unref(&mpool->mmap);
	pool_unref(&mpool->extra_pool_ref);
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

static struct master_settings_pool *
master_settings_pool_create(struct settings_mmap *mmap,
			    const char *source_filename,
			    unsigned int source_linenum)
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
	mpool->source_filename = source_filename;
	mpool->source_linenum = source_linenum;
	if (mmap != NULL)
		settings_mmap_ref(mmap);

	DLLIST_PREPEND(&master_service->settings_pools, mpool);
	return mpool;
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
settings_instance_override(struct settings_instance *instance,
			   struct setting_parser_context *parser,
			   struct master_settings_pool *mpool,
			   const char **error_r)
{
	ARRAY_TYPE(master_service_set) settings;

	t_array_init(&settings, 64);
	if (array_is_created(&instance->settings))
		array_append_array(&settings, &instance->settings);
	master_service_append_config_overrides(instance->service, &settings,
					       &mpool->pool);
	array_sort(&settings, master_service_set_cmp);

	const struct master_service_set *set;
	array_foreach(&settings, set) {
		const char *key, *value;
		int ret = master_service_set_get_value(parser, set, &key,
						       &value, error_r);
		if (ret < 0)
			return -1;
		if (ret == 0)
			continue;

		if (value != set->value)
			ret = settings_parse_keyvalue(parser, key, value);
		else {
			/* Add explicit reference to instance->pool, which is
			   kept by the settings struct's pool. This allows
			   settings to survive even if the instance is freed.

			   If there is no instance pool, it means there are
			   only CLI_PARAM settings, which are allocated from
			   FIXME: should figure out some efficient way how to
			   store them. */
			if (mpool->extra_pool_ref != NULL)
				i_assert(mpool->extra_pool_ref == instance->pool);
			else if (instance->pool != NULL) {
				mpool->extra_pool_ref = instance->pool;
				pool_ref(mpool->extra_pool_ref);
			}
			ret = settings_parse_keyvalue_nodup(parser, key, value);
		}
		if (ret < 0) {
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

static int
settings_instance_get(struct event *event,
		      struct settings_instance *instance,
		      const struct setting_parser_info *info,
		      enum master_service_settings_get_flags flags,
		      const char *source_filename,
		      unsigned int source_linenum,
		      const void **set_r, const char **error_r)
{
	struct master_service *service = instance->service;
	const char *error;
	int ret;

	i_assert(info->pool_offset1 != 0);

	event = event_create(event);
	if (event_find_field_recursive(event, "protocol") == NULL) {
		event_add_str(event, "protocol",
			      instance->service->set_protocol_name != NULL ?
			      instance->service->set_protocol_name :
			      service->name);
	}

	struct master_settings_pool *mpool =
		master_settings_pool_create(master_service->config_mmap,
					    source_filename, source_linenum);
	pool_t set_pool = &mpool->pool;
	struct setting_parser_context *parser =
		settings_parser_init(set_pool, info,
				     SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);

	if (service->config_mmap != NULL) {
		ret = settings_mmap_apply(service->config_mmap,
				event, parser, info, &error);
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
		ret = settings_instance_override(instance, parser, mpool,
						 error_r);
	} T_END_PASS_STR_IF(ret < 0, error_r);
	if (ret < 0) {
		settings_parser_unref(&parser);
		pool_unref(&set_pool);
		event_unref(&event);
		return -1;
	}

	void *set = settings_parser_get_set(parser);

	pool_t *pool_p = PTR_OFFSET(set, info->pool_offset1 - 1);
	*pool_p = set_pool;

	/* settings are now referenced, but the parser is no longer needed */
	settings_parser_unref(&parser);

	if ((flags & MASTER_SERVICE_SETTINGS_GET_FLAG_NO_CHECK) == 0) {
		if (!settings_check(info, *pool_p, set, error_r)) {
			*error_r = t_strdup_printf("Invalid %s settings: %s",
						   info->name, *error_r);
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
			info->name, *error_r);
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
				const char *source_filename,
				unsigned int source_linenum,
				const void **set_r, const char **error_r)
{
	struct settings_instance *instance = NULL;
	struct event *scan_event = event;

	while (scan_event != NULL) {
		instance = event_get_ptr(scan_event,
					 MASTER_SERVICE_SETTINGS_INSTANCE);
		if (instance != NULL)
			break;
		scan_event = event_get_parent(scan_event);
	}

	/* no instance-specific settings */
	struct settings_instance empty_instance = {
		.service = master_service,
	};
	if (instance == NULL)
		instance = &empty_instance;

	return settings_instance_get(event, instance,
		info, flags, source_filename, source_linenum, set_r, error_r);
}

#undef master_service_settings_get_or_fatal
const void *
master_service_settings_get_or_fatal(struct event *event,
				     const struct setting_parser_info *info,
				     const char *source_filename,
				     unsigned int source_linenum)
{
	const void *set;
	const char *error;

	if (master_service_settings_get(event, info, 0, source_filename,
					source_linenum, &set, &error) < 0)
		i_fatal("%s", error);
	return set;
}

void master_service_set(struct settings_instance *instance,
			const char *key, const char *value,
			enum master_service_set_type type)
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
}

struct settings_instance *
settings_instance_new(struct master_service *service)
{
	pool_t pool = pool_alloconly_create("settings instance", 1024);
	struct settings_instance *instance =
		p_new(pool, struct settings_instance, 1);
	instance->pool = pool;
	instance->service = service;
	return instance;
}

struct settings_instance *
settings_instance_dup(const struct settings_instance *src)
{
	struct settings_instance *dest =
		settings_instance_new(src->service);
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

void settings_instance_free(struct settings_instance **_instance)
{
	struct settings_instance *instance = *_instance;

	*_instance = NULL;

	pool_unref(&instance->pool);
}

void master_service_settings_deinit(struct master_service *service)
{
	struct master_settings_pool *mpool;

	for (mpool = service->settings_pools; mpool != NULL; mpool = mpool->next) {
		e_warning(service->event, "Leaked settings: %s:%u",
			  mpool->source_filename, mpool->source_linenum);
	}
}
