/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "abspath.h"
#include "istream.h"
#include "write-full.h"
#include "str.h"
#include "eacces-error.h"
#include "env-util.h"
#include "execv-const.h"
#include "settings-parser.h"
#include "master-service-private.h"
#include "master-service-settings.h"

#include <stddef.h>
#include <stdlib.h>
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
	DEF(SET_STR, log_path),
	DEF(SET_STR, info_log_path),
	DEF(SET_STR, debug_log_path),
	DEF(SET_STR, log_timestamp),
	DEF(SET_STR, syslog_facility),
	DEF(SET_SIZE, config_cache_size),
	DEF(SET_BOOL, version_ignore),
	DEF(SET_BOOL, shutdown_clients),
	DEF(SET_BOOL, verbose_proctitle),

	SETTING_DEFINE_LIST_END
};

static const struct master_service_settings master_service_default_settings = {
	.log_path = "syslog",
	.info_log_path = "",
	.debug_log_path = "",
	.log_timestamp = DEFAULT_FAILURE_STAMP_FORMAT,
	.syslog_facility = "mail",
	.config_cache_size = 1024*1024,
	.version_ignore = FALSE,
	.shutdown_clients = TRUE,
	.verbose_proctitle = FALSE
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
static bool
master_service_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			      const char **error_r ATTR_UNUSED)
{
	struct master_service_settings *set = _set;

	if (*set->log_path == '\0') {
		/* default to syslog logging */
		set->log_path = "syslog";
	}
	return TRUE;
}
/* </settings checks> */

static void ATTR_NORETURN
master_service_exec_config(struct master_service *service,
			   const struct master_service_settings_input *input)
{
	const char **conf_argv, *binary_path = service->argv[0];
	const char *home = NULL, *user = NULL;
	unsigned int i, argv_max_count;

	(void)t_binary_abspath(&binary_path);

	if (!service->keep_environment && !input->preserve_environment) {
		if (input->preserve_home)
			home = getenv("HOME");
		if (input->preserve_user)
			user = getenv("USER");
		master_service_env_clean();
		if (home != NULL)
			env_put(t_strconcat("HOME=", home, NULL));
		if (user != NULL)
			env_put(t_strconcat("USER=", user, NULL));
	}
	if (input->use_sysexits)
		env_put("USE_SYSEXITS=1");

	/* @UNSAFE */
	i = 0;
	argv_max_count = 9 + (service->argc + 1) + 1;
	conf_argv = t_new(const char *, argv_max_count);
	conf_argv[i++] = DOVECOT_CONFIG_BIN_PATH;
	conf_argv[i++] = "-f";
	conf_argv[i++] = t_strconcat("service=", service->name, NULL);
	conf_argv[i++] = "-c";
	conf_argv[i++] = service->config_path;
	if (input->module != NULL) {
		conf_argv[i++] = "-m";
		conf_argv[i++] = input->module;
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

	if (input->never_exec)
		return;

	path = input->config_path != NULL ? input->config_path :
		master_service_get_config_path(service);
	if (stat(path, &st) == 0 &&
	    !S_ISSOCK(st.st_mode) && !S_ISFIFO(st.st_mode)) {
		/* it's a file, not a socket/pipe */
		master_service_exec_config(service, input);
	}
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

	if (service->config_fd != -1 && input->config_path == NULL) {
		/* use the already opened config socket */
		fd = service->config_fd;
		service->config_fd = -1;
		return fd;
	}

	if (service->config_path_is_default && input->config_path == NULL) {
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
config_build_request(string_t *str,
		     const struct master_service_settings_input *input)
{
	str_append(str, "REQ");
	if (input->module != NULL)
		str_printfa(str, "\tmodule=%s", input->module);
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
config_send_request(const struct master_service_settings_input *input,
		    int fd, const char *path, const char **error_r)
{
	int ret;

	T_BEGIN {
		string_t *str;

		str = t_str_new(128);
		str_append(str, CONFIG_HANDSHAKE);
		config_build_request(str, input);
		ret = write_full(fd, str_data(str), str_len(str));
	} T_END;
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
		settings_parse_set_key_expandeded(parser, service->set_pool,
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
			t_strdup_printf("read(%s) failed: %m", path) :
			t_strdup_printf("read(%s) failed: EOF", path);
		return -1;
	}

	T_BEGIN {
		const char *const *arg = t_strsplit(line, "\t");
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
			else if (strncmp(*arg, "service=", 8) == 0) {
				const char *name = p_strdup(pool, *arg + 8);
				array_append(&services, &name, 1);
			 }
		}
		if (input->service == NULL) {
			(void)array_append_space(&services);
			output_r->specific_services = array_idx(&services, 0);
		}
	} T_END;
	return 0;
}

int master_service_settings_read(struct master_service *service,
				 const struct master_service_settings_input *input,
				 struct master_service_settings_output *output_r,
				 const char **error_r)
{
	ARRAY_DEFINE(all_roots, const struct setting_parser_info *);
	const struct setting_parser_info *tmp_root;
	struct setting_parser_context *parser;
	struct istream *istream;
	const char *path = NULL, *error;
	void **sets;
	unsigned int i;
	int ret, fd = -1;
	time_t now, timeout;

	memset(output_r, 0, sizeof(*output_r));

	if (getenv("DOVECONF_ENV") == NULL &&
	    (service->flags & MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS) == 0) {
		fd = master_service_open_config(service, input, &path, error_r);
		if (fd == -1)
			return -1;

		if (config_send_request(input, fd, path, error_r) < 0) {
			(void)close(fd);
			config_exec_fallback(service, input);
			return -1;
		}
	}

	if (service->set_pool != NULL) {
		if (service->set_parser != NULL)
			settings_parser_deinit(&service->set_parser);
		p_clear(service->set_pool);
	} else {
		service->set_pool =
			pool_alloconly_create("master service settings", 8192);
	}

	p_array_init(&all_roots, service->set_pool, 8);
	tmp_root = &master_service_setting_parser_info;
	array_append(&all_roots, &tmp_root, 1);
	if (input->roots != NULL) {
		for (i = 0; input->roots[i] != NULL; i++)
			array_append(&all_roots, &input->roots[i], 1);
	}

	parser = settings_parser_init_list(service->set_pool,
			array_idx(&all_roots, 0), array_count(&all_roots),
			SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);

	if (fd != -1) {
		istream = i_stream_create_fd(fd, (size_t)-1, FALSE);
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
					*error_r = settings_parser_get_error(parser);
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
			(void)close(fd);
			config_exec_fallback(service, input);
			return -1;
		}

		if ((service->flags & MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN) != 0 &&
		    service->config_fd == -1 && input->config_path == NULL)
			service->config_fd = fd;
		else
			(void)close(fd);
	}

	if (fd == -1 || service->keep_environment) {
		if (settings_parse_environ(parser) < 0) {
			*error_r = settings_parser_get_error(parser);
			return -1;
		}
	}

	if (array_is_created(&service->config_overrides)) {
		if (master_service_apply_config_overrides(service, parser,
							  error_r) < 0)
			return -1;
	}

	if (!settings_parser_check(parser, service->set_pool, &error)) {
		*error_r = t_strdup_printf("Invalid settings: %s", error);
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

	memset(&input, 0, sizeof(input));
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
	return settings_parser_get_list(service->set_parser) + 1;
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
