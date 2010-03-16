/* Copyright (c) 2005-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "abspath.h"
#include "istream.h"
#include "write-full.h"
#include "str.h"
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

static const struct setting_define master_service_setting_defines[] = {
	DEF(SET_STR, log_path),
	DEF(SET_STR, info_log_path),
	DEF(SET_STR, debug_log_path),
	DEF(SET_STR, log_timestamp),
	DEF(SET_STR, syslog_facility),
	DEF(SET_SIZE, config_cache_size),
	DEF(SET_BOOL, version_ignore),
	DEF(SET_BOOL, shutdown_clients),

	SETTING_DEFINE_LIST_END
};

static const struct master_service_settings master_service_default_settings = {
	.log_path = "",
	.info_log_path = "",
	.debug_log_path = "",
	.log_timestamp = DEFAULT_FAILURE_STAMP_FORMAT,
	.syslog_facility = "mail",
	.config_cache_size = 1024*1024,
	.version_ignore = FALSE,
	.shutdown_clients = TRUE
};

const struct setting_parser_info master_service_setting_parser_info = {
	.module_name = "master",
	.defines = master_service_setting_defines,
	.defaults = &master_service_default_settings,

	.type_offset = (size_t)-1,
	.struct_size = sizeof(struct master_service_settings),

	.parent_offset = (size_t)-1
};

static void ATTR_NORETURN
master_service_exec_config(struct master_service *service, bool preserve_home)
{
	const char **conf_argv, *path, *const *paths, *binary_path;

	binary_path = service->argv[0];
	if (*service->argv[0] == '/') {
		/* already have the path */
	} else if (strchr(service->argv[0], '/') != NULL) {
		/* relative to current directory */
		binary_path = t_abspath(service->argv[0]);
	} else if ((path = getenv("PATH")) != NULL) {
		/* we have to find our executable from path */
		paths = t_strsplit(path, ":");
		for (; *paths != NULL; paths++) {
			path = t_strconcat(*paths, "/", binary_path, NULL);
			if (access(path, X_OK) == 0) {
				binary_path = path;
				break;
			}
		}
	}

	if (!service->keep_environment)
		master_service_env_clean(preserve_home);

	/* @UNSAFE */
	conf_argv = t_new(const char *, 6 + (service->argc + 1) + 1);
	conf_argv[0] = DOVECOT_CONFIG_BIN_PATH;
	conf_argv[1] = "-f";
	conf_argv[2] = t_strconcat("service=", service->name, NULL);
	conf_argv[3] = "-c";
	conf_argv[4] = service->config_path;
	conf_argv[5] = "-e";
	conf_argv[6] = binary_path;
	memcpy(conf_argv+7, service->argv + 1,
	       (service->argc) * sizeof(conf_argv[0]));
	execv(conf_argv[0], (char **)conf_argv);
	i_fatal("execv(%s) failed: %m", conf_argv[0]);
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
		master_service_exec_config(service, input->preserve_home);
	}
}

static int
master_service_open_config(struct master_service *service,
			   const struct master_service_settings_input *input,
			   const char **path_r, const char **error_r,
			   bool *standalone_config_from_socket_r)
{
	const char *path;
	int fd;

	*path_r = path = input->config_path != NULL ? input->config_path :
		master_service_get_config_path(service);
	*standalone_config_from_socket_r = FALSE;

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
			*standalone_config_from_socket_r = TRUE;
			net_set_nonblock(fd, FALSE);
			return fd;
		}
		/* fallback to executing doveconf */
	}

	fd = net_connect_unix_with_retries(path, 1000);
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
	if (input->local_host != NULL)
		str_printfa(str, "\tlhost=%s", input->local_host);
	if (input->remote_host != NULL)
		str_printfa(str, "\tlhost=%s", input->remote_host);
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
config_read_reply_header(struct istream *input, const char *path,
			 struct master_service_settings_output *output_r,
			 const char **error_r)
{
	const char *line;
	ssize_t ret;

	while ((ret = i_stream_read(input)) > 0) {
		line = i_stream_next_line(input);
		if (line != NULL)
			break;
	}
	if (ret <= 0) {
		if (ret == 0)
			return 1;
		*error_r = input->stream_errno != 0 ?
			t_strdup_printf("read(%s) failed: %m", path) :
			t_strdup_printf("read(%s) failed: EOF", path);
		return -1;
	}

	T_BEGIN {
		const char *const *arg = t_strsplit(line, "\t");

		for (; *arg != NULL; arg++) {
			if (strcmp(*arg, "service-uses-local") == 0)
				output_r->service_uses_local = TRUE;
			else if (strcmp(*arg, "service-uses-remote") == 0)
				output_r->service_uses_remote = TRUE;
			if (strcmp(*arg, "used-local") == 0)
				output_r->used_local = TRUE;
			else if (strcmp(*arg, "used-remote") == 0)
				output_r->used_remote = TRUE;
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
	const char *path = NULL, *error, *env, *const *keys;
	void **sets;
	unsigned int i;
	int ret, fd = -1;
	time_t now, timeout;
	bool config_socket = FALSE, standalone_config_from_socket = FALSE;

	memset(output_r, 0, sizeof(*output_r));

	if (getenv("DOVECONF_ENV") == NULL &&
	    (service->flags & MASTER_SERVICE_FLAG_NO_CONFIG_SETTINGS) == 0) {
		fd = master_service_open_config(service, input, &path, error_r,
						&standalone_config_from_socket);
		if (fd == -1)
			return -1;

		if (config_send_request(input, fd, path, error_r) < 0) {
			(void)close(fd);
			config_exec_fallback(service, input);
			return -1;
		}
		config_socket = TRUE;
	}

	if (service->set_pool != NULL) {
		if (service->set_parser != NULL)
			settings_parser_deinit(&service->set_parser);
		p_clear(service->set_pool);
	} else {
		service->set_pool =
			pool_alloconly_create("master service settings", 8192);
	}

	if (input->dyn_parsers != NULL) {
		settings_parser_info_update(service->set_pool,
					    input->dyn_parsers_parent,
					    input->dyn_parsers);
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
			ret = !config_socket ? 0 :
				config_read_reply_header(istream, path,
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
	}

	if ((service->flags & MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN) != 0 &&
	    service->config_fd == -1 && input->config_path == NULL)
		service->config_fd = fd;
	else if (fd != -1)
		(void)close(fd);

	if ((service->flags & MASTER_SERVICE_FLAG_NO_ENV_SETTINGS) == 0 &&
	    !standalone_config_from_socket) {
		/* let environment override settings. especially useful for the
		   settings from userdb. */
		if (settings_parse_environ(parser) < 0) {
			*error_r = settings_parser_get_error(parser);
			return -1;
		}
		env = getenv("VARS_EXPANDED");
		if (env != NULL) T_BEGIN {
			keys = t_strsplit(env, " ");
			settings_parse_set_keys_expandeded(parser,
							   service->set_pool,
							   keys);
		} T_END;
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

int master_service_set(struct master_service *service, const char *line)
{
	return settings_parse_line(service->set_parser, line);
}
