/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings-parser.h"
#include "master-service-private.h"
#include "master-service-settings.h"

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#define DOVECOT_CONFIG_BIN_PATH BINDIR"/doveconf"

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct master_service_settings, name), NULL }

static struct setting_define master_service_setting_defines[] = {
	DEF(SET_STR, log_path),
	DEF(SET_STR, info_log_path),
	DEF(SET_STR, log_timestamp),
	DEF(SET_STR, syslog_facility),
	DEF(SET_BOOL, version_ignore),

	SETTING_DEFINE_LIST_END
};

static struct master_service_settings master_service_default_settings = {
	MEMBER(log_path) "",
	MEMBER(info_log_path) "",
	MEMBER(log_timestamp) DEFAULT_FAILURE_STAMP_FORMAT,
	MEMBER(syslog_facility) "mail",
	MEMBER(version_ignore) FALSE
};

struct setting_parser_info master_service_setting_parser_info = {
	MEMBER(defines) master_service_setting_defines,
	MEMBER(defaults) &master_service_default_settings,

	MEMBER(parent) NULL,
	MEMBER(dynamic_parsers) NULL,

	MEMBER(parent_offset) (size_t)-1,
	MEMBER(type_offset) (size_t)-1,
	MEMBER(struct_size) sizeof(struct master_service_settings)
};

static void ATTR_NORETURN
master_service_exec_config(struct master_service *service, bool preserve_home)
{
	const char **conf_argv;

	if (!service->keep_environment)
		master_service_env_clean(preserve_home);

	/* @UNSAFE */
	conf_argv = t_new(const char *, 6 + (service->argc + 1) + 1);
	conf_argv[0] = DOVECOT_CONFIG_BIN_PATH;
	conf_argv[1] = "-s";
	conf_argv[2] = service->name;
	conf_argv[3] = "-c";
	conf_argv[4] = service->config_path;
	conf_argv[5] = "--exec";
	memcpy(conf_argv+6, service->argv,
	       (service->argc+1) * sizeof(conf_argv[0]));
	execv(conf_argv[0], (char **)conf_argv);
	i_fatal("execv(%s) failed: %m", conf_argv[0]);
}

int master_service_settings_read(struct master_service *service,
				 const struct setting_parser_info *roots[],
				 const struct dynamic_settings_parser *dyn_parsers,
				 bool preserve_home, const char **error_r)
{
	ARRAY_DEFINE(all_roots, const struct setting_parser_info *);
	const struct setting_parser_info *tmp_root;
	struct setting_parser_context *parser;
	const char *error;
	void **sets;
	unsigned int i;

	if (getenv("DOVECONF_ENV") == NULL)
		master_service_exec_config(service, preserve_home);

	if (service->set_pool != NULL)
		p_clear(service->set_pool);
	else {
		service->set_pool =
			pool_alloconly_create("master service settings", 4096);
	}

	if (dyn_parsers != NULL)
		settings_parser_info_update(service->set_pool, dyn_parsers);

	p_array_init(&all_roots, service->set_pool, 8);
	tmp_root = &master_service_setting_parser_info;
	array_append(&all_roots, &tmp_root, 1);
	for (i = 0; roots[i] != NULL; i++)
		array_append(&all_roots, &roots[i], 1);

	parser = settings_parser_init_list(service->set_pool,
			array_idx(&all_roots, 0), array_count(&all_roots),
			SETTINGS_PARSER_FLAG_IGNORE_UNKNOWN_KEYS);

	if (settings_parse_environ(parser) < 0) {
		*error_r = settings_parser_get_error(parser);
		return -1;
	}

	if (settings_parser_check(parser, service->set_pool, &error) < 0) {
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

	/* if we change any settings afterwards, they're in expanded form.
	   especially all settings from userdb are already expanded. */
	settings_parse_set_expanded(service->set_parser, TRUE);
	return 0;
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
