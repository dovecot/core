/* Copyright (c) 2023 Dovecot Oy, see the included COPYING file */

#include "lib.h"
#include "settings.h"
#include "settings-parser.h"
#include "fts-solr-settings.h"

#undef DEF
#define DEF(type, name) SETTING_DEFINE_STRUCT_##type( \
	FTS_SOLR_FILTER"_"#name, name, struct fts_solr_settings)

static const struct setting_define fts_solr_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = FTS_SOLR_FILTER },
	DEF(STR,  url),
	DEF(UINT, batch_size),
	DEF(BOOL, soft_commit),
	SETTING_DEFINE_LIST_END
};

static const struct fts_solr_settings fts_solr_default_settings = {
	.url               = "",
	.batch_size        = 1000,
	.soft_commit       = TRUE,
};

static const struct setting_keyvalue fts_solr_default_settings_keyvalue[] = {
	{ FTS_SOLR_FILTER"/http_client_max_idle_time", "5s" },
	{ FTS_SOLR_FILTER"/http_client_max_parallel_connections", "1" },
	{ FTS_SOLR_FILTER"/http_client_max_pipelined_requests", "1" },
	{ FTS_SOLR_FILTER"/http_client_request_max_redirects", "1" },
	{ FTS_SOLR_FILTER"/http_client_request_max_attempts", "3" },
	{ FTS_SOLR_FILTER"/http_client_connect_timeout", "5s" },
	{ FTS_SOLR_FILTER"/http_client_request_timeout", "60s" },
	{ NULL, NULL }
};

const struct setting_parser_info fts_solr_setting_parser_info = {
	.name = FTS_SOLR_FILTER,
	.plugin_dependency = "lib21_fts_solr_plugin",

	.defines = fts_solr_setting_defines,
	.defaults = &fts_solr_default_settings,
	.default_settings = fts_solr_default_settings_keyvalue,

	.struct_size = sizeof(struct fts_solr_settings),
	.pool_offset1 = 1 + offsetof(struct fts_solr_settings, pool),
};

int fts_solr_settings_get(struct event *event,
			  const struct setting_parser_info *info,
			  const struct fts_solr_settings **set_r,
			  const char **error_r)
{
	if (settings_get(event, info, 0, set_r, error_r) < 0)
		return -1;

	const char *url = (*set_r)->url;
	if (*url == '\0') {
		*error_r = "fts_solr_url is required";
		settings_free(*set_r);
		return -1;
	}

	return 0;
}
