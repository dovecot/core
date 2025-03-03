/* Copyright (c) 2023 Dovecot Oy, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings.h"
#include "settings-parser.h"
#include "fts-settings.h"

#undef DEF
#define DEF(_type, name) SETTING_DEFINE_STRUCT_##_type( \
	FTS_FILTER"_"#name, name, struct fts_settings)

static const struct setting_define fts_setting_defines[] = {
	{ .type = SET_FILTER_ARRAY, .key = FTS_FILTER,
	  .offset = offsetof(struct fts_settings, fts),
	  .filter_array_field_name = "fts_driver", },
	DEF(BOOL,    autoindex),
	DEF(UINT,    autoindex_max_recent_msgs),
	DEF(ENUM,    decoder_driver),
	DEF(STR,     decoder_script_socket_path),
	{ .type = SET_FILTER_NAME, .key = FTS_FILTER_DECODER_TIKA },
	DEF(STR,     decoder_tika_url),
	DEF(STR,     driver),
	DEF(BOOL,    search),
	DEF(ENUM,    search_add_missing),
	DEF(BOOL,    search_read_fallback),
	DEF(BOOLLIST,header_excludes),
	DEF(BOOLLIST,header_includes),
	DEF(TIME,    search_timeout),
	DEF(SIZE,    message_max_size),
	SETTING_DEFINE_LIST_END
};

/* <settings checks> */

#define FTS_SEARCH_ADD_MISSING_BODY_SEARCH_ONLY "body-search-only"

#define FTS_DECODER_KEYWORD_NONE   ""
#define FTS_DECODER_KEYWORD_TIKA   "tika"
#define FTS_DECODER_KEYWORD_SCRIPT "script"

static bool fts_settings_check(void *set, pool_t pool, const char **error_r);

/* </settings checks> */

static const struct fts_settings fts_default_settings = {
	.fts = ARRAY_INIT,
	.autoindex = FALSE,
	.autoindex_max_recent_msgs = 0,
	.decoder_driver = FTS_DECODER_KEYWORD_NONE
		       ":"FTS_DECODER_KEYWORD_TIKA
		       ":"FTS_DECODER_KEYWORD_SCRIPT,
	.decoder_script_socket_path = "",
	.decoder_tika_url = "",
	.driver = "",
	.search = TRUE,
	.search_add_missing = FTS_SEARCH_ADD_MISSING_BODY_SEARCH_ONLY":yes",
	.search_read_fallback = TRUE,

	.search_timeout = 30,
	.message_max_size = SET_SIZE_UNLIMITED,
};

static const struct setting_keyvalue fts_default_settings_keyvalue[] = {
	{ FTS_FILTER_DECODER_TIKA"/http_client_max_idle_time", "100ms" },
	{ FTS_FILTER_DECODER_TIKA"/http_client_max_parallel_connections", "1" },
	{ FTS_FILTER_DECODER_TIKA"/http_client_max_pipelined_requests", "1" },
	{ FTS_FILTER_DECODER_TIKA"/http_client_request_max_redirects", "1" },
	{ FTS_FILTER_DECODER_TIKA"/http_client_request_max_attempts", "3" },
	{ FTS_FILTER_DECODER_TIKA"/http_client_connect_timeout", "5s" },
	{ FTS_FILTER_DECODER_TIKA"/http_client_request_timeout", "60s" },
	{ NULL, NULL }
};

const struct setting_parser_info fts_setting_parser_info = {
	.name = FTS_FILTER,
	.plugin_dependency = "lib20_fts_plugin",

	.defines = fts_setting_defines,
	.defaults = &fts_default_settings,
	.default_settings = fts_default_settings_keyvalue,
	.check_func = fts_settings_check,

	.struct_size = sizeof(struct fts_settings),
	.pool_offset1 = 1 + offsetof(struct fts_settings, pool),
};

/* <settings checks> */

struct fts_settings_enum_table {
	const char *key;
	int value;
};

static int fts_settings_parse_enum(struct fts_settings_enum_table *table,
				   const char *key)
{
	for (; table->key != NULL; table++)
		if (strcasecmp(key, table->key) == 0)
			return table->value;
	i_unreached();
}

static enum fts_decoder fts_settings_parse_decoder(const char *key)
{
	static struct fts_settings_enum_table table[] = {
		{ FTS_DECODER_KEYWORD_NONE,   FTS_DECODER_NO },
		{ FTS_DECODER_KEYWORD_TIKA,   FTS_DECODER_TIKA },
		{ FTS_DECODER_KEYWORD_SCRIPT, FTS_DECODER_SCRIPT },
		{ NULL, 0 }
	};
	return fts_settings_parse_enum(table, key);
}

static bool fts_settings_check_decoder(struct fts_settings *set,
				       const char **error_r)
{
	switch (set->parsed_decoder_driver) {
	case FTS_DECODER_SCRIPT:
		if (*set->decoder_script_socket_path != '\0')
			return TRUE;
		*error_r = "decoder_script_socket_path is required "
			   "when fts_decoder_driver = script";
		return FALSE;
	case FTS_DECODER_NO:
	case FTS_DECODER_TIKA:
		return TRUE;
	default:
		i_unreached();
	}

	if(*set->decoder_script_socket_path != '\0' &&
	   set->parsed_decoder_driver != FTS_DECODER_SCRIPT) {
		*error_r = "fts_decoder_driver = script is required "
			   "when using decoder_script_socket_path";
		return FALSE;
	}
	if(*set->decoder_tika_url != '\0' &&
	   set->parsed_decoder_driver != FTS_DECODER_TIKA) {
		*error_r = "fts_decoder_script = tika is required "
			   "when using decoder_tika_url";
		return FALSE;
	}
}

static bool fts_settings_check(void *_set, pool_t pool ATTR_UNUSED,
			       const char **error_r)
{
	struct fts_settings *set = _set;

	if (set->search_timeout == 0) {
		*error_r = "fts_search_timeout must not be 0";
		return FALSE;
	}
	set->parsed_search_add_missing_body_only =
		strcmp(set->search_add_missing,
		       FTS_SEARCH_ADD_MISSING_BODY_SEARCH_ONLY) == 0;
	set->parsed_decoder_driver = fts_settings_parse_decoder(set->decoder_driver);
	return fts_settings_check_decoder(set, error_r);
}

/* </settings checks> */
