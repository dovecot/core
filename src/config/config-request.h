#ifndef CONFIG_REQUEST_H
#define CONFIG_REQUEST_H

#include "settings-parser.h"

struct config_parsed;
struct config_module_parser;

enum config_dump_scope {
	/* Dump all settings, including hidden settings */
	CONFIG_DUMP_SCOPE_ALL_WITH_HIDDEN,
	/* Dump all non-hidden settings */
	CONFIG_DUMP_SCOPE_ALL_WITHOUT_HIDDEN,
	/* Dump all that have explicitly been set */
	CONFIG_DUMP_SCOPE_SET,
	/* Dump only settings that differ from defaults */
	CONFIG_DUMP_SCOPE_CHANGED
};

enum config_dump_flags {
	CONFIG_DUMP_FLAG_HIDE_LIST_DEFAULTS	= 0x02,
	CONFIG_DUMP_FLAG_DEDUPLICATE_KEYS	= 0x08,
};

enum config_key_type {
	CONFIG_KEY_NORMAL,
	CONFIG_KEY_LIST,
	CONFIG_KEY_UNIQUE_KEY,
	CONFIG_KEY_FILTER_ARRAY,
};

typedef void config_request_callback_t(const char *key, const char *value,
				       enum config_key_type type, void *context);

bool config_export_type(string_t *str, const void *value,
			const void *default_value,
			enum setting_type type, bool dump_default,
			bool *dump_r) ATTR_NULL(3);
struct config_export_context *
config_export_init(enum config_dump_scope scope,
		   enum config_dump_flags flags,
		   config_request_callback_t *callback, void *context)
	ATTR_NULL(1, 5);
void config_export_set_module_parsers(struct config_export_context *ctx,
				      const struct config_module_parser *parsers);
unsigned int config_export_get_parser_count(struct config_export_context *ctx);
const char *
config_export_get_import_environment(struct config_export_context *ctx);
const char *config_export_get_base_dir(struct config_export_context *ctx);
int config_export_all_parsers(struct config_export_context **ctx,
			      unsigned int *section_idx);
const struct setting_parser_info *
config_export_parser_get_info(struct config_export_context *ctx,
			      unsigned int parser_idx);
int config_export_parser(struct config_export_context *ctx,
			 unsigned int parser_idx,
			 unsigned int *section_idx, const char **error_r);
void config_export_free(struct config_export_context **ctx);

#endif
