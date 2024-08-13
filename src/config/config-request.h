#ifndef CONFIG_REQUEST_H
#define CONFIG_REQUEST_H

#include "settings-parser.h"

struct config_parsed;
struct config_module_parser;

enum config_dump_scope {
	/* Only temporarily set while parsing doveconf parameters */
	CONFIG_DUMP_SCOPE_DEFAULT,

	/* Dump all settings, including hidden settings */
	CONFIG_DUMP_SCOPE_ALL_WITH_HIDDEN,
	/* Dump all non-hidden settings */
	CONFIG_DUMP_SCOPE_ALL_WITHOUT_HIDDEN,
	/* Dump all that have explicitly been set */
	CONFIG_DUMP_SCOPE_SET,
	/* Same as CONFIG_DUMP_SCOPE_SET, but also dump any defaults overridden
	   via strings (instead of the defaults struct). */
	CONFIG_DUMP_SCOPE_SET_AND_DEFAULT_OVERRIDES,
	/* Dump only settings that differ from defaults */
	CONFIG_DUMP_SCOPE_CHANGED
};

enum config_dump_flags {
	CONFIG_DUMP_FLAG_DEDUPLICATE_KEYS	= 0x08,
};

enum config_key_type {
	CONFIG_KEY_NORMAL,
	CONFIG_KEY_LIST,
	CONFIG_KEY_FILTER_ARRAY,
};

struct config_export_setting {
	enum config_key_type type;
	const char *key;
	unsigned int key_define_idx;
	const char *value;
};

typedef void config_request_callback_t(const struct config_export_setting *set,
				       void *context);

bool config_export_type(string_t *str, const void *value,
			const void *default_value,
			enum setting_type type, bool dump_default,
			bool *dump_r) ATTR_NULL(3);
struct config_export_context *
config_export_init(enum config_dump_scope scope,
		   enum config_dump_flags flags,
		   config_request_callback_t *callback, void *context)
	ATTR_NULL(1, 5);
#define config_export_init(scope, flags, callback, context) \
	config_export_init(scope, flags, \
		(config_request_callback_t *)callback, \
		TRUE ? context : CALLBACK_TYPECHECK(callback, \
			void (*)(const struct config_export_setting *, typeof(context))))
void config_export_set_module_parsers(struct config_export_context *ctx,
				      const struct config_module_parser *parsers);
unsigned int config_export_get_parser_count(struct config_export_context *ctx);
const char *
config_export_get_import_environment(struct config_export_context *ctx);
const char *config_export_get_base_dir(struct config_export_context *ctx);
int config_export_all_parsers(struct config_export_context **ctx);
const struct setting_parser_info *
config_export_parser_get_info(struct config_export_context *ctx,
			      unsigned int parser_idx);
int config_export_parser(struct config_export_context *ctx,
			 unsigned int parser_idx, const char **error_r);
void config_export_free(struct config_export_context **ctx);

#endif
