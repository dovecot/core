#ifndef CONFIG_REQUEST_H
#define CONFIG_REQUEST_H

#include "config-filter.h"

enum setting_type;
struct master_service_settings_output;

enum config_dump_scope {
	/* Dump all settings */
	CONFIG_DUMP_SCOPE_ALL,
	/* Dump all that have explicitly been set */
	CONFIG_DUMP_SCOPE_SET,
	/* Dump only settings that differ from defaults */
	CONFIG_DUMP_SCOPE_CHANGED
};

enum config_dump_flags {
	CONFIG_DUMP_FLAG_CHECK_SETTINGS		= 0x01,
	CONFIG_DUMP_FLAG_HIDE_LIST_DEFAULTS	= 0x02,
	/* Errors are reported using callback and they don't stop handling */
	CONFIG_DUMP_FLAG_CALLBACK_ERRORS	= 0x04
};

enum config_key_type {
	CONFIG_KEY_NORMAL,
	CONFIG_KEY_LIST,
	CONFIG_KEY_UNIQUE_KEY,
	/* error message is in value */
	CONFIG_KEY_ERROR
};

typedef void config_request_callback_t(const char *key, const char *value,
				       enum config_key_type type, void *context);

bool config_export_type(string_t *str, const void *value,
			const void *default_value,
			enum setting_type type, bool dump_default,
			bool *dump_r);
struct config_export_context *
config_export_init(const char *module, enum config_dump_scope scope,
		   enum config_dump_flags flags,
		   config_request_callback_t *callback, void *context);
void config_export_by_filter(struct config_export_context *ctx,
			     const struct config_filter *filter);
void config_export_parsers(struct config_export_context *ctx,
			   const struct config_module_parser *parsers);
void config_export_get_output(struct config_export_context *ctx,
			      struct master_service_settings_output *output_r);
int config_export_finish(struct config_export_context **ctx);

#endif
