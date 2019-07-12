#ifndef OLD_SET_PARSER_H
#define OLD_SET_PARSER_H

#include "config-parser-private.h"

struct config_parser_context;

bool old_settings_ssl_dh_load(const char **value, const char **error_r);

bool old_settings_handle(struct config_parser_context *ctx,
			 enum config_line_type type,
			 const char *key, const char *value);
void old_settings_init(struct config_parser_context *ctx);
void old_settings_deinit_global(void);

#endif
