#ifndef OLD_SET_PARSER_H
#define OLD_SET_PARSER_H

#include "config-parser-private.h"

struct config_parser_context;

void old_settings_handle(struct config_parser_context *ctx,
			 struct config_line *line);
bool old_settings_default(const char *dovecot_config_version,
			  const char *key, const char *key_with_path,
			  const char **old_default_r);
unsigned int
old_settings_default_changes_count(const char *dovecot_config_version);

#endif
