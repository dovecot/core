#ifndef OLD_SET_PARSER_H
#define OLD_SET_PARSER_H

#include "config-parser-private.h"

struct config_parser_context;

bool old_settings_handle(struct config_parser_context *ctx,
			 const struct config_line *line);

#endif
