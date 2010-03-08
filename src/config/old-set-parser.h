#ifndef OLD_SET_PARSER_H
#define OLD_SET_PARSER_H

enum config_line_type;
struct config_parser_context;

bool old_settings_handle(struct config_parser_context *ctx,
			 enum config_line_type type,
			 const char *key, const char *value);
void old_settings_init(struct config_parser_context *ctx);

#endif
