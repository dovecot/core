#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

extern struct config_filter_context *config_filter;

void config_parse_file(const char *path, bool expand_files);

#endif
