#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

struct config_setting_parser_list {
	const char *module_name;
	struct setting_parser_info *root;
	struct setting_parser_context *parser;
	void *settings;
};
ARRAY_DEFINE_TYPE(config_setting_parsers, struct config_setting_parser_list *);

extern struct config_setting_parser_list *config_setting_parsers;
extern struct config_filter_context *config_filter;

int config_parse_file(const char *path, bool expand_files,
		      const char **error_r);

#endif
