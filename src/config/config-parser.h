#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#define CONFIG_MODULE_DIR MODULEDIR"/settings"

struct config_module_parser {
	const struct setting_parser_info *root;
	struct setting_parser_context *parser;
	void *settings;
};
ARRAY_DEFINE_TYPE(config_module_parsers, struct config_module_parser *);

extern struct config_module_parser *config_module_parsers;
extern struct config_filter_context *config_filter;

int config_parse_file(const char *path, bool expand_values,
		      const char **error_r);

void config_parse_load_modules(void);

#endif
