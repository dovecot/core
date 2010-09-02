#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#define CONFIG_MODULE_DIR MODULEDIR"/settings"

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

struct config_module_parser {
	const struct setting_parser_info *root;
	struct setting_parser_context *parser;
	void *settings;
};
ARRAY_DEFINE_TYPE(config_module_parsers, struct config_module_parser *);

extern struct config_module_parser *config_module_parsers;
extern struct config_filter_context *config_filter;
extern struct module *modules;

int config_parse_net(const char *value, struct ip_addr *ip_r,
		     unsigned int *bits_r, const char **error_r);
int config_parse_file(const char *path, bool expand_values, const char *module,
		      const char **error_r);

void config_parse_load_modules(void);

bool config_module_want_parser(struct config_module_parser *parsers,
			       const char *module,
			       const struct setting_parser_info *root);

#endif
