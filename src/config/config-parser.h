#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#define CONFIG_MODULE_DIR MODULEDIR"/settings"

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

enum config_parse_flags {
	CONFIG_PARSE_FLAG_EXPAND_VALUES	= BIT(0),
	CONFIG_PARSE_FLAG_HIDE_ERRORS	= BIT(1),
	CONFIG_PARSE_FLAG_SKIP_SSL_SERVER = BIT(2), /* FIXME: temporary kludge - remove later */
};

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
int config_parse_file(const char *path, enum config_parse_flags flags,
		      const char **error_r)
	ATTR_NULL(3);

void config_parse_load_modules(void);

void config_parser_deinit(void);

#endif
