#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#define CONFIG_MODULE_DIR MODULEDIR"/settings"

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

/* change_counter used for default settings created internally */
#define CONFIG_PARSER_CHANGE_INTERNAL 1
/* change_counter used for settings changed by configuration file */
#define CONFIG_PARSER_CHANGE_EXPLICIT 2

struct config_parsed;

enum config_parse_flags {
	CONFIG_PARSE_FLAG_EXPAND_VALUES	= BIT(0),
	CONFIG_PARSE_FLAG_HIDE_OBSOLETE_WARNINGS = BIT(1),
	CONFIG_PARSE_FLAG_DELAY_ERRORS  = BIT(3),
	CONFIG_PARSE_FLAG_RETURN_BROKEN_CONFIG = BIT(4),
	CONFIG_PARSE_FLAG_NO_DEFAULTS = BIT(5),
};

struct config_module_parser {
	const struct setting_parser_info *info;
	struct setting_parser_context *parser;
	/* Set if CONFIG_PARSE_FLAG_DELAY_ERRORS is enabled. The error won't
	   cause an immediate config parsing failure. Instead, the error string
	   is forwarded to the config client process, which errors out only if
	   the settings struct is attempted to be used. This allows for example
	   doveadm to be called non-root and not fail even if it can't access
	   ssl_key file. */
	const char *delayed_error;
};
ARRAY_DEFINE_TYPE(config_module_parsers, struct config_module_parser *);

extern struct module *modules;

int config_parse_net(const char *value, struct ip_addr *ip_r,
		     unsigned int *bits_r, const char **error_r);
int config_parse_file(const char *path, enum config_parse_flags flags,
		      struct config_parsed **config_r,
		      const char **error_r)
	ATTR_NULL(3);
/* Return all errors found while parsing the config file. */
const ARRAY_TYPE(const_string) *
config_parsed_get_errors(struct config_parsed *config);

/* Returns the global filter */
struct config_filter_parser *
config_parsed_get_global_filter_parser(struct config_parsed *config);
/* Returns all filters */
struct config_filter_parser *const *
config_parsed_get_filter_parsers(struct config_parsed *config);
/* Returns all module_parsers. The array is terminated with info=NULL. */
const struct config_module_parser *
config_parsed_get_module_parsers(struct config_parsed *config);
/* Returns the value for a specified setting. The setting must be found and it
   must be a string, or the function panics. */
const char *
config_module_parsers_get_setting(const struct config_module_parser *module_parsers,
				  const char *info_name, const char *key);
void config_parsed_free(struct config_parsed **config);

void config_module_parsers_free(struct config_module_parser *parsers);

void config_parse_load_modules(void);

void config_parser_deinit(void);

#endif
