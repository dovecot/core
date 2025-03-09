#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include "config-filter.h"

#include <sys/stat.h>

#define CONFIG_MODULE_DIR MODULEDIR"/settings"

/* change_counter used for default settings created internally */
#define CONFIG_PARSER_CHANGE_DEFAULTS 1
/* change_counter used for settings changed by configuration file */
#define CONFIG_PARSER_CHANGE_EXPLICIT 2

struct config_parsed;
struct setting_parser_context;

enum config_parse_flags {
	CONFIG_PARSE_FLAG_EXPAND_VALUES	= BIT(0),
	CONFIG_PARSE_FLAG_HIDE_OBSOLETE_WARNINGS = BIT(1),
	CONFIG_PARSE_FLAG_DELAY_ERRORS  = BIT(3),
	CONFIG_PARSE_FLAG_RETURN_BROKEN_CONFIG = BIT(4),
	CONFIG_PARSE_FLAG_NO_DEFAULTS = BIT(5),
	/* External hook is currently used by Pigeonhole to get capabilities
	   for managesieve-login process by running the managesieve process.
	   Do this only when executing doveconf or config binary explicitly,
	   not e.g. when executing doveadm. */
	CONFIG_PARSE_FLAG_EXTERNAL_HOOKS = BIT(6),
	/* By default filter_name { filter_name_key } is stored into the
	   parent. With this option, this is reversed so that filter_name_key
	   is stored under filter_name { filter_name_key }. This makes the
	   output nicer for the human-readable doveconf. */
	CONFIG_PARSE_FLAG_PREFIXES_IN_FILTERS = BIT(7),
	/* Expand include @groups after parsing settings. This can be useful
	   for doveconf output. */
	CONFIG_PARSE_FLAG_MERGE_GROUP_FILTERS = BIT(8),
	/* Merge default filters with non-default filters. This can be useful
	   for doveconf output. */
	CONFIG_PARSE_FLAG_MERGE_DEFAULT_FILTERS = BIT(9),
	/* Ignore unknown settings in the config file. */
	CONFIG_PARSE_FLAG_IGNORE_UNKNOWN = BIT(10),
};

/* Used to track changed settings for a setting_parser_info. Initially only
   the "info" is set, while everything else is NULL. Once the first setting
   is changed, the other fields are initialized. Each config_filter_parser
   initializes new empty config_module_parsers. */
struct config_module_parser {
	const struct setting_parser_info *info;

	/* The rest are filled only after the first setting is changed: */
	unsigned int set_count;
	union config_module_parser_setting {
		const char *str;
		struct {
			ARRAY_TYPE(const_string) *values;
			bool stop_list;
		} array;
	} *settings; /* [set_count] */
	uint8_t *change_counters; /* [set_count] */
	/* Set if CONFIG_PARSE_FLAG_DELAY_ERRORS is enabled. The error won't
	   cause an immediate config parsing failure. Instead, the error string
	   is forwarded to the config client process, which errors out only if
	   the settings struct is attempted to be used. This allows for example
	   doveadm to be called non-root and not fail even if it can't access
	   ssl_server_key_file. */
	const char *delayed_error;
};
ARRAY_DEFINE_TYPE(config_module_parsers, struct config_module_parser *);

struct config_path {
	const char *path;
	struct stat st;
};
ARRAY_DEFINE_TYPE(config_path, struct config_path);

extern struct module *modules;

int config_parse_net(const char *value, struct ip_addr *ip_r,
		     unsigned int *bits_r, const char **error_r);
int config_filter_parse(struct config_filter *filter, pool_t pool,
			const char *key, const char *value,
			const char **error_r);
int config_parse_file(const char *path, enum config_parse_flags flags,
		      const struct config_filter *dump_filter,
		      struct config_parsed **config_r,
		      const char **error_r)
	ATTR_NULL(3);
bool config_parsed_get_version(struct config_parsed *config,
			       const char **version_r);
/* Return all errors found while parsing the config file. */
const ARRAY_TYPE(const_string) *
config_parsed_get_errors(struct config_parsed *config);

/* Returns the global filter */
struct config_filter_parser *
config_parsed_get_global_filter_parser(struct config_parsed *config);
/* Returns the global default filter */
struct config_filter_parser *
config_parsed_get_global_default_filter_parser(struct config_parsed *config);
/* Returns all filters */
struct config_filter_parser *const *
config_parsed_get_filter_parsers(struct config_parsed *config);
/* Fill settings parser with settings from the given module parser. */
void config_fill_set_parser(struct setting_parser_context *parser,
			    const struct config_module_parser *p,
			    bool expand_values);
/* Returns the value for a specified setting. The setting must be found and it
   must be a string, or the function panics. */
const char *
config_parsed_get_setting(struct config_parsed *config,
			  const char *info_name, const char *key);
/* Return the change_counter for the specified setting. */
unsigned int
config_parsed_get_setting_change_counter(struct config_parsed *config,
					 const char *info_name,
					 const char *key);
/* Lookup setting with the specified key. */
const struct setting_define *
config_parsed_key_lookup(struct config_parsed *config, const char *key);
/* Get the list of filter's include groups that have any settings in the given
   module parser index. Returns TRUE if any groups were returned. */
bool config_parsed_get_includes(struct config_parsed *config,
				const struct config_filter_parser *filter,
				unsigned int parser_idx,
				ARRAY_TYPE(config_include_group) *groups);
/* Get all paths used for generating the config */
const ARRAY_TYPE(config_path) *
config_parsed_get_paths(struct config_parsed *config);
void config_parsed_free(struct config_parsed **config);

void config_parse_load_modules(bool dump_config_import);

void config_parser_deinit(void);

#endif
