#ifndef CONFIG_PARSER_PRIVATE_H
#define CONFIG_PARSER_PRIVATE_H

#include "config-parser.h"
#include "config-filter.h"

enum config_line_type {
	/* empty line, or only a #comment in the line */
	CONFIG_LINE_TYPE_SKIP,
	/* line ended with '\' - need to continue parsing the next line */
	CONFIG_LINE_TYPE_CONTINUE,
	/* value contains the parser error string */
	CONFIG_LINE_TYPE_ERROR,
	/* key = value */
	CONFIG_LINE_TYPE_KEYVALUE,
	/* key = <value */
	CONFIG_LINE_TYPE_KEYFILE,
	/* key = $value */
	CONFIG_LINE_TYPE_KEYVARIABLE,
	/* key {
	   key value { */
	CONFIG_LINE_TYPE_SECTION_BEGIN,
	/* } (key = "}", value = "") */
	CONFIG_LINE_TYPE_SECTION_END,
	/* group @key value { */
	CONFIG_LINE_TYPE_GROUP_SECTION_BEGIN,
	/* !include value (key = "!include") */
	CONFIG_LINE_TYPE_INCLUDE,
	/* !include_try value (key = "!include_try") */
	CONFIG_LINE_TYPE_INCLUDE_TRY
};

struct config_line {
	enum config_line_type type;
	const char *key;
	const char *value;
	/* value is inside "quotes" */
	bool value_quoted;
};

/* Returns TRUE if section is inside strlist { .. } or boollist { .. } */
#define config_section_is_in_list(section) \
	(!(section)->is_filter && (section)->key != NULL)

/* A section { .. } either in configuration file, or its equivalent in a
   section/key setting path. */
struct config_section_stack {
	/* Parent section, or NULL if this is the root (not a section) */
	struct config_section_stack *prev;
	/* Section key, e.g. "foo" in "foo { .. }". This is used only for
	   non-filters, i.e. strlist { .. } or boollist { .. } */
	const char *key;

	/* The filter_parser matches all the filters in this section stack. */
	struct config_filter_parser *filter_parser;

	/* Config file's filename and line number where this section was
	   opened in. */
	const char *open_path;
	unsigned int open_linenum;
	/* This section is a filter (instead of strlist or boollist) */
	bool is_filter;

	/* If this section begins a named [list] filter, this points to its
	   definition. */
	const struct setting_define *filter_def;
};

struct input_stack {
	struct input_stack *prev;

	struct istream *input;
	const char *path;
	unsigned int linenum;
};

struct config_parser_context {
	pool_t pool;
	const char *path;

	ARRAY_TYPE(config_path) seen_paths;
	HASH_TABLE(const char *, struct config_parser_key *) all_keys;
	ARRAY(struct config_filter_parser *) all_filter_parsers;
	HASH_TABLE(struct config_filter *,
		   struct config_filter_parser *) all_filter_parsers_hash;
	struct config_module_parser *root_module_parsers;
	struct config_section_stack *cur_section;
	struct input_stack *cur_input;
	uint8_t change_counter;
	unsigned int create_order_counter;

	string_t *value;
	const char *error;

	const char *dovecot_config_version;

	const char *const *filter_name_prefixes;
	unsigned int filter_name_prefixes_count;

	struct old_set_parser *old;

	HASH_TABLE(const char *, const char *) seen_settings;
	struct config_filter_context *filter;
	bool dump_defaults:1;
	bool expand_values:1;
	bool hide_errors:1;
	bool delay_errors:1;
	bool hide_obsolete_warnings:1;
	bool ignore_unknown:1;
};

extern void (*hook_config_parser_begin)(struct config_parser_context *ctx);
/* Finish parsing settings. The event parameter provides access to already
   parsed settings. It's still possible to further modify the config. */
extern int (*hook_config_parser_end)(struct config_parser_context *ctx,
				     struct config_parsed *new_config,
				     struct event *event, const char **error_r);

int config_apply_line(struct config_parser_context *ctx, const char *key,
		      const char *value, const char **full_key_r) ATTR_NULL(4);
void config_parser_apply_line(struct config_parser_context *ctx,
			      const struct config_line *line);
void config_parser_set_change_counter(struct config_parser_context *ctx,
				      uint8_t change_counter);

#endif
