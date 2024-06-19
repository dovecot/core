#ifndef CONFIG_PARSER_PRIVATE_H
#define CONFIG_PARSER_PRIVATE_H

#include "config-parser.h"
#include "config-filter.h"

enum config_line_type {
	CONFIG_LINE_TYPE_SKIP,
	CONFIG_LINE_TYPE_CONTINUE,
	CONFIG_LINE_TYPE_ERROR,
	CONFIG_LINE_TYPE_KEYVALUE,
	CONFIG_LINE_TYPE_KEYFILE,
	CONFIG_LINE_TYPE_KEYVARIABLE,
	CONFIG_LINE_TYPE_SECTION_BEGIN,
	CONFIG_LINE_TYPE_SECTION_END,
	CONFIG_LINE_TYPE_INCLUDE,
	CONFIG_LINE_TYPE_INCLUDE_TRY
};

struct config_line {
	enum config_line_type type;
	const char *key;
	const char *value;
	bool value_quoted;
};

struct config_section_stack {
	struct config_section_stack *prev;
	const char *key;

	struct config_filter filter;
	struct config_filter_parser *filter_parser;
	/* root=NULL-terminated list of parsers */
	struct config_module_parser *module_parsers;
	size_t pathlen;

	const char *open_path;
	unsigned int open_linenum;
	bool is_filter;

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

	HASH_TABLE(const char *, struct config_parser_key *) all_keys;
	ARRAY(struct config_filter_parser *) all_filter_parsers;
	struct config_module_parser *root_module_parsers;
	struct config_section_stack *cur_section;
	struct input_stack *cur_input;
	uint8_t change_counter;

	string_t *key_path, *value;
	const char *error;

	const char *dovecot_config_version;
	struct old_set_parser *old;

	HASH_TABLE(const char *, const char *) seen_settings;
	struct config_filter_context *filter;
	bool expand_values:1;
	bool hide_errors:1;
	bool delay_errors:1;
	bool hide_obsolete_warnings:1;
};

extern void (*hook_config_parser_begin)(struct config_parser_context *ctx);
extern int (*hook_config_parser_end)(struct config_parser_context *ctx,
				     const char **error_r);

int config_apply_line(struct config_parser_context *ctx, const char *key,
		      const char *value, const char **full_key_r) ATTR_NULL(4);
void config_parser_apply_line(struct config_parser_context *ctx,
			      const struct config_line *line);
void config_parser_set_change_counter(struct config_parser_context *ctx,
				      uint8_t change_counter);

#endif
