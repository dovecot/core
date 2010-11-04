#ifndef CONFIG_PARSER_PRIVATE_H
#define CONFIG_PARSER_PRIVATE_H

#include "config-parser.h"
#include "config-filter.h"

enum config_line_type {
	CONFIG_LINE_TYPE_SKIP,
	CONFIG_LINE_TYPE_ERROR,
	CONFIG_LINE_TYPE_KEYVALUE,
	CONFIG_LINE_TYPE_KEYFILE,
	CONFIG_LINE_TYPE_KEYVARIABLE,
	CONFIG_LINE_TYPE_SECTION_BEGIN,
	CONFIG_LINE_TYPE_SECTION_END,
	CONFIG_LINE_TYPE_INCLUDE,
	CONFIG_LINE_TYPE_INCLUDE_TRY
};

struct config_section_stack {
	struct config_section_stack *prev;

	struct config_filter filter;
	/* root=NULL-terminated list of parsers */
	struct config_module_parser *parsers;
	unsigned int pathlen;

	const char *open_path;
	unsigned int open_linenum;
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
	const char *module;

	ARRAY_DEFINE(all_parsers, struct config_filter_parser *);
	struct config_module_parser *root_parsers;
	struct config_section_stack *cur_section;
	struct input_stack *cur_input;

	string_t *str;
	unsigned int pathlen;
	unsigned int section_counter;
	const char *error;

	struct old_set_parser *old;

	struct config_filter_context *filter;
	unsigned int expand_values:1;
};

extern void (*hook_config_parser_begin)(struct config_parser_context *ctx);

int config_apply_line(struct config_parser_context *ctx, const char *key,
		      const char *line, const char *section_name);
void config_parser_apply_line(struct config_parser_context *ctx,
			      enum config_line_type type,
			      const char *key, const char *value);

#endif
