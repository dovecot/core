/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-search-parser-private.h"

struct cmdline_mail_search_parser {
	struct mail_search_parser parser;

	const char *const *args;
	unsigned int list_level;
};

static int cmdline_search_parse_key(struct mail_search_parser *_parser,
				    const char **key_r)
{
	struct cmdline_mail_search_parser *parser =
		(struct cmdline_mail_search_parser *)_parser;

	if (parser->args[0] == NULL) {
		if (parser->list_level != 0) {
			_parser->error = "Missing ')'";
			return -1;
		}
		return 0;
	}

	if (strcmp(parser->args[0], "(") == 0) {
		parser->list_level++;
		parser->args++;
		*key_r = MAIL_SEARCH_PARSER_KEY_LIST;
		return 1;
	} else if (strcmp(parser->args[0], ")") == 0) {
		if (parser->list_level == 0) {
			_parser->error = "Unexpected ')'";
			return -1;
		}
		parser->list_level--;
		parser->args++;
		*key_r = MAIL_SEARCH_PARSER_KEY_LIST;
		return 0;
	} else {
		*key_r = parser->args[0];
		parser->args++;
		return 1;
	}
}

static int cmdline_search_parse_string(struct mail_search_parser *_parser,
				       const char **value_r)
{
	struct cmdline_mail_search_parser *parser =
		(struct cmdline_mail_search_parser *)_parser;

	if (parser->args[0] == NULL) {
		_parser->error = "Missing parameter for search key";
		return -1;
	}
	*value_r = parser->args[0];

	parser->args++;
	return 1;
}

static bool
cmdline_search_parse_skip_next(struct mail_search_parser *_parser,
			       const char *str)
{
	struct cmdline_mail_search_parser *parser =
		(struct cmdline_mail_search_parser *)_parser;

	if (parser->args[0] == NULL)
		return FALSE;
	if (strcasecmp(parser->args[0], str) != 0)
		return FALSE;

	parser->args++;
	return TRUE;
}

static const struct mail_search_parser_vfuncs mail_search_parser_cmdline_vfuncs = {
	cmdline_search_parse_key,
	cmdline_search_parse_string,
	cmdline_search_parse_skip_next
};

struct mail_search_parser *
mail_search_parser_init_cmdline(const char *const args[])
{
	struct cmdline_mail_search_parser *parser;
	pool_t pool;

	pool = pool_alloconly_create("cmdline search parser", 1024);
	parser = p_new(pool, struct cmdline_mail_search_parser, 1);
	parser->parser.pool = pool;
	parser->parser.v = mail_search_parser_cmdline_vfuncs;
	parser->args = args;
	return &parser->parser;
}
