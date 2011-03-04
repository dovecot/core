/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-search-parser-private.h"

void mail_search_parser_deinit(struct mail_search_parser **_parser)
{
	struct mail_search_parser *parser = *_parser;

	*_parser = NULL;
	pool_unref(&parser->pool);
}

int mail_search_parse_key(struct mail_search_parser *parser,
			  const char **key_r)
{
	int ret;

	if ((ret = parser->v.parse_key(parser, key_r)) <= 0)
		return ret;

	parser->cur_key = *key_r;
	return 1;
}

int mail_search_parse_string(struct mail_search_parser *parser,
			     const char **value_r)
{
	int ret;

	ret = parser->v.parse_string(parser, value_r);
	if (ret < 0 && parser->cur_key != NULL) {
		parser->error = p_strdup_printf(parser->pool,
			"%s (for search key: %s)",
			parser->error, t_str_ucase(parser->cur_key));
	}
	return ret;
}

bool mail_search_parse_skip_next(struct mail_search_parser *parser,
				 const char *str)
{
	return parser->v.parse_skip_next(parser, str);
}

const char *mail_search_parser_get_error(struct mail_search_parser *parser)
{
	return parser->error;
}
