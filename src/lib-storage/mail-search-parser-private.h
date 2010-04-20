#ifndef MAIL_SEARCH_PARSER_PRIVATE_H
#define MAIL_SEARCH_PARSER_PRIVATE_H

#include "mail-search-parser.h"

struct mail_search_parser_vfuncs {
	int (*parse_key)(struct mail_search_parser *parser, const char **key_r);
	int (*parse_string)(struct mail_search_parser *parser,
			    const char **value_r);
	bool (*parse_skip_next)(struct mail_search_parser *parser,
				const char *str);
};

struct mail_search_parser {
	struct mail_search_parser_vfuncs v;

	pool_t pool;
	const char *cur_key;
	const char *error;
};

#endif
