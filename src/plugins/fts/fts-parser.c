/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "fts-parser.h"

const struct fts_parser *parsers[] = {
	&fts_parser_html
};

bool fts_parser_init(const char *content_type, const char *content_disposition,
		     struct fts_parser **parser_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(parsers); i++) {
		*parser_r = parsers[i]->try_init(content_type,
						 content_disposition);
		if (*parser_r != NULL)
			return TRUE;
	}
	return FALSE;
}

void fts_parser_more(struct fts_parser *parser, struct message_block *block)
{
	parser->more(parser, block);
}

void fts_parser_deinit(struct fts_parser **_parser)
{
	struct fts_parser *parser = *_parser;

	*_parser = NULL;
	parser->deinit(parser);
}
