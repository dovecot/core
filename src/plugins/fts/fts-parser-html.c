/* Copyright (c) 2011-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "message-parser.h"
#include "mail-html2text.h"
#include "fts-parser.h"

struct html_fts_parser {
	struct fts_parser parser;
	struct mail_html2text *html2text;
	buffer_t *output;
};

static struct fts_parser *
fts_parser_html_try_init(struct mail_user *user ATTR_UNUSED,
			 const char *content_type,
			 const char *content_disposition ATTR_UNUSED)
{
	struct html_fts_parser *parser;

	if (!mail_html2text_content_type_match(content_type))
		return NULL;

	parser = i_new(struct html_fts_parser, 1);
	parser->parser.v = fts_parser_html;
	parser->html2text = mail_html2text_init(0);
	parser->output = buffer_create_dynamic(default_pool, 4096);
	return &parser->parser;
}

static void fts_parser_html_more(struct fts_parser *_parser,
				 struct message_block *block)
{
	struct html_fts_parser *parser = (struct html_fts_parser *)_parser;

	if (block->size == 0) {
		/* finished */
		return;
	}

	buffer_set_used_size(parser->output, 0);
	mail_html2text_more(parser->html2text, block->data, block->size,
			    parser->output);

	block->data = parser->output->data;
	block->size = parser->output->used;
}

static int fts_parser_html_deinit(struct fts_parser *_parser)
{
	struct html_fts_parser *parser = (struct html_fts_parser *)_parser;

	mail_html2text_deinit(&parser->html2text);
	buffer_free(&parser->output);
	i_free(parser);
	return 0;
}

struct fts_parser_vfuncs fts_parser_html = {
	fts_parser_html_try_init,
	fts_parser_html_more,
	fts_parser_html_deinit,
	NULL
};
