/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "unichar.h"
#include "message-parser.h"
#include "fts-parser.h"

const struct fts_parser_vfuncs *parsers[] = {
	&fts_parser_html,
	&fts_parser_script
};

bool fts_parser_init(struct mail_user *user,
		     const char *content_type, const char *content_disposition,
		     struct fts_parser **parser_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(parsers); i++) {
		*parser_r = parsers[i]->try_init(user, content_type,
						 content_disposition);
		if (*parser_r != NULL)
			return TRUE;
	}
	return FALSE;
}

struct fts_parser *fts_parser_text_init(void)
{
	return i_new(struct fts_parser, 1);
}

static bool data_has_nuls(const unsigned char *data, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		if (data[i] == '\0')
			return TRUE;
	}
	return FALSE;
}

static void replace_nul_bytes(buffer_t *buf)
{
	unsigned char *data;
	size_t i, size;

	data = buffer_get_modifiable_data(buf, &size);
	for (i = 0; i < size; i++) {
		if (data[i] == '\0')
			data[i] = ' ';
	}
}

void fts_parser_more(struct fts_parser *parser, struct message_block *block)
{
	if (parser->v.more != NULL)
		parser->v.more(parser, block);

	if (!uni_utf8_data_is_valid(block->data, block->size) ||
	    data_has_nuls(block->data, block->size)) {
		/* output isn't valid UTF-8. make it. */
		if (parser->utf8_output == NULL) {
			parser->utf8_output =
				buffer_create_dynamic(default_pool, 4096);
		} else {
			buffer_set_used_size(parser->utf8_output, 0);
		}
		(void)uni_utf8_get_valid_data(block->data, block->size,
					      parser->utf8_output);
		replace_nul_bytes(parser->utf8_output);
		block->data = parser->utf8_output->data;
		block->size = parser->utf8_output->used;
	}
}

void fts_parser_deinit(struct fts_parser **_parser)
{
	struct fts_parser *parser = *_parser;

	*_parser = NULL;

	if (parser->utf8_output != NULL)
		buffer_free(&parser->utf8_output);
	if (parser->v.deinit != NULL)
		parser->v.deinit(parser);
	else
		i_free(parser);
}
