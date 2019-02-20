/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "unichar.h"
#include "message-parser.h"
#include "fts-parser.h"

static const struct fts_parser_vfuncs *parsers[] = {
	&fts_parser_html,
	&fts_parser_script,
	&fts_parser_tika
};

static const char *plaintext_content_types[] = {
	"text/plain",
	"message/delivery-status",
	"message/disposition-notification",
	"application/pgp-signature",
	NULL
};

bool fts_parser_init(struct fts_parser_context *parser_context,
		     struct fts_parser **parser_r)
{
	unsigned int i;
	i_assert(parser_context->user != NULL);
	i_assert(parser_context->content_type != NULL);

	if (str_array_find(plaintext_content_types, parser_context->content_type)) {
		/* we probably don't want/need to allow parsers to handle
		   plaintext? */
		return FALSE;
	}

	for (i = 0; i < N_ELEMENTS(parsers); i++) {
		*parser_r = parsers[i]->try_init(parser_context);
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
		if (uni_utf8_get_valid_data(block->data, block->size,
					    parser->utf8_output)) {
			/* valid UTF-8, but there were NULs */
			buffer_append(parser->utf8_output, block->data,
				      block->size);
		}
		replace_nul_bytes(parser->utf8_output);
		block->data = parser->utf8_output->data;
		block->size = parser->utf8_output->used;
	}
}

int fts_parser_deinit(struct fts_parser **_parser, const char **retriable_err_msg_r)
{
	struct fts_parser *parser = *_parser;
	int ret = 1;

	*_parser = NULL;

	buffer_free(&parser->utf8_output);
	if (parser->v.deinit != NULL) {
		const char *error = NULL;
		ret = parser->v.deinit(parser, &error);
		if (ret == 0) {
			i_assert(error != NULL);
			if (retriable_err_msg_r != NULL)
				*retriable_err_msg_r = error;
		}
	} else
		i_free(parser);
	return ret;
}

void fts_parsers_unload(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(parsers); i++) {
		if (parsers[i]->unload != NULL)
			parsers[i]->unload();
	}
}
