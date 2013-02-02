/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "unichar.h"
#include "message-parser.h"
#include "fts-parser.h"

/* Zero-width space (&#x200B;) apparently also belongs here, but that gets a
   bit tricky to handle.. is it actually used anywhere? */
#define HTML_WHITESPACE(c) \
	((c) == ' ' || (c) == '\t' || (c) == '\r' || (c) == '\n')

enum html_state {
	/* regular text */
	HTML_STATE_TEXT,
	/* tag outside "quoted string" */
	HTML_STATE_TAG,
	/* tag inside "quoted string" */
	HTML_STATE_TAG_QUOTED,
	/* tag -> "escape\ */
	HTML_STATE_TAG_QUOTED_ESCAPE,
	/* script/stype content */
	HTML_STATE_IGNORE,
	/* comment */
	HTML_STATE_COMMENT,
	/* comment is ending, we've seen "--" and now just waiting for ">" */
	HTML_STATE_COMMENT_END
};

struct html_fts_parser {
	struct fts_parser parser;

	enum html_state state;
	buffer_t *input, *output;
	bool ignore_next_text;
};

struct {
	const char *name;
	unichar_t chr;
} html_entities[] = {
#include "html-entities.h"
};

static struct fts_parser *
fts_parser_html_try_init(struct mail_user *user ATTR_UNUSED,
			 const char *content_type,
			 const char *content_disposition ATTR_UNUSED)
{
	struct html_fts_parser *parser;

	if (strcasecmp(content_type, "text/html") != 0)
		return NULL;

	parser = i_new(struct html_fts_parser, 1);
	parser->parser.v = fts_parser_html;
	parser->input = buffer_create_dynamic(default_pool, 512);
	parser->output = buffer_create_dynamic(default_pool, 4096);
	return &parser->parser;
}

static bool
parse_tag_name(struct html_fts_parser *parser,
	       const unsigned char *data, size_t size)
{
	size_t i;

	if (size >= 3 && memcmp(data, "!--", 3) == 0) {
		parser->state = HTML_STATE_COMMENT;
		return 3;
	}

	if (size > 5 && i_memcasecmp(data, "style", 5) == 0) {
		i = 5;
	} else if (size > 6 && i_memcasecmp(data, "script", 6) == 0) {
		i = 6;
	} else {
		if (size <= 6) {
			/* can we see the whole tag name? */
			for (i = 0; i < size; i++) {
				if (HTML_WHITESPACE(data[i]) || data[i] == '>')
					break;
			}
			if (i == size) {
				/* need more data */
				return 0;
			}
		}
		parser->state = HTML_STATE_TAG;
		return 1;
	}
	parser->state = HTML_STATE_TAG;
	if (HTML_WHITESPACE(data[i]) || data[i] == '>')
		parser->ignore_next_text = TRUE;
	return 1;
}

static bool html_entity_get_unichar(const char *name, unichar_t *chr_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(html_entities); i++) {
		if (strcasecmp(html_entities[i].name, name) == 0) {
			*chr_r = html_entities[i].chr;
			return TRUE;
		}
	}
	return FALSE;
}

static size_t parse_entity(struct html_fts_parser *parser,
			   const unsigned char *data, size_t size)
{
	char entity[10];
	unichar_t chr;
	size_t i;

	for (i = 0; i < size; i++) {
		if (HTML_WHITESPACE(data[i]) || i >= sizeof(entity)) {
			/* broken entity */
			return 1;
		}
		if (data[i] == ';')
			break;
	}
	if (i == size)
		return 0;

	i_assert(i < sizeof(entity));
	memcpy(entity, data, i); entity[i] = '\0';

	if (html_entity_get_unichar(entity, &chr))
		uni_ucs4_to_utf8_c(chr, parser->output);
	return i + 1;
}

static void parser_add_space(struct html_fts_parser *parser)
{
	const unsigned char *data = parser->output->data;

	if (parser->output->used > 0 &&
	    data[parser->output->used-1] != ' ')
		buffer_append_c(parser->output, ' ');
}

static size_t
parse_data(struct html_fts_parser *parser,
	   const unsigned char *data, size_t size)
{
	size_t i, ret;

	for (i = 0; i < size; i++) {
		char c = data[i];

		switch (parser->state) {
		case HTML_STATE_TEXT:
			if (c == '<') {
				ret = parse_tag_name(parser, data+i+1, size-i-1);
				if (ret == 0)
					return i;
				i += ret - 1;
			} else if (c == '&') {
				ret = parse_entity(parser, data+i+1, size-i-1);
				if (ret == 0)
					return i;
				i += ret - 1;
			} else {
				buffer_append_c(parser->output, c);
			}
			break;
		case HTML_STATE_TAG:
			if (c == '"')
				parser->state = HTML_STATE_TAG_QUOTED;
			else if (c == '>') {
				parser->state = parser->ignore_next_text ?
					HTML_STATE_IGNORE : HTML_STATE_TEXT;
				parser_add_space(parser);
			}
			break;
		case HTML_STATE_TAG_QUOTED:
			if (c == '"')
				parser->state = HTML_STATE_TAG;
			else if (c == '\\')
				parser->state = HTML_STATE_TAG_QUOTED_ESCAPE;
			break;
		case HTML_STATE_TAG_QUOTED_ESCAPE:
			parser->state = HTML_STATE_TAG_QUOTED;
			break;
		case HTML_STATE_IGNORE:
			if (c == '<') {
				parser->state = HTML_STATE_TAG;
				parser->ignore_next_text = FALSE;
			}
			break;
		case HTML_STATE_COMMENT:
			if (c == '-') {
				if (i+1 == size)
					return i;
				if (data[i+1] == '-') {
					parser->state = HTML_STATE_COMMENT_END;
					i++;
				}
			}
			break;
		case HTML_STATE_COMMENT_END:
			if (c == '>')
				parser->state = HTML_STATE_TEXT;
			else if (!HTML_WHITESPACE(c))
				parser->state = HTML_STATE_COMMENT;
			break;
		}
	}
	return i;
}

static void fts_parser_html_more(struct fts_parser *_parser,
				 struct message_block *block)
{
	struct html_fts_parser *parser = (struct html_fts_parser *)_parser;
	size_t size, buf_orig_size;

	buffer_set_used_size(parser->output, 0);

	if (parser->input->used > 0) {
		/* we didn't get enough input the last time to know
		   what to do. */
		buf_orig_size = parser->input->used;

		size = I_MIN(block->size, 128);
		buffer_append(parser->input, block->data, size);
		size = parse_data(parser, parser->input->data,
				  parser->input->used);
		if (size != 0) {
			i_assert(size >= buf_orig_size);
			block->data += size - buf_orig_size;
			block->size -= size - buf_orig_size;
		} else if (block->size != 0) {
			/* we're slowly parsing forward */
			return;
		} else {
			/* we're at EOF and can't finish this */
		}
		buffer_set_used_size(parser->input, 0);
	}
	size = parse_data(parser, block->data, block->size);
	buffer_append(parser->input, block->data + size, block->size - size);

	block->data = parser->output->data;
	block->size = parser->output->used;
}

static void fts_parser_html_deinit(struct fts_parser *_parser)
{
	struct html_fts_parser *parser = (struct html_fts_parser *)_parser;

	buffer_free(&parser->input);
	buffer_free(&parser->output);
	i_free(parser);
}

struct fts_parser_vfuncs fts_parser_html = {
	fts_parser_html_try_init,
	fts_parser_html_more,
	fts_parser_html_deinit
};
