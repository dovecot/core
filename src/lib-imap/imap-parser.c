/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "imap-parser.h"

#define is_linebreak(c) \
	((c) == '\r' || (c) == '\n')

typedef enum {
	ARG_PARSE_NONE = 0,
	ARG_PARSE_ATOM,
	ARG_PARSE_STRING,
	ARG_PARSE_LITERAL,
	ARG_PARSE_LITERAL_DATA
} ArgParseType;

struct _ImapParser {
	Pool pool;
	IOBuffer *inbuf, *outbuf;

	unsigned int pos;
	ImapArg *args;

	ArgParseType cur_type;
	size_t cur_pos;
	ImapArg *cur_arg;

	ImapArg *cur_list_arg; /* argument which contains current list */
	ImapArgList **cur_list; /* pointer where to append next list item */

        ImapParserFlags flags;
	int str_first_escape; /* ARG_PARSE_STRING: index to first '\' */
	uoff_t literal_size; /* ARG_PARSE_LITERAL: string size */
	unsigned int literal_skip_crlf:1;

	unsigned int inside_bracket:1;
	unsigned int eol:1;
	unsigned int error:1;
};

ImapParser *imap_parser_create(IOBuffer *inbuf, IOBuffer *outbuf)
{
	ImapParser *parser;

	parser = i_new(ImapParser, 1);
	parser->pool = pool_create("IMAP parser", 8192, FALSE);
	parser->inbuf = inbuf;
	parser->outbuf = outbuf;
	return parser;
}

void imap_parser_destroy(ImapParser *parser)
{
	pool_unref(parser->pool);
	i_free(parser);
}

void imap_parser_reset(ImapParser *parser)
{
	p_clear(parser->pool);

	parser->pos = 0;
	parser->args = NULL;

	parser->cur_type = ARG_PARSE_NONE;
	parser->cur_pos = 0;
	parser->cur_arg = NULL;

	parser->cur_list_arg = NULL;
	parser->cur_list = NULL;

	parser->eol = FALSE;
	parser->error = FALSE;
}

static int imap_parser_skip_whitespace(ImapParser *parser, char **data,
				       size_t *data_size)
{
	size_t i;

	for (i = parser->cur_pos; i < *data_size; i++) {
		if ((*data)[i] != ' ')
			break;
	}

        io_buffer_skip(parser->inbuf, i);
	parser->cur_pos = 0;

	*data += i;
	*data_size -= i;
	return *data_size > 0;
}

static ImapArg *imap_arg_create(ImapParser *parser)
{
	ImapArgList *list;

	/* create new argument into list */
	i_assert(parser->cur_list != NULL);

	list = p_new(parser->pool, ImapArgList, 1);
	*parser->cur_list = list;
	parser->cur_list = &list->next;

	return &list->arg;
}

static void imap_parser_open_list(ImapParser *parser)
{
	if (parser->cur_arg == NULL)
		parser->cur_arg = imap_arg_create(parser);

	parser->cur_arg->type = IMAP_ARG_LIST;
	parser->cur_list = &parser->cur_arg->data.list;
	parser->cur_list_arg = parser->cur_arg;

	parser->cur_type = ARG_PARSE_NONE;
	parser->cur_arg = NULL;
}

static int imap_parser_close_list(ImapParser *parser)
{
	ImapArgList **list;

	if (parser->cur_list_arg == NULL) {
		/* we're not inside list */
		parser->error = TRUE;
		return FALSE;
	}

	parser->cur_list_arg = parser->cur_list_arg->parent;
	if (parser->cur_list_arg == NULL) {
		/* end of argument */
		parser->cur_list = NULL;
		return TRUE;
	}

	/* skip to end of the upper list */
        list = &parser->cur_list_arg->data.list;
	while (*list != NULL)
		list = &(*list)->next;
	parser->cur_list = list;

	parser->cur_type = ARG_PARSE_NONE;
	parser->cur_arg = NULL;

	return TRUE;
}

static void imap_parser_save_arg(ImapParser *parser, char *data,
				 size_t lastpos)
{
	ImapArg *arg;

	arg = parser->cur_arg;
	if (arg == NULL)
		arg = imap_arg_create(parser);

	switch (parser->cur_type) {
	case ARG_PARSE_ATOM:
		if (lastpos == 3 && strncmp(data, "NIL", 3) == 0) {
			/* NIL argument */
			arg->type = IMAP_ARG_NIL;
		} else {
			/* simply save the string */
			arg->type = IMAP_ARG_ATOM;
			arg->data.str = p_strndup(parser->pool, data, lastpos);
		}
		break;
	case ARG_PARSE_STRING:
		/* data is quoted and may contain escapes. */
		arg->type = IMAP_ARG_STRING;
		arg->data.str = p_strndup(parser->pool, data+1, lastpos-1);

		/* remove the escapes */
		if (parser->str_first_escape >= 0) {
			/* -1 because we skipped the '"' prefix */
			string_remove_escapes(arg->data.str +
					      parser->str_first_escape-1);
		}
		break;
	case ARG_PARSE_LITERAL_DATA:
		if ((parser->flags & IMAP_PARSE_FLAG_LITERAL_SIZE) == 0) {
			/* simply save the string */
			arg->type = IMAP_ARG_STRING;
			arg->data.str = p_strndup(parser->pool, data, lastpos);
		} else {
			/* save literal size */
			arg->type = IMAP_ARG_LITERAL_SIZE;
			arg->data.literal_size = parser->literal_size;
		}
		break;
	default:
		i_assert(0);
	}

	parser->cur_arg = NULL;
        parser->cur_type = ARG_PARSE_NONE;
}

static int imap_parser_read_atom(ImapParser *parser, char *data,
				 size_t data_size)
{
	size_t i;

	/* read until we've found space, CR or LF. Data inside '[' and ']'
	   characters are an exception though, allow spaces inside them. */
	for (i = parser->cur_pos; i < data_size; i++) {
		if (parser->inside_bracket) {
			if (data[i] == '[' || is_linebreak(data[i])) {
				/* a) nested '[' characters not allowed
				      (too much trouble and imap doesn't need)
				   b) missing ']' character */
				parser->error = TRUE;
				return FALSE;
			}

			if (data[i] == ']') {
				parser->inside_bracket = FALSE;
			}
		} else {
			if (data[i] == '[')
				parser->inside_bracket = TRUE;
			else if (data[i] == ' ' || data[i] == ')' ||
				 is_linebreak(data[i])) {
				imap_parser_save_arg(parser, data, i);
				break;
			}
		}
	}

	parser->cur_pos = i;
	return TRUE;
}

static int imap_parser_read_string(ImapParser *parser, char *data,
				   size_t data_size)
{
	size_t i;

	/* read until we've found non-escaped ", CR or LF */
	for (i = parser->cur_pos; i < data_size; i++) {
		if (data[i] == '"') {
			imap_parser_save_arg(parser, data, i);

			i++; /* skip the trailing '"' too */
			break;
		}

		if (data[i] == '\\') {
			if (i+1 == data_size) {
				/* known data ends with '\' - leave it to
				   next time as well if it happens to be \" */
				break;
			}

			/* save the first escaped char */
			if (parser->str_first_escape < 0)
				parser->str_first_escape = i;

			/* skip the escaped char */
			i++;
		}

		/* check linebreaks here, so escaping CR/LF isn't possible.
		   string always ends with '"', so it's an error if we found
		   a linebreak.. */
		if (is_linebreak(data[i])) {
			parser->error = TRUE;
			return FALSE;
		}
	}

	parser->cur_pos = i;
	return TRUE;
}

static int imap_parser_literal_end(ImapParser *parser)
{
	if ((parser->flags & IMAP_PARSE_FLAG_LITERAL_SIZE) == 0) {
		if (parser->literal_size > parser->inbuf->max_buffer_size) {
			/* too long string, abort. */
			parser->error = TRUE;
			return FALSE;
		}

		io_buffer_send(parser->outbuf, "+ OK\r\n", 6);
		io_buffer_send_flush(parser->outbuf);
	}

	parser->cur_type = ARG_PARSE_LITERAL_DATA;
	parser->literal_skip_crlf = TRUE;

	parser->cur_pos = 0;
	return TRUE;
}

static int imap_parser_read_literal(ImapParser *parser, char *data,
				    size_t data_size)
{
	size_t i, prev_size;

	/* expecting digits + "}" */
	for (i = parser->cur_pos; i < data_size; i++) {
		if (data[i] == '}') {
			io_buffer_skip(parser->inbuf, i+1);
			if (!imap_parser_literal_end(parser))
				return FALSE;
			break;
		}

		if (data[i] < '0' || data[i] > '9')
			return FALSE;

		prev_size = parser->literal_size;
		parser->literal_size = parser->literal_size*10 + (data[i]-'0');

		if (parser->literal_size < prev_size) {
			/* wrapped around, abort. */
			parser->error = TRUE;
			return FALSE;
		}
	}

	return TRUE;
}

static int imap_parser_read_literal_data(ImapParser *parser, char *data,
					 size_t data_size)
{
	if (parser->literal_skip_crlf) {
		/* skip \r\n or \n, anything else gives an error */
		if (*data == '\r') {
			if (data_size == 1)
				return TRUE;

			data++; data_size--;
			io_buffer_skip(parser->inbuf, 1);
		}

		if (*data != '\n')
			return FALSE;

		data++; data_size--;
		io_buffer_skip(parser->inbuf, 1);
		parser->literal_skip_crlf = FALSE;

		i_assert(parser->cur_pos == 0);
	}

	if ((parser->flags & IMAP_PARSE_FLAG_LITERAL_SIZE) == 0) {
		/* now we just wait until we've read enough data */
		if (data_size >= parser->literal_size) {
			imap_parser_save_arg(parser, data,
					     (size_t)parser->literal_size);
			parser->cur_pos = (size_t) parser->literal_size;
		}
	} else {
		/* we want to save only literal size, not the literal itself. */
		imap_parser_save_arg(parser, NULL, 0);
	}

	return TRUE;
}

/* Returns TRUE if argument was fully processed. Also returns TRUE if
   an argument inside a list was processed. */
static int imap_parser_read_arg(ImapParser *parser, ImapArg *root_arg)
{
	char *data;
	size_t data_size;

	data = (char *) io_buffer_get_data(parser->inbuf, &data_size);
	if (data_size == 0)
		return FALSE;

	if (parser->cur_arg == NULL && parser->cur_list == NULL) {
		/* beginning to parse a new argument */
		parser->cur_arg = root_arg;
	}

	while (parser->cur_type == ARG_PARSE_NONE) {
		/* we haven't started parsing yet */
		if (!imap_parser_skip_whitespace(parser, &data, &data_size))
			return FALSE;
		i_assert(parser->cur_pos == 0);

		switch (data[0]) {
		case '\r':
		case '\n':
			/* unexpected end of line */
			parser->eol = TRUE;
			return FALSE;
		case '"':
			parser->cur_type = ARG_PARSE_STRING;
			parser->str_first_escape = -1;
			break;
		case '{':
			parser->cur_type = ARG_PARSE_LITERAL;
			parser->literal_size = 0;
			break;
		case '(':
			imap_parser_open_list(parser);
			break;
		case ')':
			if (!imap_parser_close_list(parser))
				return FALSE;

			if (parser->cur_list_arg == NULL) {
				/* end of argument */
				parser->cur_pos++;
				return TRUE;
			}
			break;
		default:
			parser->cur_type = ARG_PARSE_ATOM;
                        parser->inside_bracket = FALSE;
			break;
		}

		parser->cur_pos++;
	}

	i_assert(data_size > 0);

	switch (parser->cur_type) {
	case ARG_PARSE_ATOM:
		if (!imap_parser_read_atom(parser, data, data_size))
			return FALSE;
		break;
	case ARG_PARSE_STRING:
		if (!imap_parser_read_string(parser, data, data_size))
			return FALSE;
		break;
	case ARG_PARSE_LITERAL:
		if (!imap_parser_read_literal(parser, data, data_size))
			return FALSE;

		/* pass through to parsing data. since inbuf->skip was
		   modified, we need to get the data start position again. */
		data = io_buffer_get_data(parser->inbuf, &data_size);
	case ARG_PARSE_LITERAL_DATA:
		imap_parser_read_literal_data(parser, data, data_size);
		break;
	default:
		i_assert(0);
	}

	/* NOTE: data and data_size are invalid here, the functions above
	   may have changed them. */

	return parser->cur_type == ARG_PARSE_NONE;
}

int imap_parser_read_args(ImapParser *parser, unsigned int count,
			  ImapParserFlags flags, ImapArg **args)
{
	unsigned int args_size;

	parser->flags = flags;

	args_size = 0;
	while (count == 0 || parser->pos < count) {
		if (parser->pos >= args_size) {
			args_size = nearest_power(parser->pos);
			if (args_size < 8) args_size = 8;

			parser->args =
				p_realloc_min(parser->pool, parser->args,
					      args_size * sizeof(ImapArg));
		}

		if (!imap_parser_read_arg(parser, &parser->args[parser->pos]))
			break;

		/* jump to next argument, unless we're processing a list */
		if (parser->cur_list == NULL)
			parser->pos++;
	}

	if (parser->pos >= count || parser->eol) {
		/* all arguments read / end of line */
		*args = parser->args;
		return count == 0 || parser->pos < count ? parser->pos : count;
	} else if (parser->error) {
		/* error, abort */
		*args = NULL;
		return -1;
	} else {
		/* need more data */
		*args = NULL;
		return -2;
	}
}

const char *imap_parser_read_word(ImapParser *parser)
{
	unsigned char *data;
	size_t i, data_size;

	/* get the beginning of data in input buffer */
	data = io_buffer_get_data(parser->inbuf, &data_size);

	for (i = 0; i < data_size; i++) {
		if (data[i] == ' ' || data[i] == '\r' || data[i] == '\n')
			break;
	}

	if (i < data_size) {
		io_buffer_skip(parser->inbuf, i + (data[i] == ' ' ? 1 : 0));
		return p_strndup(parser->pool, data, i);
	} else {
		return NULL;
	}
}

const char *imap_parser_read_line(ImapParser *parser)
{
	unsigned char *data;
	size_t i, data_size;

	/* get the beginning of data in input buffer */
	data = io_buffer_get_data(parser->inbuf, &data_size);

	for (i = 0; i < data_size; i++) {
		if (data[i] == '\r' || data[i] == '\n')
			break;
	}

	if (i < data_size) {
		io_buffer_skip(parser->inbuf, i);
		return p_strndup(parser->pool, data, i);
	} else {
		return NULL;
	}
}

const char *imap_arg_string(ImapArg *arg)
{
	switch (arg->type) {
	case IMAP_ARG_NIL:
		return "";

	case IMAP_ARG_ATOM:
	case IMAP_ARG_STRING:
		return arg->data.str;

	default:
		return NULL;
	}
}
