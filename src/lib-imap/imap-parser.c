/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "ibuffer.h"
#include "obuffer.h"
#include "imap-parser.h"

#define is_linebreak(c) \
	((c) == '\r' || (c) == '\n')

#define LIST_ALLOC_SIZE 7

typedef enum {
	ARG_PARSE_NONE = 0,
	ARG_PARSE_ATOM,
	ARG_PARSE_STRING,
	ARG_PARSE_LITERAL,
	ARG_PARSE_LITERAL_DATA
} ArgParseType;

struct _ImapParser {
	/* permanent */
	Pool pool;
	IBuffer *inbuf;
	OBuffer *outbuf;
	size_t max_literal_size;
        ImapParserFlags flags;

	/* reset by imap_parser_reset(): */
        ImapArgList *root_list;
        ImapArgList *cur_list;
	ImapArg *list_arg;

	ArgParseType cur_type;
	size_t cur_pos; /* parser position in input buffer */

	int str_first_escape; /* ARG_PARSE_STRING: index to first '\' */
	uoff_t literal_size; /* ARG_PARSE_LITERAL: string size */

	unsigned int literal_skip_crlf:1;
	unsigned int inside_bracket:1;
	unsigned int eol:1;
	unsigned int error:1;
};

#define LIST_REALLOC(parser, old_list, size) \
	p_realloc((parser)->pool, old_list, \
		  sizeof(ImapArgList) + sizeof(ImapArg) * ((size)-1))

static void imap_args_realloc(ImapParser *parser, size_t size)
{
	parser->cur_list = LIST_REALLOC(parser, parser->cur_list, size);
	parser->cur_list->alloc = size;

	if (parser->list_arg == NULL)
		parser->root_list = parser->cur_list;
	else
		parser->list_arg->data.list = parser->cur_list;
}

ImapParser *imap_parser_create(IBuffer *inbuf, OBuffer *outbuf,
			       size_t max_literal_size)
{
	ImapParser *parser;

	parser = i_new(ImapParser, 1);
        parser->pool = pool_create("IMAP parser", 8192, FALSE);
	parser->inbuf = inbuf;
	parser->outbuf = outbuf;
	parser->max_literal_size = max_literal_size;

	imap_args_realloc(parser, LIST_ALLOC_SIZE);
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

	parser->root_list = NULL;
	parser->cur_list = NULL;
	parser->list_arg = NULL;

	parser->cur_type = ARG_PARSE_NONE;
	parser->cur_pos = 0;

	parser->str_first_escape = 0;
	parser->literal_size = 0;

	parser->literal_skip_crlf = FALSE;
	parser->inside_bracket = FALSE;
	parser->eol = FALSE;
	parser->error = FALSE;

	imap_args_realloc(parser, LIST_ALLOC_SIZE);
}

/* skip over everything parsed so far, plus the following whitespace */
static int imap_parser_skip_to_next(ImapParser *parser, const char **data,
				    size_t *data_size)
{
	size_t i;

	for (i = parser->cur_pos; i < *data_size; i++) {
		if ((*data)[i] != ' ')
			break;
	}

        i_buffer_skip(parser->inbuf, i);
	parser->cur_pos = 0;

	*data += i;
	*data_size -= i;
	return *data_size > 0;
}

static ImapArg *imap_arg_create(ImapParser *parser)
{
	ImapArg *arg;

	i_assert(parser->cur_list != NULL);

	if (parser->cur_list->size == parser->cur_list->alloc)
		imap_args_realloc(parser, parser->cur_list->alloc * 2);

	arg = &parser->cur_list->args[parser->cur_list->size];
	arg->parent = parser->list_arg;
	parser->cur_list->size++;

	return arg;
}

static void imap_parser_open_list(ImapParser *parser)
{
	parser->list_arg = imap_arg_create(parser);

	parser->cur_list = NULL;
	imap_args_realloc(parser, LIST_ALLOC_SIZE);

	parser->list_arg->type = IMAP_ARG_LIST;
	parser->list_arg->data.list = parser->cur_list;

	parser->cur_type = ARG_PARSE_NONE;
}

static int imap_parser_close_list(ImapParser *parser)
{
	ImapArg *arg;

	if (parser->list_arg == NULL) {
		/* we're not inside list */
		parser->error = TRUE;
		return FALSE;
	}

	arg = imap_arg_create(parser);
	arg->type = IMAP_ARG_EOL;
	parser->cur_list->size--; /* EOL doesn't belong to argument count */

	parser->list_arg = parser->list_arg->parent;
	if (parser->list_arg == NULL) {
		parser->cur_list = parser->root_list;
	} else {
		parser->cur_list = parser->list_arg->data.list;
	}

	parser->cur_type = ARG_PARSE_NONE;
	return TRUE;
}

static void imap_parser_save_arg(ImapParser *parser, const char *data,
				 size_t lastpos)
{
	ImapArg *arg;

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
		i_assert(lastpos > 0);

		arg->type = IMAP_ARG_STRING;
		arg->data.str = p_strndup(parser->pool, data+1, lastpos-1);

		/* remove the escapes */
		if (parser->str_first_escape >= 0 &&
		    (parser->flags & IMAP_PARSE_FLAG_NO_UNESCAPE) == 0) {
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
                i_unreached();
	}

	parser->cur_type = ARG_PARSE_NONE;
}

static int imap_parser_read_atom(ImapParser *parser, const char *data,
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
	return parser->cur_type == ARG_PARSE_NONE;
}

static int imap_parser_read_string(ImapParser *parser, const char *data,
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
	return parser->cur_type == ARG_PARSE_NONE;
}

static int imap_parser_literal_end(ImapParser *parser)
{
	if ((parser->flags & IMAP_PARSE_FLAG_LITERAL_SIZE) == 0) {
		if (parser->literal_size > parser->max_literal_size) {
			/* too long string, abort. */
			parser->error = TRUE;
			return FALSE;
		}

		if (parser->outbuf != NULL) {
			o_buffer_send(parser->outbuf, "+ OK\r\n", 6);
			o_buffer_flush(parser->outbuf);
		}
	}

	parser->cur_type = ARG_PARSE_LITERAL_DATA;
	parser->literal_skip_crlf = TRUE;

	parser->cur_pos = 0;
	return TRUE;
}

static int imap_parser_read_literal(ImapParser *parser, const char *data,
				    size_t data_size)
{
	size_t i, prev_size;

	/* expecting digits + "}" */
	for (i = parser->cur_pos; i < data_size; i++) {
		if (data[i] == '}') {
			i_buffer_skip(parser->inbuf, i+1);
			return imap_parser_literal_end(parser);
		}

		if (data[i] < '0' || data[i] > '9') {
			parser->error = TRUE;
			return FALSE;
		}

		prev_size = parser->literal_size;
		parser->literal_size = parser->literal_size*10 + (data[i]-'0');

		if (parser->literal_size < prev_size) {
			/* wrapped around, abort. */
			parser->error = TRUE;
			return FALSE;
		}
	}

	parser->cur_pos = i;
	return FALSE;
}

static int imap_parser_read_literal_data(ImapParser *parser, const char *data,
					 size_t data_size)
{
	if (parser->literal_skip_crlf) {
		/* skip \r\n or \n, anything else gives an error */
		if (data_size == 0)
			return FALSE;

		if (*data == '\r') {
			data++; data_size--;
			i_buffer_skip(parser->inbuf, 1);

			if (data_size == 0)
				return FALSE;
		}

		if (*data != '\n') {
			parser->error = TRUE;
			return FALSE;
		}

		data++; data_size--;
		i_buffer_skip(parser->inbuf, 1);
		parser->literal_skip_crlf = FALSE;

		i_assert(parser->cur_pos == 0);
	}

	if ((parser->flags & IMAP_PARSE_FLAG_LITERAL_SIZE) == 0) {
		/* now we just wait until we've read enough data */
		if (data_size < parser->literal_size)
			return FALSE;
		else {
			imap_parser_save_arg(parser, data,
					     (size_t)parser->literal_size);
			parser->cur_pos = (size_t)parser->literal_size;
			return TRUE;
		}
	} else {
		/* we want to save only literal size, not the literal itself. */
		imap_parser_save_arg(parser, NULL, 0);
		return TRUE;
	}
}

/* Returns TRUE if argument was fully processed. Also returns TRUE if
   an argument inside a list was processed. */
static int imap_parser_read_arg(ImapParser *parser)
{
	const char *data;
	size_t data_size;

	data = (const char *) i_buffer_get_data(parser->inbuf, &data_size);
	if (data_size == 0)
		return FALSE;

	while (parser->cur_type == ARG_PARSE_NONE) {
		/* we haven't started parsing yet */
		if (!imap_parser_skip_to_next(parser, &data, &data_size))
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

			if (parser->list_arg == NULL) {
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
		data = (const char *) i_buffer_get_data(parser->inbuf,
							&data_size);

		/* fall through */
	case ARG_PARSE_LITERAL_DATA:
		if (!imap_parser_read_literal_data(parser, data, data_size))
			return FALSE;
		break;
	default:
                i_unreached();
	}

	i_assert(parser->cur_type == ARG_PARSE_NONE);
	return TRUE;
}

#define IS_UNFINISHED(parser) \
        ((parser)->cur_type != ARG_PARSE_NONE || \
	 (parser)->cur_list != parser->root_list)

int imap_parser_read_args(ImapParser *parser, unsigned int count,
			  ImapParserFlags flags, ImapArg **args)
{
	parser->flags = flags;

	while (count == 0 || parser->root_list->size < count ||
	       IS_UNFINISHED(parser)) {
		if (!imap_parser_read_arg(parser))
			break;
	}

	if (parser->error) {
		/* error, abort */
		*args = NULL;
		return -1;
	} else if ((!IS_UNFINISHED(parser) && count > 0 &&
		    parser->root_list->size >= count) || parser->eol) {
		/* all arguments read / end of line. ARG_PARSE_NONE checks
		   that last argument isn't only partially parsed. */
		if (count >= parser->root_list->alloc) {
			/* unused arguments must be NIL-filled. */
			parser->root_list->alloc = count+1;
			parser->root_list = LIST_REALLOC(parser,
							 parser->root_list,
							 count+1);
		}

		parser->root_list->args[parser->root_list->size].type =
			IMAP_ARG_EOL;

		*args = parser->root_list->args;
		return parser->root_list->size;
	} else {
		/* need more data */
		*args = NULL;
		return -2;
	}
}

const char *imap_parser_read_word(ImapParser *parser)
{
	const char *data;
	size_t i, data_size;

	/* get the beginning of data in input buffer */
	data = (const char *) i_buffer_get_data(parser->inbuf, &data_size);

	for (i = 0; i < data_size; i++) {
		if (data[i] == ' ' || data[i] == '\r' || data[i] == '\n')
			break;
	}

	if (i < data_size) {
		i_buffer_skip(parser->inbuf, i + (data[i] == ' ' ? 1 : 0));
		return p_strndup(parser->pool, data, i);
	} else {
		return NULL;
	}
}

const char *imap_parser_read_line(ImapParser *parser)
{
	const char *data;
	size_t i, data_size;

	/* get the beginning of data in input buffer */
	data = (const char *) i_buffer_get_data(parser->inbuf, &data_size);

	for (i = 0; i < data_size; i++) {
		if (data[i] == '\r' || data[i] == '\n')
			break;
	}

	if (i < data_size) {
		i_buffer_skip(parser->inbuf, i);
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
