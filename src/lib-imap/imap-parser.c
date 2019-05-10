/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "strescape.h"
#include "imap-parser.h"

/* We use this macro to read atoms from input. It should probably contain
   everything some day, but for now we can't handle some input otherwise:

   ']' is required for parsing section (FETCH BODY[])
   '%', '*' and ']' are valid list-chars for LIST patterns
   '\' is used in flags */
#define IS_ATOM_PARSER_INPUT(c) \
	((c) == '(' || (c) == ')' || (c) == '{' || \
	 (c) == '"' || (c) <= 32 || (c) == 0x7f)

#define is_linebreak(c) \
	((c) == '\r' || (c) == '\n')

#define LIST_INIT_COUNT 7

enum arg_parse_type {
	ARG_PARSE_NONE = 0,
	ARG_PARSE_ATOM,
	ARG_PARSE_STRING,
	ARG_PARSE_LITERAL,
	ARG_PARSE_LITERAL8,
	ARG_PARSE_LITERAL_DATA,
	ARG_PARSE_LITERAL_DATA_FORCED,
	ARG_PARSE_TEXT
};

struct imap_parser {
	/* permanent */
	int refcount;
	pool_t pool;
	struct istream *input;
	struct ostream *output;
	size_t max_line_size;
        enum imap_parser_flags flags;

	/* reset by imap_parser_reset(): */
	size_t line_size;
	ARRAY_TYPE(imap_arg_list) root_list;
        ARRAY_TYPE(imap_arg_list) *cur_list;
	struct imap_arg *list_arg;

	enum arg_parse_type cur_type;
	size_t cur_pos; /* parser position in input buffer */
	bool cur_resp_text; /* we're parsing [resp-text-code] */

	int str_first_escape; /* ARG_PARSE_STRING: index to first '\' */
	uoff_t literal_size; /* ARG_PARSE_LITERAL: string size */

	enum imap_parser_error error;
	const char *error_msg;

	bool literal_minus:1;
	bool literal_skip_crlf:1;
	bool literal_nonsync:1;
	bool literal8:1;
	bool literal_size_return:1;
	bool eol:1;
	bool args_added_extra_eol:1;
	bool fatal_error:1;
};

struct imap_parser *
imap_parser_create(struct istream *input, struct ostream *output,
		   size_t max_line_size)
{
	struct imap_parser *parser;

	parser = i_new(struct imap_parser, 1);
	parser->refcount = 1;
	parser->pool = pool_alloconly_create(MEMPOOL_GROWING"IMAP parser",
					     1024);
	parser->input = input;
	parser->output = output;
	parser->max_line_size = max_line_size;

	p_array_init(&parser->root_list, parser->pool, LIST_INIT_COUNT);
	parser->cur_list = &parser->root_list;
	return parser;
}

void imap_parser_ref(struct imap_parser *parser)
{
	i_assert(parser->refcount > 0);

	parser->refcount++;
}

void imap_parser_unref(struct imap_parser **_parser)
{
	struct imap_parser *parser = *_parser;

	*_parser = NULL;

	i_assert(parser->refcount > 0);
	if (--parser->refcount > 0)
		return;

	pool_unref(&parser->pool);
	i_free(parser);
}

void imap_parser_enable_literal_minus(struct imap_parser *parser)
{
	parser->literal_minus = TRUE;
}

void imap_parser_reset(struct imap_parser *parser)
{
	p_clear(parser->pool);

	parser->line_size = 0;

	p_array_init(&parser->root_list, parser->pool, LIST_INIT_COUNT);
	parser->cur_list = &parser->root_list;
	parser->list_arg = NULL;

	parser->cur_type = ARG_PARSE_NONE;
	parser->cur_pos = 0;
	parser->cur_resp_text = FALSE;

	parser->str_first_escape = 0;
	parser->literal_size = 0;

	parser->error = IMAP_PARSE_ERROR_NONE;
	parser->error_msg = NULL;

	parser->literal_skip_crlf = FALSE;
	parser->eol = FALSE;
	parser->args_added_extra_eol = FALSE;
	parser->literal_size_return = FALSE;
}

void imap_parser_set_streams(struct imap_parser *parser, struct istream *input,
			     struct ostream *output)
{
	parser->input = input;
	parser->output = output;
}

const char *imap_parser_get_error(struct imap_parser *parser,
	enum imap_parser_error *error_r)
{
	if (error_r != NULL)
		*error_r = parser->error;
	return parser->error_msg;
}

/* skip over everything parsed so far, plus the following whitespace */
static bool imap_parser_skip_to_next(struct imap_parser *parser,
				     const unsigned char **data,
				     size_t *data_size)
{
	size_t i;

	for (i = parser->cur_pos; i < *data_size; i++) {
		if ((*data)[i] != ' ')
			break;
	}

	parser->line_size += i;
        i_stream_skip(parser->input, i);
	parser->cur_pos = 0;

	*data += i;
	*data_size -= i;
	return *data_size > 0;
}

static struct imap_arg *imap_arg_create(struct imap_parser *parser)
{
	struct imap_arg *arg;

	arg = array_append_space(parser->cur_list);
	arg->parent = parser->list_arg;
	return arg;
}

static void imap_parser_open_list(struct imap_parser *parser)
{
	parser->list_arg = imap_arg_create(parser);
	parser->list_arg->type = IMAP_ARG_LIST;
	p_array_init(&parser->list_arg->_data.list, parser->pool,
		     LIST_INIT_COUNT);
	parser->cur_list = &parser->list_arg->_data.list;

	parser->cur_type = ARG_PARSE_NONE;
}

static bool imap_parser_close_list(struct imap_parser *parser)
{
	struct imap_arg *arg;

	if (parser->list_arg == NULL) {
		/* we're not inside list */
		if ((parser->flags & IMAP_PARSE_FLAG_INSIDE_LIST) != 0) {
			parser->eol = TRUE;
			parser->cur_type = ARG_PARSE_NONE;
			return TRUE;
		}
		parser->error_msg = "Unexpected ')'";
		parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
		return FALSE;
	}

	arg = imap_arg_create(parser);
	arg->type = IMAP_ARG_EOL;

	parser->list_arg = parser->list_arg->parent;
	if (parser->list_arg == NULL) {
		parser->cur_list = &parser->root_list;
	} else {
		parser->cur_list = &parser->list_arg->_data.list;
	}

	parser->cur_type = ARG_PARSE_NONE;
	return TRUE;
}

static char *
imap_parser_strdup(struct imap_parser *parser,
		   const void *data, size_t len)
{
	char *ret;

	ret = p_malloc(parser->pool, len + 1);
	memcpy(ret, data, len);
	return ret;
}

static void imap_parser_save_arg(struct imap_parser *parser,
				 const unsigned char *data, size_t size)
{
	struct imap_arg *arg;
	char *str;

	arg = imap_arg_create(parser);

	switch (parser->cur_type) {
	case ARG_PARSE_ATOM:
	case ARG_PARSE_TEXT:
		if (size == 3 && i_memcasecmp(data, "NIL", 3) == 0) {
			/* NIL argument. it might be an actual NIL, but if
			   we're reading astring, it's an atom and we can't
			   lose its case. */
			arg->type = IMAP_ARG_NIL;
		} else {
			/* simply save the string */
			arg->type = IMAP_ARG_ATOM;
		}
		arg->_data.str = imap_parser_strdup(parser, data, size);
		arg->str_len = size;
		break;
	case ARG_PARSE_STRING:
		/* data is quoted and may contain escapes. */
		i_assert(size > 0);

		arg->type = IMAP_ARG_STRING;
		str = p_strndup(parser->pool, data+1, size-1);

		/* remove the escapes */
		if (parser->str_first_escape >= 0 &&
		    (parser->flags & IMAP_PARSE_FLAG_NO_UNESCAPE) == 0) {
			/* -1 because we skipped the '"' prefix */
			(void)str_unescape(str + parser->str_first_escape-1);
		}
		arg->_data.str = str;
		arg->str_len = strlen(str);
		break;
	case ARG_PARSE_LITERAL_DATA:
		if ((parser->flags & IMAP_PARSE_FLAG_LITERAL_SIZE) != 0) {
			/* save literal size */
			arg->type = parser->literal_nonsync ?
				IMAP_ARG_LITERAL_SIZE_NONSYNC :
				IMAP_ARG_LITERAL_SIZE;
			arg->_data.literal_size = parser->literal_size;
			arg->literal8 = parser->literal8;
			break;
		}
		/* fall through */
	case ARG_PARSE_LITERAL_DATA_FORCED:
		if ((parser->flags & IMAP_PARSE_FLAG_LITERAL_TYPE) != 0)
			arg->type = IMAP_ARG_LITERAL;
		else
			arg->type = IMAP_ARG_STRING;
		arg->_data.str = imap_parser_strdup(parser, data, size);
		arg->literal8 = parser->literal8;
		arg->str_len = size;
		break;
	default:
                i_unreached();
	}

	parser->cur_type = ARG_PARSE_NONE;
}

static bool is_valid_atom_char(struct imap_parser *parser, char chr)
{
	const char *error_msg;

	if (IS_ATOM_PARSER_INPUT((unsigned char)chr))
		error_msg = "Invalid characters in atom";
	else if ((chr & 0x80) != 0)
		error_msg = "8bit data in atom";
	else
		return TRUE;

	if ((parser->flags & IMAP_PARSE_FLAG_ATOM_ALLCHARS) != 0)
		return TRUE;
	parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
	parser->error_msg = error_msg;
	return FALSE;
}

static bool imap_parser_read_atom(struct imap_parser *parser,
				  const unsigned char *data, size_t data_size)
{
	size_t i;

	/* read until we've found space, CR or LF. */
	for (i = parser->cur_pos; i < data_size; i++) {
		if (data[i] == ' ' || is_linebreak(data[i])) {
			imap_parser_save_arg(parser, data, i);
			break;
		} else if (data[i] == ')') {
			if (parser->list_arg != NULL ||
			    (parser->flags & IMAP_PARSE_FLAG_INSIDE_LIST) != 0) {
				imap_parser_save_arg(parser, data, i);
				break;
			} else if ((parser->flags &
				    IMAP_PARSE_FLAG_ATOM_ALLCHARS) == 0) {
				parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
				parser->error_msg = "Unexpected ')'";
				return FALSE;
			}
			/* assume it's part of the atom */
		} else if (!is_valid_atom_char(parser, data[i]))
			return FALSE;
	}

	parser->cur_pos = i;
	return parser->cur_type == ARG_PARSE_NONE;
}

static bool imap_parser_read_string(struct imap_parser *parser,
				    const unsigned char *data, size_t data_size)
{
	size_t i;

	/* read until we've found non-escaped ", CR or LF */
	for (i = parser->cur_pos; i < data_size; i++) {
		if (data[i] == '"') {
			imap_parser_save_arg(parser, data, i);

			i++; /* skip the trailing '"' too */
			break;
		}

		if (data[i] == '\0') {
			parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
			parser->error_msg = "NULs not allowed in strings";
			return FALSE;
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
		if (is_linebreak(data[i]) &&
		    (parser->flags & IMAP_PARSE_FLAG_MULTILINE_STR) == 0) {
			parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
			parser->error_msg = "Missing '\"'";
			return FALSE;
		}
	}

	parser->cur_pos = i;
	return parser->cur_type == ARG_PARSE_NONE;
}

static bool imap_parser_literal_end(struct imap_parser *parser)
{
	if (parser->literal_minus && parser->literal_nonsync &&
		parser->literal_size > 4096) {
		parser->error_msg = "Non-synchronizing literal size too large";
		parser->error = IMAP_PARSE_ERROR_LITERAL_TOO_BIG;
		return FALSE;
	}

	if ((parser->flags & IMAP_PARSE_FLAG_LITERAL_SIZE) == 0) {
		if (parser->line_size >= parser->max_line_size ||
		    parser->literal_size >
		    parser->max_line_size - parser->line_size) {
			/* too long string, abort. */
			parser->error = IMAP_PARSE_ERROR_LITERAL_TOO_BIG;
			parser->error_msg = "Literal size too large";
			return FALSE;
		}

		if (parser->output != NULL && !parser->literal_nonsync) {
			o_stream_nsend(parser->output, "+ OK\r\n", 6);
			if (o_stream_is_corked(parser->output)) {
				/* make sure this continuation is sent to the
				   client as soon as possible */
				o_stream_uncork(parser->output);
				o_stream_cork(parser->output);
			}
		}
	}

	parser->cur_type = ARG_PARSE_LITERAL_DATA;
	parser->literal_skip_crlf = TRUE;

	parser->cur_pos = 0;
	return TRUE;
}

static bool imap_parser_read_literal(struct imap_parser *parser,
				     const unsigned char *data,
				     size_t data_size)
{
	size_t i, prev_size;

	/* expecting digits + "}" */
	for (i = parser->cur_pos; i < data_size; i++) {
		if (data[i] == '}') {
			parser->line_size += i+1;
			i_stream_skip(parser->input, i+1);
			return imap_parser_literal_end(parser);
		}

		if (parser->literal_nonsync) {
			parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
			parser->error_msg = "Expecting '}' after '+'";
			return FALSE;
		}

		if (data[i] == '+') {
			parser->literal_nonsync = TRUE;
			continue;
		}

		if (data[i] < '0' || data[i] > '9') {
			parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
			parser->error_msg = "Invalid literal size";
			return FALSE;
		}

		prev_size = parser->literal_size;
		parser->literal_size = parser->literal_size*10 + (data[i]-'0');

		if (parser->literal_size < prev_size) {
			/* wrapped around, abort. */
			parser->error = IMAP_PARSE_ERROR_LITERAL_TOO_BIG;
			parser->error_msg = "Literal size too large";
			return FALSE;
		}
	}

	parser->cur_pos = i;
	return FALSE;
}

static bool imap_parser_read_literal_data(struct imap_parser *parser,
					  const unsigned char *data,
					  size_t data_size)
{
	if (parser->literal_skip_crlf) {
		/* skip \r\n or \n, anything else gives an error */
		if (data_size == 0)
			return FALSE;

		if (*data == '\r') {
			parser->line_size++;
			data++; data_size--;
			i_stream_skip(parser->input, 1);

			if (data_size == 0)
				return FALSE;
		}

		if (*data != '\n') {
			parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
			parser->error_msg = "Missing LF after literal size";
			return FALSE;
		}

		parser->line_size++;
		data++; data_size--;
		i_stream_skip(parser->input, 1);

		parser->literal_skip_crlf = FALSE;

		i_assert(parser->cur_pos == 0);
	}

	if ((parser->flags & IMAP_PARSE_FLAG_LITERAL_SIZE) == 0 ||
	    parser->cur_type == ARG_PARSE_LITERAL_DATA_FORCED) {
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
		parser->literal_size_return = TRUE;
		imap_parser_save_arg(parser, uchar_empty_ptr, 0);
		return FALSE;
	}
}

static bool imap_parser_is_next_resp_text(struct imap_parser *parser)
{
	const struct imap_arg *arg;

	if (parser->cur_list != &parser->root_list ||
	    array_count(parser->cur_list) != 1)
		return FALSE;

	arg = array_front(&parser->root_list);
	if (arg->type != IMAP_ARG_ATOM)
		return FALSE;

	return strcasecmp(arg->_data.str, "OK") == 0 ||
		strcasecmp(arg->_data.str, "NO") == 0 ||
		strcasecmp(arg->_data.str, "BAD") == 0 ||
		strcasecmp(arg->_data.str, "BYE") == 0;
}

static bool imap_parser_is_next_text(struct imap_parser *parser)
{
	const struct imap_arg *arg;
	size_t len;

	if (parser->cur_list != &parser->root_list)
		return FALSE;

	arg = array_back(&parser->root_list);
	if (arg->type != IMAP_ARG_ATOM)
		return FALSE;

	len = strlen(arg->_data.str);
	return len > 0 && arg->_data.str[len-1] == ']';
}

static bool imap_parser_read_text(struct imap_parser *parser,
				  const unsigned char *data, size_t data_size)
{
	size_t i;

	/* read until end of line */
	for (i = parser->cur_pos; i < data_size; i++) {
		if (is_linebreak(data[i])) {
			imap_parser_save_arg(parser, data, i);
			break;
		}
	}
	parser->cur_pos = i;
	return parser->cur_type == ARG_PARSE_NONE;
}

/* Returns TRUE if argument was fully processed. Also returns TRUE if
   an argument inside a list was processed. */
static bool imap_parser_read_arg(struct imap_parser *parser)
{
	const unsigned char *data;
	size_t data_size;

	data = i_stream_get_data(parser->input, &data_size);
	if (data_size == 0)
		return FALSE;

	while (parser->cur_type == ARG_PARSE_NONE) {
		/* we haven't started parsing yet */
		if (!imap_parser_skip_to_next(parser, &data, &data_size))
			return FALSE;
		i_assert(parser->cur_pos == 0);

		if (parser->cur_resp_text &&
		    imap_parser_is_next_text(parser)) {
			/* we just parsed [resp-text-code] */
			parser->cur_type = ARG_PARSE_TEXT;
			break;
		}

		switch (data[0]) {
		case '\r':
			if (data_size == 1) {
				/* wait for LF */
				return FALSE;
			}
			if (data[1] != '\n') {
				parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
				parser->error_msg = "CR sent without LF";
				return FALSE;
			}
			/* fall through */
		case '\n':
			/* unexpected end of line */
			if ((parser->flags & IMAP_PARSE_FLAG_INSIDE_LIST) != 0) {
				parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
				parser->error_msg = "Missing ')'";
				return FALSE;
			}
			parser->eol = TRUE;
			return FALSE;
		case '"':
			parser->cur_type = ARG_PARSE_STRING;
			parser->str_first_escape = -1;
			break;
		case '~':
			/* This could be either literal8 or atom */
			if (data_size == 1) {
				/* wait for the next char */
				return FALSE;
			}
			if (data[1] != '{') {
				parser->cur_type = ARG_PARSE_ATOM;
				break;
			}
			if ((parser->flags & IMAP_PARSE_FLAG_LITERAL8) == 0) {
				parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
				parser->error_msg = "literal8 not allowed here";
				return FALSE;
			}
			parser->cur_type = ARG_PARSE_LITERAL8;
			parser->literal_size = 0;
			parser->literal_nonsync = FALSE;
			parser->literal8 = TRUE;
			break;
		case '{':
			parser->cur_type = ARG_PARSE_LITERAL;
			parser->literal_size = 0;
			parser->literal_nonsync = FALSE;
			parser->literal8 = FALSE;
			break;
		case '(':
			imap_parser_open_list(parser);
			if ((parser->flags & IMAP_PARSE_FLAG_STOP_AT_LIST) != 0) {
				i_stream_skip(parser->input, 1);
				return FALSE;
			}
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
			if (!is_valid_atom_char(parser, data[0]))
				return FALSE;
			parser->cur_type = ARG_PARSE_ATOM;
			break;
		}

		parser->cur_pos++;
	}

	i_assert(data_size > 0);

	switch (parser->cur_type) {
	case ARG_PARSE_ATOM:
		if (!imap_parser_read_atom(parser, data, data_size))
			return FALSE;
		if ((parser->flags & IMAP_PARSE_FLAG_SERVER_TEXT) == 0)
			break;

		if (imap_parser_is_next_resp_text(parser)) {
			/* we just parsed OK/NO/BAD/BYE. after parsing the
			   [resp-text-code] the rest of the message can contain
			   pretty much any random text, which we can't parse
			   as if it was valid IMAP input */
			parser->cur_resp_text = TRUE;
		}
		break;
	case ARG_PARSE_STRING:
		if (!imap_parser_read_string(parser, data, data_size))
			return FALSE;
		break;
	case ARG_PARSE_LITERAL8:
		if (parser->cur_pos == data_size)
			return FALSE;
		if (data[parser->cur_pos] != '{') {
			parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
			parser->error_msg = "Expected '{'";
			return FALSE;
		}
		parser->cur_type = ARG_PARSE_LITERAL;
		parser->cur_pos++;
		/* fall through */
	case ARG_PARSE_LITERAL:
		if (!imap_parser_read_literal(parser, data, data_size))
			return FALSE;

		/* pass through to parsing data. since input->skip was
		   modified, we need to get the data start position again. */
		data = i_stream_get_data(parser->input, &data_size);

		/* fall through */
	case ARG_PARSE_LITERAL_DATA:
	case ARG_PARSE_LITERAL_DATA_FORCED:
		if (!imap_parser_read_literal_data(parser, data, data_size))
			return FALSE;
		break;
	case ARG_PARSE_TEXT:
		if (!imap_parser_read_text(parser, data, data_size))
			return FALSE;
		break;
	default:
                i_unreached();
	}

	i_assert(parser->cur_type == ARG_PARSE_NONE);
	return TRUE;
}

/* ARG_PARSE_NONE checks that last argument isn't only partially parsed. */
#define IS_UNFINISHED(parser) \
        ((parser)->cur_type != ARG_PARSE_NONE || \
	 ((parser)->cur_list != &parser->root_list && \
	 ((parser)->flags & IMAP_PARSE_FLAG_STOP_AT_LIST) == 0))

static int finish_line(struct imap_parser *parser, unsigned int count,
		       const struct imap_arg **args_r)
{
	struct imap_arg *arg;
	int ret = array_count(&parser->root_list);

	parser->line_size += parser->cur_pos;
	i_stream_skip(parser->input, parser->cur_pos);
	parser->cur_pos = 0;
	parser->cur_resp_text = FALSE;

	if (parser->list_arg != NULL && !parser->literal_size_return &&
	    (parser->flags & IMAP_PARSE_FLAG_STOP_AT_LIST) == 0) {
		parser->error = IMAP_PARSE_ERROR_BAD_SYNTAX;
		parser->error_msg = "Missing ')'";
		*args_r = NULL;
		return -1;
	}

	arg = array_append_space(&parser->root_list);
	arg->type = IMAP_ARG_EOL;
	parser->args_added_extra_eol = TRUE;

	*args_r = array_get(&parser->root_list, &count);
	return ret;
}

int imap_parser_read_args(struct imap_parser *parser, unsigned int count,
			  enum imap_parser_flags flags,
			  const struct imap_arg **args_r)
{
	parser->flags = flags;

	if (parser->args_added_extra_eol) {
		/* delete EOL */
		array_pop_back(&parser->root_list);
		parser->args_added_extra_eol = FALSE;
		parser->literal_size_return = FALSE;
	}

	while (!parser->eol && (count == 0 || IS_UNFINISHED(parser) ||
				array_count(&parser->root_list) < count)) {
		if (!imap_parser_read_arg(parser))
			break;

		if (parser->line_size > parser->max_line_size) {
			parser->error = IMAP_PARSE_ERROR_LINE_TOO_LONG;
			parser->error_msg = "IMAP command line too large";
			break;
		}
	}

	if (parser->error != IMAP_PARSE_ERROR_NONE) {
		/* error, abort */
		parser->line_size += parser->cur_pos;
		i_stream_skip(parser->input, parser->cur_pos);
		parser->cur_pos = 0;
		*args_r = NULL;
		return -1;
	} else if ((!IS_UNFINISHED(parser) && count > 0 &&
		    array_count(&parser->root_list) >= count) ||
		   parser->eol || parser->literal_size_return) {
		/* all arguments read / end of line. */
                return finish_line(parser, count, args_r);
	} else {
		/* need more data */
		*args_r = NULL;
		return -2;
	}
}

static struct imap_arg *
imap_parser_get_last_literal_size(struct imap_parser *parser,
				  ARRAY_TYPE(imap_arg_list) **list_r)
{
	ARRAY_TYPE(imap_arg_list) *list;
	struct imap_arg *args;
	unsigned int count;

	list = &parser->root_list;
	args = array_get_modifiable(&parser->root_list, &count);
	i_assert(count > 1 && args[count-1].type == IMAP_ARG_EOL);
	count--;

	while (args[count-1].type != IMAP_ARG_LITERAL_SIZE &&
	       args[count-1].type != IMAP_ARG_LITERAL_SIZE_NONSYNC) {
		if (args[count-1].type != IMAP_ARG_LIST)
			return NULL;

		/* maybe the list ends with literal size */
		list = &args[count-1]._data.list;
		args = array_get_modifiable(list, &count);
		if (count == 0)
			return NULL;
	}

	*list_r = list;
	return &args[count-1];
}

bool imap_parser_get_literal_size(struct imap_parser *parser, uoff_t *size_r)
{
	ARRAY_TYPE(imap_arg_list) *list;
	struct imap_arg *last_arg;

	last_arg = imap_parser_get_last_literal_size(parser, &list);
	if (last_arg == NULL)
		return FALSE;

	return imap_arg_get_literal_size(last_arg, size_r);
}

void imap_parser_read_last_literal(struct imap_parser *parser)
{
	ARRAY_TYPE(imap_arg_list) *list;
	struct imap_arg *last_arg;

	i_assert(parser->literal_size_return);

	last_arg = imap_parser_get_last_literal_size(parser, &list);
	i_assert(last_arg != NULL);

	parser->cur_type = ARG_PARSE_LITERAL_DATA_FORCED;
	i_assert(parser->literal_size == last_arg->_data.literal_size);

	/* delete EOL */
	array_pop_back(&parser->root_list);
	parser->args_added_extra_eol = FALSE;

	/* delete literal size */
	array_pop_back(list);
	parser->literal_size_return = FALSE;
}

int imap_parser_finish_line(struct imap_parser *parser, unsigned int count,
			    enum imap_parser_flags flags,
			    const struct imap_arg **args_r)
{
	const unsigned char *data;
	size_t data_size;
	int ret;

	ret = imap_parser_read_args(parser, count, flags, args_r);
	if (ret == -1)
		return -1;
	if (ret == -2) {
		/* we should have noticed end of everything except atom */
		if (parser->cur_type == ARG_PARSE_ATOM) {
			data = i_stream_get_data(parser->input, &data_size);
			imap_parser_save_arg(parser, data, data_size);
		}
	}
	return finish_line(parser, count, args_r);
}

const char *imap_parser_read_word(struct imap_parser *parser)
{
	const unsigned char *data;
	size_t i, data_size;

	data = i_stream_get_data(parser->input, &data_size);

	for (i = 0; i < data_size; i++) {
		if (data[i] == ' ' || data[i] == '\r' || data[i] == '\n')
			break;
	}

	if (i < data_size) {
		data_size = i + (data[i] == ' ' ? 1 : 0);
		parser->line_size += data_size;
		i_stream_skip(parser->input, data_size);
		return p_strndup(parser->pool, data, i);
	} else {
		return NULL;
	}
}
