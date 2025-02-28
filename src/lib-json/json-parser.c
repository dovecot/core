/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "strescape.h"
#include "array.h"
#include "istream-private.h"

#include "json-syntax.h"
#include "json-parser.h"

#include <stdlib.h>
#include <math.h>

/* From RFC 7159:

   JSON-text = ws value ws

   ; value

   value = false / null / true / object / array / number / string

   false = %x66.61.6c.73.65   ; false
   null  = %x6e.75.6c.6c      ; null
   true  = %x74.72.75.65      ; true

   ; object

   object = begin-object [ member *( value-separator member ) ]
            end-object
   member = string name-separator value

   ; array

   array = begin-array [ value *( value-separator value ) ] end-array

   ; number

   number = [ minus ] int [ frac ] [ exp ]
	 int = zero / ( digit1-9 *DIGIT )

   frac = decimal-point 1*DIGIT
   decimal-point = %x2E       ; .

   exp = e [ minus / plus ] 1*DIGIT
   e = %x65 / %x45            ; e E

   digit1-9 = %x31-39         ; 1-9
   zero = %x30                ; 0
   minus = %x2D               ; -
   plus = %x2B                ; +

   ; string

   string = quotation-mark *char quotation-mark

   char = unescaped /
       escape (
           %x22 /          ; "    quotation mark  U+0022
           %x5C /          ; \    reverse solidus U+005C
           %x2F /          ; /    solidus         U+002F
           %x62 /          ; b    backspace       U+0008
           %x66 /          ; f    form feed       U+000C
           %x6E /          ; n    line feed       U+000A
           %x72 /          ; r    carriage return U+000D
           %x74 /          ; t    tab             U+0009
           %x75 4HEXDIG )  ; uXXXX                U+XXXX
   escape = %x5C              ; \
   quotation-mark = %x22      ; "
   unescaped = %x20-21 / %x23-5B / %x5D-10FFFF

   ; structural characters

   begin-array     = ws %x5B ws  ; [ left square bracket
   begin-object    = ws %x7B ws  ; { left curly bracket
   end-array       = ws %x5D ws  ; ] right square bracket
   end-object      = ws %x7D ws  ; } right curly bracket
   name-separator  = ws %x3A ws  ; : colon
   value-separator = ws %x2C ws  ; , comma

   ; white space

   ws = *(
           %x20 /              ; Space
           %x09 /              ; Horizontal tab
           %x0A /              ; Line feed or New line
           %x0D )              ; Carriage return
 */

/*
 * JSON parser
 */

/* As this parser is in many ways very similar to a normal recursive descent
   parser, it (partly) uses the normal call stack. However, it will backtrack
   once it reaches this level (just like it does when it is halted for more
   data), to prevent a process stack overflow. The syntax stack keeps growing
   though, meaning that it can parse arbitrary syntax nesting depths. */
#define JSON_PARSER_MAX_CALL_STACK_DEPTH 32

struct json_string_istream;

enum json_parse_result {
	/* Parsing interrupted (meaning is context-dependent) */
	JSON_PARSE_INTERRUPTED = -7,
	/* Parsing reached expected boundary */
	JSON_PARSE_BOUNDARY = -6,
	/* Buffer for current syntax element is full; element is too large */
	JSON_PARSE_OVERFLOW = -5,
	/* Parsed to end of currently buffered data */
	JSON_PARSE_NO_DATA = -4,
	/* Prevent call stack overflow
	  (to support arbitrarily deeply nested input) */
	JSON_PARSE_CALL_STACK_OVERFLOW = -3,
	/* Encountered invalid/unexpected syntax */
	JSON_PARSE_UNEXPECTED_EOF = -2,
	/* Encountered invalid/unexpected syntax */
	JSON_PARSE_ERROR = -1,
	/* Parsed OK, but no match */
	JSON_PARSE_OK = 0
};

typedef int
(*json_parser_func_t)(struct json_parser *parser,
		      struct json_parser_state *state);

struct json_parser_state {
	unsigned int state;
	void *context;
	void *param;
	unsigned int count;
};

struct json_parser_level {
	json_parser_func_t func;
	struct json_parser_state state;
	int result;

	bool backtracked:1;
	bool finished:1;
};

struct json_parser {
	enum json_parser_flags flags;

	struct json_limits limits;

	const struct json_parser_callbacks *callbacks;
	void *context;

	/* State information */
	ARRAY(struct json_parser_level) level_stack;
	unsigned int level_stack_pos;
	unsigned int call_stack_depth;

	struct istream *input;
	uoff_t input_offset;

	const unsigned char *begin, *cur, *end;

	unichar_t current_char;
	int current_char_len;

	struct {
		uoff_t line_number, value_line_number;
		uoff_t column;
	} loc;

	string_t *buffer;
	string_t *object_member;
	struct json_data content_data;

	struct json_string_istream *str_stream;
	size_t str_stream_threshold;
	size_t str_stream_max_buffer_size;

	char *error;

	bool parsed_nul_char:1;
	bool parsed_control_char:1;
	bool parsed_float:1;
	bool streaming_string:1;
	bool callback_interrupted:1;
	bool callback_running:1;
	bool finished_level:1;
	bool end_of_input:1;
	bool started:1;
	bool have_object_member:1;
};

static struct istream *
json_string_stream_create(struct json_parser *parser, bool complete);

static inline bool json_parser_is_busy(struct json_parser *parser)
{
	return (parser->level_stack_pos > 0 || parser->cur < parser->end);
}

struct json_parser *
json_parser_init(struct istream *input, const struct json_limits *limits,
		 enum json_parser_flags flags,
		 const struct json_parser_callbacks *callbacks, void *context)
{
	struct json_parser *parser;

	parser = i_new(struct json_parser, 1);
	parser->flags = flags;

	i_array_init(&parser->level_stack, 8);

	parser->input = input;
	i_stream_ref(input);
	parser->input_offset = input->v_offset;

	if (limits != NULL)
		parser->limits = *limits;
	if (parser->limits.max_string_size == 0)
		parser->limits.max_string_size = JSON_DEFAULT_MAX_STRING_SIZE;
	if (parser->limits.max_name_size == 0)
		parser->limits.max_name_size = JSON_DEFAULT_MAX_NAME_SIZE;
	if (parser->limits.max_nesting == 0)
		parser->limits.max_nesting = JSON_DEFAULT_MAX_NESTING;
	if (parser->limits.max_list_items == 0)
		parser->limits.max_list_items = JSON_DEFAULT_MAX_LIST_ITEMS;

	parser->callbacks = callbacks;
	parser->context = context;

	parser->loc.line_number = 1;

	return parser;
}

void json_parser_deinit(struct json_parser **_parser)
{
	struct json_parser *parser = *_parser;

	if (parser == NULL)
		return;
	*_parser = NULL;

	str_free(&parser->buffer);
	str_free(&parser->object_member);
	array_free(&parser->level_stack);
	i_stream_unref(&parser->input);
	i_free(parser->error);
	i_free(parser);
}

/*
 * External error handling
 */

void json_parser_error(struct json_parser *parser, const char *format, ...)
{
	va_list args;

	i_free(parser->error);
	va_start(args, format);
	parser->error = i_strdup_vprintf(format, args);
	va_end(args);
}

/*
 * Callbacks
 */

void json_parser_interrupt(struct json_parser *parser)
{
	i_assert(parser->callback_running);
	parser->callback_interrupted = TRUE;
}

static inline void json_parser_callback_init(struct json_parser *parser)
{
	i_free(parser->error);
	i_assert(!parser->callback_running);
	parser->callback_running = TRUE;
	parser->callback_interrupted = FALSE;
}

static inline int json_parser_callback_deinit(struct json_parser *parser)
{
	i_assert(parser->callback_running);
	parser->callback_running = FALSE;

	if (parser->error != NULL)
		return JSON_PARSE_ERROR;
	if (parser->callback_interrupted)
		return JSON_PARSE_INTERRUPTED;
	return JSON_PARSE_OK;
}

static int
json_parser_callback_parse_list_open(struct json_parser *parser,
				     void *parent_context, bool object,
				     void **list_context_r)
{
	const char *name;

	if (parser->callbacks == NULL ||
	    parser->callbacks->parse_list_open == NULL)
		return JSON_PARSE_OK;

	name = (parser->have_object_member ?
		str_c(parser->object_member) : NULL);

	json_parser_callback_init(parser);
	parser->callbacks->parse_list_open(parser->context, parent_context,
					   name, object, list_context_r);
	return json_parser_callback_deinit(parser);
}

static int
json_parser_callback_parse_list_close(struct json_parser *parser,
				      void *list_context, bool object)
{
	if (parser->callbacks == NULL ||
	    parser->callbacks->parse_list_close == NULL)
		return JSON_PARSE_OK;

	json_parser_callback_init(parser);
	parser->callbacks->parse_list_close(parser->context, list_context,
					    object);
	return json_parser_callback_deinit(parser);
}

static int
json_parser_callback_parse_object_member(struct json_parser *parser,
					 void *parent_context)
{
	const char *name;

	i_assert(parser->have_object_member);

	if (parser->callbacks == NULL ||
	    parser->callbacks->parse_object_member == NULL)
		return JSON_PARSE_OK;

	name = str_c(parser->object_member);

	json_parser_callback_init(parser);
	parser->callbacks->parse_object_member(parser->context, parent_context,
					       name);
	return json_parser_callback_deinit(parser);
}

static int
json_parser_callback_parse_value(struct json_parser *parser,
				 void *parent_context, enum json_type type,
				 const struct json_value *value)
{
	const char *name;

	if (parser->callbacks == NULL ||
	    parser->callbacks->parse_value == NULL)
		return JSON_PARSE_OK;

	name = (parser->have_object_member ?
		str_c(parser->object_member) : NULL);

	json_parser_callback_init(parser);
	parser->callbacks->parse_value(parser->context, parent_context,
				       name, type, value);
	return json_parser_callback_deinit(parser);
}

static void
json_parser_number_range_error(struct json_parser *parser, int dir)
{
	if (dir > 0) {
		json_parser_error(parser, "Number overflow: "
				  "Positive number exceeds range");
		return;
	}
	if (dir < 0) {
		json_parser_error(parser, "Number overflow: "
				  "Negative number exceeds range");
		return;
	}
	json_parser_error(parser, "Number underflow: "
			  "Required precision exceeds range");
}

/* Parses a signed integer from the string representation of a floating point
   number (fraction is truncated) */
static int str_float_to_intmax(const char *str, intmax_t *num_r)
{
	const char *p, *dp = NULL;
	bool neg = FALSE, eneg = FALSE;
	uintmax_t un = 0, e = 0;

	/* Skip over base */
	p = str;
	if (*p == '+' || *p == '-') {
		neg = (*p == '-');
		p++;
	}
	if (*p < '0' || *p > '9')
		return -1;
	for (; *p >= '0' && *p <= '9'; p++);
	/* Fractional part */
	if (*p == '.') {
		dp = p;
		p++;
		for (; *p >= '0' && *p <= '9'; p++);
	}
	/* Parse exponent */
	if (*p == 'e' || *p == 'E') {
		if (dp == NULL)
			dp = p;
		p++;
		if (*p == '+' || *p == '-') {
			eneg = (*p == '-');
			p++;
		}
		for (; *p >= '0' && *p <= '9'; p++) {
			if (e >= (UINTMAX_MAX / 10)) {
				if (e > UINTMAX_MAX / 10)
					return -1;
				if ((uintmax_t)(*p - '0') >
				    (UINTMAX_MAX % 10))
					return -1;
			}
			e = e * 10 + (*p - '0');
		}
	}
	if (*p != '\0')
		return -1;
	if (dp == NULL)
		dp = p;
	/* Move back to integer part */
	p = (neg ? str+1 : str);
	/* Apply negative exponent */
	if (eneg) {
		if ((uintmax_t)(dp-p) <= e) {
			/* Value is [-1 .. 1] */
			*num_r = 0;
			return 0;
		}
		dp -= e;
		e = 0;
		i_assert(dp > str);
	}
	/* Parse integer */
	while (*p >= '0' && *p <= '9') {
		if (un >= (UINTMAX_MAX / 10)) {
			if (un > UINTMAX_MAX / 10)
				return -1;
			if ((uintmax_t)(*p - '0') > (UINTMAX_MAX % 10))
				return -1;
		}
		un = un * 10 + (*p- '0');
		p++;
		if (p == dp) {
			/* Encountered (updated) decimal point position */
			if (eneg) {
				/* Negative exponent applied; exit here */
				break;
			}
			if (*p != '.') {
				/* No fraction; exit here */
				break;
			}
			/* Exponent is zero; exit here */
			if (e == 0)
				break;
			p++;
		} else if (p > dp) {
			/* Keep parsing fractional part until exponent is
			   exhausted */
			if (--e == 0)
				break;
		}
	}
	if (un > 0 && !eneg) {
		/* Apply remainder of positive exponent */
		while (e > 0) {
			e--;
			if (un > UINTMAX_MAX / 10)
				return -1;
			un = un * 10;
		}
	}
	/* Apply sign */
	if (!neg) {
		if (un > (uintmax_t)INTMAX_MAX)
			return -1;
		*num_r = (intmax_t)un;
	} else {
		if (un > (uintmax_t)INTMAX_MAX + 1)
			return -1;
		if (un == (uintmax_t)INTMAX_MAX + 1)
			*num_r = -(intmax_t)(un - 1) - 1;
		else
			*num_r = -(intmax_t)un;
	}
	return 0;
}

static int
json_parser_callback_number_value(struct json_parser *parser,
				  void *list_context)
{
	struct json_value value;
	const char *numstr = str_c(parser->buffer);

	i_zero(&value);

	if ((parser->flags & JSON_PARSER_FLAG_NUMBERS_AS_STRING) != 0) {
		value.content_type = JSON_CONTENT_TYPE_STRING;
		value.content.str = numstr;
	} else {
		if (str_float_to_intmax(numstr, &value.content.intnum) < 0) {
			json_parser_number_range_error(
				parser, (*numstr == '-' ? -1 : 1));
			return JSON_PARSE_ERROR;
		}
		value.content_type = JSON_CONTENT_TYPE_INTEGER;
	}

	return json_parser_callback_parse_value(parser, list_context,
						JSON_TYPE_NUMBER, &value);
}

static int
json_parser_callback_string_value(struct json_parser *parser,
				  void *list_context)
{
	struct json_value value;
	int ret;

	if (parser->str_stream != NULL)
		return JSON_PARSE_BOUNDARY;
	if (parser->streaming_string) {
		parser->streaming_string = FALSE;
		return JSON_PARSE_OK;
	}

	i_zero(&value);

	if (parser->str_stream_max_buffer_size > 0) {
		if (str_len(parser->buffer) >= parser->str_stream_threshold) {
			value.content_type = JSON_CONTENT_TYPE_STREAM;
			value.content.stream =
				json_string_stream_create(parser, TRUE);
			ret = json_parser_callback_parse_value(
				parser, list_context, JSON_TYPE_STRING,
				&value);
			i_stream_unref(&value.content.stream);
			parser->streaming_string = TRUE;
			if (ret < JSON_PARSE_OK)
				return ret;
			return JSON_PARSE_INTERRUPTED;
		}
	}

	if (parser->parsed_nul_char ||
	    (parser->flags & JSON_PARSER_FLAG_STRINGS_AS_DATA) != 0) {
		struct json_data *data = &parser->content_data;

		i_zero(data);
		data->data = str_data(parser->buffer);
		data->size = str_len(parser->buffer);
		data->contains_nul = parser->parsed_nul_char;
		data->contains_control = parser->parsed_control_char;

		value.content_type = JSON_CONTENT_TYPE_DATA;
		value.content.data = data;
	} else {
		value.content_type = JSON_CONTENT_TYPE_STRING;
		value.content.str = str_c(parser->buffer);
	}

	return json_parser_callback_parse_value(parser, list_context,
						JSON_TYPE_STRING, &value);
}

static int
json_parser_callback_string_stream(struct json_parser *parser,
				   void *list_context)
{
	struct json_value value;
	int ret;

	if (parser->streaming_string)
		return JSON_PARSE_OK;
	parser->streaming_string = TRUE;

	i_zero(&value);
	value.content_type = JSON_CONTENT_TYPE_STREAM;
	value.content.stream = json_string_stream_create(parser, FALSE);

	ret = json_parser_callback_parse_value(parser, list_context,
					       JSON_TYPE_STRING, &value);
	i_stream_unref(&value.content.stream);
	return ret;
}

static int
json_parser_callback_true_value(struct json_parser *parser,
				 void *list_context)
{
	struct json_value value;

	i_zero(&value);
	return json_parser_callback_parse_value(parser, list_context,
						JSON_TYPE_TRUE, &value);
}

static int
json_parser_callback_false_value(struct json_parser *parser,
				  void *list_context)
{
	struct json_value value;

	i_zero(&value);
	return json_parser_callback_parse_value(parser, list_context,
						JSON_TYPE_FALSE, &value);
}

static int
json_parser_callback_null_value(struct json_parser *parser,
				void *list_context)
{
	struct json_value value;

	i_zero(&value);
	return json_parser_callback_parse_value(parser, list_context,
						JSON_TYPE_NULL, &value);
}

/*
 * Data handling
 */

static inline bool json_parser_have_data(struct json_parser *parser)
{
	return (parser->current_char_len > 0 ||
		parser->cur < parser->end);
}

static void
json_parser_set_data(struct json_parser *parser,
		     const unsigned char *data, size_t size)
{
	parser->begin = data;
	parser->cur = data;
	parser->end = data + size;
}

static int json_parser_read(struct json_parser *parser)
{
	const unsigned char *data;
	size_t size;
	int ret;

	i_assert(parser->end >= parser->begin);
	ret = i_stream_read_data(parser->input, &data, &size,
				 (size_t)(parser->end - parser->begin));
	if (ret <= 0) {
		/* As long as the input stream buffer is large enough to hold a
		   single UTF-8 code point (4 bytes), the parser will always
		   clear enough of the buffer that it can never be full upon the
		   next read. */
		i_assert(ret != -2);

		if (parser->input->stream_errno == 0) {
			/* Just make sure we're still looking at the correct
			   buffer */
			data = i_stream_get_data(parser->input, &size);
			json_parser_set_data(parser, data, size);
		}
		return ret;
	}

	json_parser_set_data(parser, data, size);
	return size;
}

/*
 * Unicode character handling
 */

static inline const char *json_parser_curchar_str(struct json_parser *parser)
{
	unichar_t ch = parser->current_char;

	i_assert(parser->current_char_len > 0);
	if (ch >= 0x20 && ch < 0x7f)
		return t_strdup_printf("'%c'", (char) ch);
	switch (ch) {
	case 0x00:
		return "<NUL>";
	case '\r':
		return "<CR>";
	case '\n':
		return "<LF>";
	case '\t':
		return "<TAB>";
	}
	if (ch <= 0xffff)
		return t_strdup_printf("U+%04lX", (unsigned long int) ch);

	return t_strdup_printf("U+%06lX", (unsigned long int) ch);
}

static int json_parser_readchar(struct json_parser *parser)
{
	int ret;

	if (parser->cur >= parser->end)
		return JSON_PARSE_NO_DATA;

	ret = uni_utf8_get_char_buf(parser->cur, (parser->end - parser->cur),
				    &parser->current_char);
	if (ret <= 0) {
		if (ret < 0) {
			json_parser_error(parser, "Invalid UTF-8 character");
			return JSON_PARSE_ERROR;
		}
		if (parser->end_of_input) {
			json_parser_error(parser,
				"Incomplete UTF-8 character at end of input");
			return JSON_PARSE_UNEXPECTED_EOF;
		}
		return JSON_PARSE_NO_DATA;
	}

	if (parser->current_char > 0x10ffff ||
	    (parser->current_char & 0xfff800) == 0x00d800) {
		/* Should be checked in unichar.h */
		json_parser_error(parser, "Invalid Unicode character U+%04lX",
				  (unsigned long int)parser->current_char);
		return JSON_PARSE_ERROR;
	}

	/* Update parser location */
	if (parser->current_char == '\n')
		parser->loc.line_number++;
	else
		parser->loc.column++;

	parser->current_char_len = ret;
	return JSON_PARSE_OK;
}

static inline int
json_parser_curchar(struct json_parser *parser, unichar_t *ch_r)
{
	int ret;

	if (parser->current_char_len <= 0) {
		ret = json_parser_readchar(parser);
		if (ret < JSON_PARSE_OK)
			return ret;
		i_assert(parser->current_char_len > 0);
	}
	if (ch_r != NULL)
		*ch_r = parser->current_char;
	return JSON_PARSE_OK;
}

static inline void json_parser_shift(struct json_parser *parser)
{
	i_assert(parser->current_char_len > 0);
	parser->cur += parser->current_char_len;
	i_assert(parser->cur <= parser->end);
	parser->current_char_len = 0;

	if (parser->current_char == '\n')
		parser->loc.column = 0;
}

static inline size_t json_parser_available_size(struct json_parser *parser)
{
	i_assert(parser->cur <= parser->end);
	return (parser->end - parser->cur);
}

static inline size_t
json_parser_shifted_size(struct json_parser *parser,
			 const unsigned char *offset)
{
	i_assert(offset <= parser->cur);
	return (parser->cur - offset);
}

static inline size_t
json_parser_parsed_size(struct json_parser *parser,
			const unsigned char *offset)
{
	return json_parser_shifted_size(parser, offset)
		+ parser->current_char_len;
}

/*
 * Parser core
 */

static inline int
json_parser_call(struct json_parser *parser,
		 json_parser_func_t parse_func, void *param)
{
	struct json_parser_level *level;
	struct json_parser_state state;
	unsigned int level_stack_pos;
	int status;

	if (!json_parser_have_data(parser) && !parser->end_of_input)
		return JSON_PARSE_NO_DATA;

	if (parser->level_stack_pos > parser->limits.max_nesting) {
		json_parser_error(
			parser, "Data is nested too deep (max %u levels)",
			parser->limits.max_nesting);
		return JSON_PARSE_ERROR;
	}

	/* Ascend syntax stack */
	parser->level_stack_pos++;
	level_stack_pos = parser->level_stack_pos;

	level = array_idx_get_space(&parser->level_stack, level_stack_pos-1);

	if (level->result == JSON_PARSE_OVERFLOW) {
		/* We're backtracking from an overflow */
		i_assert(level->func == parse_func);
		--parser->level_stack_pos;
		status = level->result;
		level->result = 0;
		level->backtracked = TRUE;
		return status;
	}
	if (level->finished) {
		/* This level is finished in json_parser_run();
		   return result */
		i_assert(level->func == parse_func);
		status = level->result;
		--parser->level_stack_pos;
		i_zero(level);
		parser->finished_level = TRUE;
		return status;
	}

	if (level->backtracked) {
		/* Continue in earlier backtracked level */
		level->backtracked = FALSE;
	} else {
		/* Start parsing at new syntax level */
		i_assert(level->func == NULL);
		i_zero(level);
		level->func = parse_func;
		level->state.param = param;
	}

	if (parser->call_stack_depth >= JSON_PARSER_MAX_CALL_STACK_DEPTH) {
		/* Backtrack to clear the call stack */
		return JSON_PARSE_CALL_STACK_OVERFLOW;
	}

	parser->call_stack_depth++;

	state = level->state;
	status = parse_func(parser, &state);
	level = array_idx_modifiable(&parser->level_stack, level_stack_pos-1);
	level->state = state;

	i_assert(parser->call_stack_depth > 0);
	parser->call_stack_depth--;

	switch (status) {
	case JSON_PARSE_OVERFLOW:
		level->backtracked = TRUE;
		--parser->level_stack_pos;
		return status;
	case JSON_PARSE_CALL_STACK_OVERFLOW:
	case JSON_PARSE_NO_DATA:
	case JSON_PARSE_BOUNDARY:
	case JSON_PARSE_INTERRUPTED:
		/* Parsing halted at this position */
		return status;
	default:
		break;
	}

	/* Level finished immediately */
	--parser->level_stack_pos;
	level->func = NULL;
	level->backtracked = FALSE;
	return status;
}

static int
json_parser_run(struct json_parser *parser, json_parser_func_t parse_func)
{
	struct json_parser_level *level;
	struct json_parser_state state;
	unsigned int overflow_stack_pos;
	int ret;

	/* Exit early if there is no data */
	if (!json_parser_have_data(parser) && !parser->end_of_input)
		return JSON_PARSE_NO_DATA;

	/* Make sure parse functions get no partial characters */
	if ((ret = json_parser_curchar(parser, NULL)) < JSON_PARSE_OK) {
		if (ret != JSON_PARSE_NO_DATA || !parser->end_of_input)
			return ret;
	}

	if (parser->level_stack_pos == 0) {
		/* Start parsing */
		parser->call_stack_depth = 0;
		ret = json_parser_call(parser, parse_func, NULL);
		i_assert(parser->call_stack_depth == 0);
		if (ret != JSON_PARSE_CALL_STACK_OVERFLOW)
			return ret;
	}

	/* Continue parsing */
	level = NULL;
	overflow_stack_pos = 0;
	do {
		unsigned int level_stack_pos;
		bool first = TRUE;

		if (level != NULL) {
			first = FALSE;
			level->result = ret;
			if (ret != JSON_PARSE_OVERFLOW) {
				/* Mark previous level as finished; meaning that
				   json_parser_call() in the current level will
				   return level->result */
				level->finished = TRUE;
			}
		}

		level_stack_pos = parser->level_stack_pos;

		level =	array_idx_get_space(&parser->level_stack,
					    level_stack_pos-1);

		parser->finished_level = FALSE;

		/* Call the level parse function */
		parser->call_stack_depth = 0;
		i_assert(level->func != NULL);
		state = level->state;
		ret = level->func(parser, &state);
		level =	array_idx_modifiable(&parser->level_stack,
					     level_stack_pos-1);
		level->state = state;
		i_assert(parser->call_stack_depth == 0);

		switch (ret) {
		case JSON_PARSE_OVERFLOW:
			if (overflow_stack_pos == 0)
				overflow_stack_pos = parser->level_stack_pos;
			break;
		case JSON_PARSE_OK:
			break;
		case JSON_PARSE_CALL_STACK_OVERFLOW:
			/* Unwrapped call stack; continue */
			level = NULL;
			continue;
		default:
			if (overflow_stack_pos > 0)
				parser->level_stack_pos = overflow_stack_pos;
			return ret;
		}

		/* Descend the syntax stack */
		parser->level_stack_pos--;

		i_assert(first || parser->finished_level ||
			 parser->end_of_input || ret == JSON_PARSE_OVERFLOW);
	} while (parser->level_stack_pos > 0);
	i_assert(level != NULL);
	level->func = NULL;

	if (overflow_stack_pos > 0)
		parser->level_stack_pos = overflow_stack_pos;
	return ret;
}

/*
 * Buffers
 */

static inline void json_parser_reset_buffer(struct json_parser *parser)
{
	if (parser->buffer == NULL)
		parser->buffer = str_new(default_pool, 256);
	else
		str_truncate(parser->buffer, 0);
}

static inline void
json_parser_append_buffer(struct json_parser *parser,
			  buffer_t *buffer, const unsigned char *offset)
{
	size_t size = json_parser_shifted_size(parser, offset);

	if (size == 0)
		return;
	str_append_data(buffer, offset, size);
}

/*
 * JSON syntax
 */

/* ws */

static int json_parser_skip_ws(struct json_parser *parser)
{
	unichar_t ch;
	int ret;

	/* ws = *(
	           %x20 /              ; Space
	           %x09 /              ; Horizontal tab
	           %x0A /              ; Line feed or New line
	           %x0D )              ; Carriage return
	 */

	while ((ret = json_parser_curchar(parser, &ch)) == JSON_PARSE_OK) {
		if (!json_unichar_is_ws(ch))
			return JSON_PARSE_OK;
		json_parser_shift(parser);
	}
	if (ret == JSON_PARSE_NO_DATA) {
		return (parser->end_of_input ?
			JSON_PARSE_OK : JSON_PARSE_NO_DATA);
	}
	return ret;
}

/* false, null, true */

static int
json_parser_do_parse_literal(struct json_parser *parser,
			     struct json_parser_state *state)
{
	enum { _LIT_START = 0, _LIT_NEXT, _LIT_END };
	const char *literal = (const char *)state->param;
	const char *p = (const char *)state->context;
	unichar_t ch;
	int ret;

	while ((ret = json_parser_curchar(parser, &ch)) == JSON_PARSE_OK) {
		switch (state->state) {
		case _LIT_START:
			p = literal;
			i_assert(*p != '\0');
			i_assert((unichar_t)*p == ch);
			p++;
			if (*p == '\0') {
				state->state = _LIT_END;
				return JSON_PARSE_OK;
			}
			state->state = _LIT_NEXT;
			json_parser_shift(parser);
			continue;
		case _LIT_NEXT:
			if ((unichar_t)*p != ch) {
				json_parser_error(
					parser, "Expected value '%s', "
					"but encounted '%s' + %s",
					literal, t_strdup_until(literal, p),
					json_parser_curchar_str(parser));
				return JSON_PARSE_ERROR;
			}
			p++;
			if (*p == '\0') {
				state->state = _LIT_END;
				json_parser_shift(parser);
				return JSON_PARSE_OK;
			}
			json_parser_shift(parser);
			continue;
		default:
			i_unreached();
		}
	}
	state->context = (void *)p;
	return ret;
}
static int
json_parser_parse_literal(struct json_parser *parser, const char *literal)
{
	return json_parser_call(parser, json_parser_do_parse_literal,
				(void*)literal);
}

/* number */

static int
json_parser_do_parse_number(struct json_parser *parser,
			    struct json_parser_state *state)
{
	enum { _NUM_START = 0, _NUM_INT, _NUM_ZERO, _NUM_NONZERO,
	       _NUM_DOT, _NUM_FRAC, _NUM_FRAC_NEXT, _NUM_E, _NUM_E_PM,
	       _NUM_EXP, _NUM_EXP_NEXT, _NUM_END };
	string_t *buf = parser->buffer;
	const unsigned char *offset = parser->cur;
	size_t max_size = parser->limits.max_string_size;
	unichar_t ch;
	int ret;

	/* number = [ minus ] int [ frac ] [ exp ]
		 int = zero / ( digit1-9 *DIGIT )

	   frac = decimal-point 1*DIGIT
	   decimal-point = %x2E       ; .

	   exp = e [ minus / plus ] 1*DIGIT
	   e = %x65 / %x45            ; e E

	   digit1-9 = %x31-39         ; 1-9
	   zero = %x30                ; 0
	   minus = %x2D               ; -
	   plus = %x2B                ; +
	 */

	i_assert(max_size > 0);
	i_assert(str_len(buf) <= max_size);

	while ((ret = json_parser_curchar(parser, &ch)) == JSON_PARSE_OK) {
		if ((str_len(buf) +
		    json_parser_parsed_size(parser, offset)) > max_size)
			return JSON_PARSE_OVERFLOW;
		switch (state->state) {
		case _NUM_START:
			parser->parsed_float = FALSE;
			state->state = _NUM_INT;
			if (ch == '-') {
				json_parser_shift(parser);
				continue;
			}
			/* Fall through */
		case _NUM_INT:
			if (ch == '0') {
				state->state = _NUM_ZERO;
				json_parser_shift(parser);
				continue;
			}
			if (json_unichar_is_digit(ch)) {
				state->state = _NUM_NONZERO;
				json_parser_shift(parser);
				continue;
			}
			json_parser_error(parser,
				"Expected digit, but encountered %s",
				json_parser_curchar_str(parser));
			return JSON_PARSE_ERROR;
		case _NUM_ZERO:
			if (json_unichar_is_digit(ch)) {
				json_parser_error(parser,
					"Numbers cannot have leading zeros");
				return JSON_PARSE_ERROR;
			}
			state->state = _NUM_DOT;
			continue;
		case _NUM_NONZERO:
			if (!json_unichar_is_digit(ch)) {
				state->state = _NUM_DOT;
				continue;
			}
			json_parser_shift(parser);
			continue;
		case _NUM_DOT:
			if (ch == 'e' || ch == 'E') {
				parser->parsed_float = TRUE;
				state->state = _NUM_E_PM;
				json_parser_shift(parser);
				continue;
			}
			if (ch == '.') {
				parser->parsed_float = TRUE;
				state->state = _NUM_FRAC;
				json_parser_shift(parser);
				continue;
			}
			json_parser_append_buffer(parser, buf, offset);
			state->state = _NUM_END;
			return JSON_PARSE_OK;
		case _NUM_FRAC:
			if (!json_unichar_is_digit(ch)) {
				json_parser_error(parser,
					"Expected digit in number fraction, "
					"but encountered %s",
					json_parser_curchar_str(parser));
				return JSON_PARSE_ERROR;
			}
			state->state = _NUM_FRAC_NEXT;
			json_parser_shift(parser);
			continue;
		case _NUM_FRAC_NEXT:
			if (!json_unichar_is_digit(ch)) {
				state->state = _NUM_E;
				continue;
			}
			json_parser_shift(parser);
			continue;
		case _NUM_E:
			if (ch == 'e' || ch == 'E') {
				state->state = _NUM_E_PM;
				json_parser_shift(parser);
				continue;
			}
			json_parser_append_buffer(parser, buf, offset);
			state->state = _NUM_END;
			return JSON_PARSE_OK;
		case _NUM_E_PM:
			state->state = _NUM_EXP;
			if (ch == '-' || ch == '+') {
				json_parser_shift(parser);
				continue;
			}
			/* Fall through */
		case _NUM_EXP:
			if (!json_unichar_is_digit(ch)) {
				json_parser_error(parser,
					"Expected digit in number exponent, "
					"but encountered %s",
					json_parser_curchar_str(parser));
				return JSON_PARSE_ERROR;
			}
			state->state = _NUM_EXP_NEXT;
			json_parser_shift(parser);
			continue;
		case _NUM_EXP_NEXT:
			if (json_unichar_is_digit(ch)) {
				json_parser_shift(parser);
				continue;
			}
			json_parser_append_buffer(parser, buf, offset);
			state->state = _NUM_END;
			return JSON_PARSE_OK;
		default:
			i_unreached();
		}
	}
	if (ret == JSON_PARSE_NO_DATA) {
		if ((str_len(buf) +
		    json_parser_parsed_size(parser, offset)) > max_size)
			return JSON_PARSE_OVERFLOW;
		if (parser->end_of_input) {
			switch (state->state) {
			case _NUM_ZERO:
			case _NUM_NONZERO:
			case _NUM_DOT:
			case _NUM_FRAC_NEXT:
			case _NUM_E:
			case _NUM_EXP_NEXT:
				json_parser_append_buffer(parser, buf, offset);
				return JSON_PARSE_OK;
			default:
				break;
			}
			json_parser_error(parser,
				"Encountered end of input inside number");
			return JSON_PARSE_UNEXPECTED_EOF;
		}
		json_parser_append_buffer(parser, buf, offset);
	}
	return ret;
}
static int json_parser_parse_number(struct json_parser *parser)
{
	return json_parser_call(parser, json_parser_do_parse_number, NULL);
}

/* string */

static int
json_parser_finish_bad_unicode_escape(
	struct json_parser *parser,
	struct json_parser_state *state ATTR_UNUSED)
{
	unichar_t ch;
	int ret;

	ret = json_parser_curchar(parser, &ch);
	if (ret == JSON_PARSE_OK) {
		json_parser_error(parser,
			"Invalid digit %s in Unicode escape sequence",
			json_parser_curchar_str(parser));
		return JSON_PARSE_ERROR;
	}
	return ret;
}

static int
json_parser_parse_unicode_escape(struct json_parser *parser,
				 struct json_parser_state *state,
				 size_t max_size)
{
	string_t *buf = (string_t *)state->param;
	unichar_t hi_surg = (unichar_t)(uintptr_t)state->context;
	unichar_t ch, ech;
	int ret, i;

	if (hi_surg != 0x0000 && (hi_surg & 0xfffc00) != 0xd800) {
		/* Already parsed, but string buffer was full. */
		ech = hi_surg;
		if ((str_len(buf) + uni_ucs4_to_utf8_len(ech)) > max_size) {
			/* Buffer is more than full when the escaped
			   character is added; return overflow. */
			return JSON_PARSE_OVERFLOW;
		}
		uni_ucs4_to_utf8_c(ech, buf);
		return JSON_PARSE_OK;
	}

	/* No need to create a level on the parser stack, since we can just wait
	   until sufficient input is available. */
	if (json_parser_available_size(parser) < 4)
		return JSON_PARSE_NO_DATA;
	ech = 0;
	i = 0;
	while ((ret = json_parser_curchar(parser, &ch)) == JSON_PARSE_OK) {
		switch (ch) {
		case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
			ech = (ech << 4) + (unichar_t)(ch - 'a' + 10);
			break;
		case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
			ech = (ech << 4) + (unichar_t)(ch - 'A' + 10);
			break;
		case '0': case '1': case '2': case '3': case '4': case '5':
		case '6': case '7': case '8': case '9':
			ech = (ech << 4) + (unichar_t)(ch - '0');
			break;
		default:
			json_parser_error(parser,
				"Invalid digit %s in Unicode escape sequence",
				json_parser_curchar_str(parser));
			return JSON_PARSE_ERROR;
		}
		json_parser_shift(parser);
		if (++i >= 4)
			break;
	}
	if (ret == JSON_PARSE_NO_DATA) {
		/* We already checked that 4 octets are available for for hex
		   digits. The only thing that could have happened is that we
		   encountered the beginnings of an UTF-8 character and no more
		   input is available. Finish it at a deeper parse level that
		   always returns error once the UTF-8 character is complete. */
		return json_parser_call(
			parser, json_parser_finish_bad_unicode_escape, NULL);
	}
	if (ech == 0x0000) {
		if ((parser->flags &
		     JSON_PARSER_FLAG_STRINGS_ALLOW_NUL) == 0) {
			json_parser_error(parser,
				"String contains escaped NUL character");
			return JSON_PARSE_ERROR;
		}
		parser->parsed_nul_char = TRUE;
	}
	if (hi_surg != 0x0000) {
		i_assert((hi_surg & 0xfffc00) == 0xd800);
		if ((ech & 0xfffc00) != 0xdc00) {
			json_parser_error(parser,
				"String contains lonely Unicode high surrogate "
				"'\\u%04lX'", (unsigned long int)hi_surg);
			return JSON_PARSE_ERROR;
		}
		ech = (ech & 0x3ff) | ((hi_surg & 0x3ff) << 10);
		ech += 0x10000;
		hi_surg = 0x0000;
		state->context = (void*)(uintptr_t)hi_surg;
	} else if ((ech & 0xfffc00) == 0xd800) {
		hi_surg = ech;
		state->context = (void*)(uintptr_t)hi_surg;
	} else if ((ech & 0xfffc00) == 0xdc00) {
		json_parser_error(parser,
			"String contains lonely Unicode low surrogate "
			"'\\u%04lX'", (unsigned long int)ech);
		return JSON_PARSE_ERROR;
	}
	if (hi_surg == 0x0000) {
		if (!uni_is_valid_ucs4(ech)) {
			json_parser_error(parser,
				"String contains invalid escaped "
				"Unicode character U+%04lX",
				(unsigned long int)ech);
			return JSON_PARSE_ERROR;
		}
		if (json_unichar_is_control(ech))
			parser->parsed_control_char = TRUE;

		if ((str_len(buf) + uni_ucs4_to_utf8_len(ech)) > max_size) {
			/* Buffer is more than full when the escaped character
			   is added; return overflow. Store the parsed character
			   for the next call. */
			state->context = (void*)(uintptr_t)ech;
			return JSON_PARSE_OVERFLOW;
		}
		uni_ucs4_to_utf8_c(ech, buf);
	}
	return JSON_PARSE_OK;
}

static inline int
json_parser_parse_unicode_escape_close(struct json_parser *parser,
				       struct json_parser_state *state)
{
	unichar_t hi_surg = (unichar_t)(uintptr_t)state->context;

	if (hi_surg != 0x0000) {
		i_assert((hi_surg & 0xfffc00) == 0xd800);
		json_parser_error(parser,
			"String contains lonely Unicode high surrogate "
			"'\\u%04lX'", (unsigned long int)hi_surg);
		return JSON_PARSE_ERROR;
	}

	state->context = (void*)(uintptr_t)0x000;
	return JSON_PARSE_OK;
}

static int
json_parser_do_parse_string(struct json_parser *parser,
			    struct json_parser_state *state, size_t max_size)
{
	enum { _STR_START = 0, _STR_CHAR, _STR_ESCAPE, _STR_ESCAPE_U,
		_STR_END };
	string_t *buf = (string_t *)state->param;
	const unsigned char *offset = parser->cur;
	unichar_t ch;
	int ret;

	/* string = quotation-mark *char quotation-mark

	   char = unescaped /
	          escape (
	            %x22 /          ; "    quotation mark  U+0022
	            %x5C /          ; \    reverse solidus U+005C
	            %x2F /          ; /    solidus         U+002F
	            %x62 /          ; b    backspace       U+0008
	            %x66 /          ; f    form feed       U+000C
	            %x6E /          ; n    line feed       U+000A
	            %x72 /          ; r    carriage return U+000D
	            %x74 /          ; t    tab             U+0009
	            %x75 4HEXDIG )  ; uXXXX                U+XXXX
	   escape = %x5C              ; \
	   quotation-mark = %x22      ; "
	   unescaped = %x20-21 / %x23-5B / %x5D-10FFFF
	 */

	i_assert(str_len(buf) <= max_size);

	while ((ret = json_parser_curchar(parser, &ch)) == JSON_PARSE_OK) {
		switch (state->state) {
		/* quotation-mark */
		case _STR_START:
			if (ch != '"') {
				json_parser_error(parser,
					"Expected string, but encountered %s",
					json_parser_curchar_str(parser));
				return JSON_PARSE_ERROR;
			}
			json_parser_shift(parser);
			offset = parser->cur;
			parser->parsed_nul_char = FALSE;
			parser->parsed_control_char = FALSE;
			state->state = _STR_CHAR;
			continue;
		/* char */
		case _STR_CHAR:
			/* escape */
			if (ch == '\\') {
				i_assert((str_len(buf) +
					  json_parser_shifted_size(parser, offset))
					 <= max_size);
				json_parser_append_buffer(parser, buf, offset);
				state->state = _STR_ESCAPE;
				json_parser_shift(parser);
				continue;
			}
			ret = json_parser_parse_unicode_escape_close(
				parser, state);
			if (ret < JSON_PARSE_OK)
				return ret;
			if (ch == '"') {
				i_assert((str_len(buf) +
					  json_parser_shifted_size(parser, offset))
					 <= max_size);
				json_parser_append_buffer(parser, buf, offset);
				state->state = _STR_END;
				json_parser_shift(parser);
				return JSON_PARSE_OK;
			}
			/* unescaped = %x20-21 / %x23-5B / %x5D-10FFFF */
			if (!json_unichar_is_uchar(ch)) {
				json_parser_error(parser,
					"String contains invalid character %s",
					json_parser_curchar_str(parser));
				return JSON_PARSE_ERROR;
			}
			if ((str_len(buf) +
			     json_parser_parsed_size(parser, offset))
				> max_size) {
				/* Buffer is more than full when current
				   character is added; just add the pending
				   characters we skipped so far and return
				   overflow. */
				json_parser_append_buffer(parser, buf, offset);
				return JSON_PARSE_OVERFLOW;
			}
			json_parser_shift(parser);
			continue;
		/* escape */
		case _STR_ESCAPE:
			if (str_len(buf) >= max_size)
				return JSON_PARSE_OVERFLOW;
			state->state = _STR_CHAR;
			switch (ch) {
			/* %x22 /          ; "    quotation mark  U+0022 */
			case '"':
				str_append_c(buf, '"');
				break;
			/* %x5C /          ; \    reverse solidus U+005C */
			case '\\':
				str_append_c(buf, '\\');
				break;
			/* %x2F /          ; /    solidus         U+002F */
			case '/':
				str_append_c(buf, '/');
				break;
			/* %x62 /          ; b    backspace       U+0008 */
			case 'b':
				parser->parsed_control_char = TRUE;
				str_append_c(buf, 0x08);
				break;
			/* %x66 /          ; f    form feed       U+000C */
			case 'f':
				parser->parsed_control_char = TRUE;
				str_append_c(buf, 0x0c);
				break;
			/* %x6E /          ; n    line feed       U+000A */
			case 'n':
				str_append_c(buf, '\n');
				break;
			/* %x72 /          ; r    carriage return U+000D */
			case 'r':
				str_append_c(buf, '\r');
				break;
			/* %x74 /          ; t    tab             U+0009 */
			case 't':
				str_append_c(buf, '\t');
				break;
			/* %x75 4HEXDIG )  ; uXXXX                U+XXXX */
			case 'u':
				state->state = _STR_ESCAPE_U;
				json_parser_shift(parser);
				continue;
			default:
				json_parser_error(parser,
					"Invalid escape sequence '\\' + %s",
					json_parser_curchar_str(parser));
				return JSON_PARSE_ERROR;
			}
			ret = json_parser_parse_unicode_escape_close(
				parser, state);
			if (ret < JSON_PARSE_OK)
				return ret;
			json_parser_shift(parser);
			offset = parser->cur;
			continue;
		/* %x75 4HEXDIG */
		case _STR_ESCAPE_U:
			ret = json_parser_parse_unicode_escape(
				parser, state, max_size);
			if (ret < JSON_PARSE_OK)
				return ret;
			offset = parser->cur;
			state->state = _STR_CHAR;
			continue;
		default:
			i_unreached();
		}
	}
	if (ret == JSON_PARSE_NO_DATA) {
		if (parser->end_of_input) {
			switch (state->state) {
			case _STR_START:
				json_parser_error(parser,
					"Expected string, "
					"but encountered end of input");
				return JSON_PARSE_UNEXPECTED_EOF;
			case _STR_CHAR:
			case _STR_ESCAPE:
			case _STR_ESCAPE_U:
				json_parser_error(parser,
					"Encountered end of input inside string");
				return JSON_PARSE_UNEXPECTED_EOF;
			default:
				break;
			}
			i_unreached();
		}
		if (state->state == _STR_CHAR) {
			i_assert((str_len(buf) +
				  json_parser_shifted_size(parser, offset))
				 <= max_size);
			json_parser_append_buffer(parser, buf, offset);
		}
	}
	return ret;
}

static int
json_parser_do_parse_string_value(struct json_parser *parser,
				  struct json_parser_state *state)
{
	size_t max_size;

	if (parser->str_stream_max_buffer_size > 0)
		max_size = parser->str_stream_max_buffer_size;
	else
		max_size = parser->limits.max_string_size;

	if (parser->str_stream == NULL &&
	    parser->str_stream_max_buffer_size > 0 &&
	    max_size > parser->str_stream_threshold) {
		/* Return string stream immediately once the threshold is
		   crossed */
		max_size = parser->str_stream_threshold;
	}

	return json_parser_do_parse_string(parser, state, max_size);
}

static int
json_parser_parse_string_value(struct json_parser *parser, string_t *buf)
{
	return json_parser_call(parser, json_parser_do_parse_string_value,
				(void *)buf);
}

static int
json_parser_do_parse_object_member(struct json_parser *parser,
				   struct json_parser_state *state)
{
	return json_parser_do_parse_string(parser, state,
					    parser->limits.max_name_size);
}

static int
json_parser_parse_object_member(struct json_parser *parser, string_t *buf)
{
	return json_parser_call(parser, json_parser_do_parse_object_member,
				(void *)buf);
}

/* value */

static int
json_parser_parse_value(struct json_parser *parser, void *context);
static int
json_parser_do_parse_value(struct json_parser *parser,
			   struct json_parser_state *state)
{
	enum { _VALUE_START = 0, _VALUE_ARRAY, _VALUE_ARRAY_EMPTY,
	       _VALUE_ARRAY_VALUE, _VALUE_ARRAY_COMMA, _VALUE_ARRAY_COMMA_WS,
	       _VALUE_OBJECT, _VALUE_OBJECT_EMPTY, _VALUE_OBJECT_MEMBER,
	       _VALUE_OBJECT_NAME_WS, _VALUE_OBJECT_COLON,
	       _VALUE_OBJECT_COLON_WS,	_VALUE_OBJECT_VALUE,
	       _VALUE_OBJECT_COMMA, _VALUE_OBJECT_COMMA_WS,
	       _VALUE_NUMBER, _VALUE_STRING, _VALUE_FALSE, _VALUE_NULL,
	       _VALUE_TRUE, _VALUE_WS, _VALUE_END };
	void *parent_context = state->param;
	unichar_t ch;
	int ret;

	/* value = false / null / true / object / array / number / string

	   false = %x66.61.6c.73.65   ; false
	   null  = %x6e.75.6c.6c      ; null
	   true  = %x74.72.75.65      ; true

	   ; object

	   object = begin-object [ member *( value-separator member ) ]
	            end-object
	   member = string name-separator value

	   ; array

	   array = begin-array [ value *( value-separator value ) ] end-array

	   ; structural characters

	   begin-array     = ws %x5B ws  ; [ left square bracket
	   begin-object    = ws %x7B ws  ; { left curly bracket
	   end-array       = ws %x5D ws  ; ] right square bracket
	   end-object      = ws %x7D ws  ; } right curly bracket
	   name-separator  = ws %x3A ws  ; : colon
	   value-separator = ws %x2C ws  ; , comma
	 */

	while ((ret = json_parser_curchar(parser, &ch)) == JSON_PARSE_OK) {
		switch (state->state) {
		case _VALUE_START:
			switch (ch) {
			/* array */
			case '[':
				state->state = _VALUE_ARRAY;
				state->count = 1;
				json_parser_shift(parser);
				ret = json_parser_callback_parse_list_open(
					parser, parent_context, FALSE,
					&state->context);
				if (ret < JSON_PARSE_OK)
					return ret;
				continue;
			/* object */
			case '{':
				state->state = _VALUE_OBJECT;
				state->count = 1;
				json_parser_shift(parser);
				ret = json_parser_callback_parse_list_open(
					parser,	parent_context, TRUE,
					&state->context);
				if (ret < JSON_PARSE_OK)
					return ret;
				continue;
			/* number */
			case '-':
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				json_parser_reset_buffer(parser);
				state->state = _VALUE_NUMBER;
				continue;
			/* string */
			case '"':
				json_parser_reset_buffer(parser);
				state->state = _VALUE_STRING;
				continue;
			/* false */
			case 'f':
				state->state = _VALUE_FALSE;
				continue;
			/* null */
			case 'n':
				state->state = _VALUE_NULL;
				continue;
			/* true */
			case 't':
				state->state = _VALUE_TRUE;
				continue;
			default:
				break;
			}
			json_parser_error(parser,
				"Expected value, but encountered %s",
				json_parser_curchar_str(parser));
			return JSON_PARSE_ERROR;
		/* "[" ws */
		case _VALUE_ARRAY:
			ret = json_parser_skip_ws(parser);
			if (ret < JSON_PARSE_OK)
				return ret;
			if (parser->object_member != NULL)
				str_truncate(parser->object_member, 0);
			parser->have_object_member = FALSE;
			state->state = _VALUE_ARRAY_EMPTY;
			continue;
		/* "[" ws "]" */
		case _VALUE_ARRAY_EMPTY:
			if (ch == ']') {
				state->state = _VALUE_WS;
				json_parser_shift(parser);
				ret = json_parser_callback_parse_list_close(
					parser, state->context, FALSE);
				if (ret < JSON_PARSE_OK)
					return ret;
				continue;
			}
			state->state = _VALUE_ARRAY_VALUE;
			continue;
		/* value */
		case _VALUE_ARRAY_VALUE:
			ret = json_parser_parse_value(parser, state->context);
			if (ret < JSON_PARSE_OK)
				return ret;
			state->state = _VALUE_ARRAY_COMMA;
			continue;
		/* "," */
		case _VALUE_ARRAY_COMMA:
			if (ch == ']') {
				state->state = _VALUE_WS;
				json_parser_shift(parser);
				ret = json_parser_callback_parse_list_close(
					parser, state->context, FALSE);
				if (ret < JSON_PARSE_OK)
					return ret;
				continue;
			}
			if (ch != ',') {
				json_parser_error(parser,
					"Expected ',' or ']', "
					"but encountered %s",
					json_parser_curchar_str(parser));
				return JSON_PARSE_ERROR;
			}
			if (++state->count > parser->limits.max_list_items) {
				json_parser_error(parser,
					"Too many items in array");
				return JSON_PARSE_ERROR;
			}
			state->state = _VALUE_ARRAY_COMMA_WS;
			json_parser_shift(parser);
			continue;
		/* "," ws */
		case _VALUE_ARRAY_COMMA_WS:
			ret = json_parser_skip_ws(parser);
			if (ret	< JSON_PARSE_OK)
				return ret;
			state->state = _VALUE_ARRAY_VALUE;
			continue;
		/* "{" ws */
		case _VALUE_OBJECT:
			ret = json_parser_skip_ws(parser);
			if (ret < JSON_PARSE_OK)
				return ret;
			if (parser->object_member != NULL)
				str_truncate(parser->object_member, 0);
			parser->have_object_member = FALSE;
			state->state = _VALUE_OBJECT_EMPTY;
			continue;
		/* "{" ws "}" */
		case _VALUE_OBJECT_EMPTY:
			if (ch == '}') {
				state->state = _VALUE_WS;
				json_parser_shift(parser);
				ret = json_parser_callback_parse_list_close(
					parser, state->context, TRUE);
				if (ret < JSON_PARSE_OK)
					return ret;
				continue;
			}
			if (parser->object_member == NULL) {
				parser->object_member =
					str_new(default_pool, 128);
			}
			state->state = _VALUE_OBJECT_MEMBER;
			continue;
		/* member */
		case _VALUE_OBJECT_MEMBER:
			ret = json_parser_parse_object_member(
				parser, parser->object_member);
			if (ret	< JSON_PARSE_OK) {
				if (ret == JSON_PARSE_OVERFLOW) {
					json_parser_error(parser,
						"Excessive object member name size");
					return JSON_PARSE_ERROR;
				}
				return ret;
			}
			if (parser->parsed_nul_char) {
				json_parser_error(parser,
					"Encountered NUL character in object member name");
				return JSON_PARSE_ERROR;
			}
			parser->have_object_member = TRUE;
			state->state = _VALUE_OBJECT_NAME_WS;
			ret = json_parser_callback_parse_object_member(
				parser, parent_context);
			if (ret < JSON_PARSE_OK)
				return ret;
			continue;
		/* string ws */
		case _VALUE_OBJECT_NAME_WS:
			ret = json_parser_skip_ws(parser);
			if (ret < JSON_PARSE_OK)
				return ret;
			state->state = _VALUE_OBJECT_COLON;
			continue;
		/* ":" */
		case _VALUE_OBJECT_COLON:
			if (ch != ':') {
				json_parser_error(parser,
					"Expected ':', but encountered %s",
					json_parser_curchar_str(parser));
				return JSON_PARSE_ERROR;
			}
			state->state = _VALUE_OBJECT_COLON_WS;
			json_parser_shift(parser);
			continue;
		/* ":" ws */
		case _VALUE_OBJECT_COLON_WS:
			ret = json_parser_skip_ws(parser);
			if (ret < JSON_PARSE_OK)
				return ret;
			state->state = _VALUE_OBJECT_VALUE;
			continue;
		/* value */
		case _VALUE_OBJECT_VALUE:
			ret = json_parser_parse_value(parser, state->context);
			if (ret < JSON_PARSE_OK)
				return ret;
			if (parser->object_member != NULL)
				str_truncate(parser->object_member, 0);
			parser->have_object_member = FALSE;
			state->state = _VALUE_OBJECT_COMMA;
			continue;
		/* "," */
		case _VALUE_OBJECT_COMMA:
			if (ch == '}') {
				state->state = _VALUE_WS;
				json_parser_shift(parser);
				ret = json_parser_callback_parse_list_close(
					parser, state->context, TRUE);
				if (ret < JSON_PARSE_OK)
					return ret;
				continue;
			}
			if (ch != ',') {
				json_parser_error(parser,
					"Expected ',' or '}', "
					"but encountered %s",
					json_parser_curchar_str(parser));
				return JSON_PARSE_ERROR;
			}
			if (++state->count > parser->limits.max_list_items) {
				json_parser_error(parser,
					"Too many fields in object");
				return JSON_PARSE_ERROR;
			}
			state->state = _VALUE_OBJECT_COMMA_WS;
			json_parser_shift(parser);
			continue;
		/* "," ws */
		case _VALUE_OBJECT_COMMA_WS:
			ret = json_parser_skip_ws(parser);
			if (ret < JSON_PARSE_OK)
				return ret;
			str_truncate(parser->object_member, 0);
			parser->have_object_member = FALSE;
			state->state = _VALUE_OBJECT_MEMBER;
			continue;
		/* number */
		case _VALUE_NUMBER:
			ret = json_parser_parse_number(parser);
			if (ret < JSON_PARSE_OK) {
				if (ret == JSON_PARSE_OVERFLOW) {
					json_parser_error(parser,
						"Excessive number string size");
					return JSON_PARSE_ERROR;
				}
				return ret;
			}
			state->state = _VALUE_WS;
			ret = json_parser_callback_number_value(
				parser,	parent_context);
			if (ret < JSON_PARSE_OK)
				return ret;
			continue;
		/* string */
		case _VALUE_STRING:
			ret = json_parser_parse_string_value(
				parser, parser->buffer);
			if (ret < JSON_PARSE_OK) {
				if (ret != JSON_PARSE_OVERFLOW)
					return ret;
				if (parser->str_stream_max_buffer_size == 0) {
					json_parser_error(parser,
						"Excessive string size (> %zu)",
						parser->limits.max_string_size);
					return JSON_PARSE_ERROR;
				}
				ret = json_parser_callback_string_stream(
					parser,	parent_context);
				if (ret < JSON_PARSE_OK)
					return ret;
				return JSON_PARSE_INTERRUPTED;
			}
			state->state = _VALUE_WS;
			ret = json_parser_callback_string_value(
				parser,	parent_context);
			if (ret < JSON_PARSE_OK)
				return ret;
			continue;
		/* false */
		case _VALUE_FALSE:
			ret = json_parser_parse_literal(parser, "false");
			if (ret < JSON_PARSE_OK)
				return ret;
			state->state = _VALUE_WS;
			ret = json_parser_callback_false_value(
				parser,	parent_context);
			if (ret < JSON_PARSE_OK)
				return ret;
			continue;
		/* null */
		case _VALUE_NULL:
			ret = json_parser_parse_literal(parser, "null");
			if (ret < JSON_PARSE_OK)
				return ret;
			state->state = _VALUE_WS;
			ret = json_parser_callback_null_value(
				parser, parent_context);
			if (ret < JSON_PARSE_OK)
				return ret;
			continue;
		/* true */
		case _VALUE_TRUE:
			ret = json_parser_parse_literal(parser, "true");
			if (ret < JSON_PARSE_OK)
				return ret;
			state->state = _VALUE_WS;
			ret = json_parser_callback_true_value(
				parser, parent_context);
			if (ret < JSON_PARSE_OK)
				return ret;
			continue;
		/* value ws */
		case _VALUE_WS:
			ret = json_parser_skip_ws(parser);
			if (ret < JSON_PARSE_OK)
				return ret;
			parser->streaming_string = FALSE;
			state->state = _VALUE_END;
			return JSON_PARSE_OK;
		default:
			i_unreached();
		}
	}
	if (ret == JSON_PARSE_NO_DATA && parser->end_of_input) {
		switch (state->state) {
		case _VALUE_START:
			json_parser_error(parser,
				"Expected value, "
				"but encountered end of input");
			return JSON_PARSE_UNEXPECTED_EOF;
		case _VALUE_ARRAY:
		case _VALUE_ARRAY_EMPTY:
		case _VALUE_ARRAY_VALUE:
		case _VALUE_ARRAY_COMMA:
		case _VALUE_ARRAY_COMMA_WS:
			json_parser_error(parser,
				"Encountered end of input inside array");
			return JSON_PARSE_UNEXPECTED_EOF;
		case _VALUE_OBJECT:
		case _VALUE_OBJECT_EMPTY:
		case _VALUE_OBJECT_MEMBER:
		case _VALUE_OBJECT_NAME_WS:
		case _VALUE_OBJECT_COLON:
		case _VALUE_OBJECT_COLON_WS:
		case _VALUE_OBJECT_VALUE:
		case _VALUE_OBJECT_COMMA:
		case _VALUE_OBJECT_COMMA_WS:
			json_parser_error(parser,
				"Encountered end of input inside object");
			return JSON_PARSE_UNEXPECTED_EOF;
		case _VALUE_NUMBER:
			return json_parser_callback_number_value(parser,
				parent_context);
		case _VALUE_STRING:
			return json_parser_callback_string_value(parser,
				parent_context);
		case _VALUE_FALSE:
			return json_parser_callback_false_value(parser,
				parent_context);
		case _VALUE_NULL:
			return json_parser_callback_null_value(parser,
				parent_context);
		case _VALUE_TRUE:
			return json_parser_callback_true_value(parser,
				parent_context);
		case _VALUE_WS:
			break;
		default:
			i_unreached();
		}
		return JSON_PARSE_OK;
	}
	return ret;
}
static int
json_parser_parse_value(struct json_parser *parser, void *context)
{
	return json_parser_call(parser, json_parser_do_parse_value, context);
}

/* JSON-text */

static int
json_parser_parse_text(struct json_parser *parser,
		       struct json_parser_state *state)
{
	enum { _TEXT_START = 0, _TEXT_WS, _TEXT_VALUE, _TEXT_END };
	unichar_t ch;
	int ret;

	/* JSON-text = ws value ws */

	while ((ret = json_parser_curchar(parser, &ch)) == JSON_PARSE_OK) {
		switch (state->state) {
		/* BOM */
		case _TEXT_START:
			state->state = _TEXT_WS;
			if (ch == 0xFEFF) {
				if ((parser->flags &
				     JSON_PARSER_FLAG_ALLOW_BOM) != 0) {
					/* Ignore it */
					json_parser_shift(parser);
					continue;
				}
				json_parser_error(parser,
					"Encountered byte order mark at the beginning of input, "
					"which is not allowed");
				return JSON_PARSE_ERROR;
			}
			/* Fall through */
		/* ws */
		case _TEXT_WS:
			ret = json_parser_skip_ws(parser);
			if (ret	< JSON_PARSE_OK)
				return ret;
			state->state = _TEXT_VALUE;
			continue;
		/* value */
		case _TEXT_VALUE:
			ret = json_parser_parse_value(parser, NULL);
			if (ret < JSON_PARSE_OK)
				return ret;
			state->state = _TEXT_END;
			return JSON_PARSE_OK;
		default:
			i_unreached();
		}
	}
	if (ret == JSON_PARSE_NO_DATA && parser->end_of_input) {
		switch (state->state) {
		case _TEXT_START:
		case _TEXT_WS:
			break;
		case _TEXT_VALUE:
		case _TEXT_END:
			return JSON_PARSE_OK;
		default:
			i_unreached();
		}
		json_parser_error(parser, "JSON text has no value");
		return JSON_PARSE_ERROR;
	}
	return ret;
}

/*
 * API
 */

static int json_parser_continue(struct json_parser *parser)
{
	int status, ret;

	if (parser->error != NULL)
		return JSON_PARSE_ERROR;
	if (parser->started &&
		!json_parser_is_busy(parser)) {
		return JSON_PARSE_OK;
	}

	do {
		if (!json_parser_have_data(parser))
			continue;
		status = json_parser_run(parser,
			json_parser_parse_text);
		parser->started = TRUE;

		switch (status) {
		case JSON_PARSE_ERROR:
		case JSON_PARSE_UNEXPECTED_EOF:
			return status;
		default:
			break;
		}

		i_stream_skip(parser->input,
			      (size_t)(parser->cur - parser->begin));
		parser->begin = parser->cur;

		switch (status) {
		case JSON_PARSE_INTERRUPTED:
		case JSON_PARSE_OVERFLOW:
		case JSON_PARSE_BOUNDARY:
			return status;
		case JSON_PARSE_NO_DATA:
			break;
		case JSON_PARSE_OK:
			if (parser->cur < parser->end) {
				json_parser_error(parser,
					"Spurious data at end of JSON text");
				return JSON_PARSE_ERROR;
			}
			status = JSON_PARSE_NO_DATA;
			break;
		case JSON_PARSE_ERROR:
		case JSON_PARSE_UNEXPECTED_EOF:
			i_unreached();
		}
		i_assert(status == JSON_PARSE_NO_DATA);
	} while ((ret = json_parser_read(parser)) > 0);

	if (ret < 0) {
		if (parser->input->stream_errno != 0) {
			json_parser_error(parser, "read(%s) failed: %s",
					  i_stream_get_name(parser->input),
					  i_stream_get_error(parser->input));
			return JSON_PARSE_ERROR;
		}

		parser->end_of_input = TRUE;

		status = json_parser_run(parser, json_parser_parse_text);
		switch (status) {
		case JSON_PARSE_ERROR:
		case JSON_PARSE_UNEXPECTED_EOF:
		case JSON_PARSE_INTERRUPTED:
		case JSON_PARSE_OK:
		case JSON_PARSE_BOUNDARY:
			return status;
		case JSON_PARSE_NO_DATA:
			break;
		default:
			i_unreached();
		}
		json_parser_error(parser, "Premature end of input");
		return JSON_PARSE_UNEXPECTED_EOF;
	}
	return JSON_PARSE_NO_DATA;
}

int json_parse_more(struct json_parser *parser, const char **error_r)
{
	int ret;

	i_assert(parser->str_stream == NULL);

	*error_r = NULL;

	ret = json_parser_continue(parser);
	switch (ret) {
	case JSON_PARSE_ERROR:
	case JSON_PARSE_UNEXPECTED_EOF:
		*error_r = parser->error;
		return -1;
	case JSON_PARSE_OK:
		break;
	case JSON_PARSE_INTERRUPTED:
		if (parser->end_of_input)
			return 1;
		return 0;
	case JSON_PARSE_OVERFLOW:
	case JSON_PARSE_NO_DATA:
		return 0;
	default:
		i_unreached();
	}

	return 1;
}

void json_parser_get_location(struct json_parser *parser,
			      struct json_parser_location *loc_r)
{
	i_zero(loc_r);
	i_assert(parser->input->v_offset >= parser->input_offset);
	loc_r->offset = parser->input->v_offset - parser->input_offset +
			(parser->cur - parser->begin);
	loc_r->line = parser->loc.line_number;
	loc_r->value_line = parser->loc.value_line_number;
	loc_r->column = parser->loc.column;
}

/*
 *
 */

struct json_string_istream {
	struct istream_private istream;

	struct json_parser *parser;

	bool buffer_overflowed:1;
	bool ended:1;
};

static ssize_t json_string_istream_read(struct istream_private *stream)
{
	struct json_string_istream *jstream =
		(struct json_string_istream *)stream;
	struct json_parser *parser = jstream->parser;
	bool stop_loop;
	size_t old_pos, read_size, read_total;
	int ret;

	if (jstream->ended) {
		stream->istream.eof = TRUE;
		return -1;
	}
	i_assert(jstream->parser != NULL);

	i_assert(stream->pos == str_len(parser->buffer));
	i_assert(stream->skip <= stream->pos);

	read_total = 0;
	do {
		if (jstream->buffer_overflowed) {
			if (stream->skip == str_len(parser->buffer))
				str_truncate(parser->buffer, 0);
			else if (stream->skip > 0)
				str_delete(parser->buffer, 0, stream->skip);
			else
				return -2;
			stream->pos = str_len(parser->buffer);
			stream->skip = 0;
			jstream->buffer_overflowed = FALSE;
		}

		old_pos = str_len(parser->buffer);
		ret = json_parser_continue(parser);
		i_assert(str_len(parser->buffer) >= old_pos);
		read_size = str_len(parser->buffer) - old_pos;
		stop_loop = (read_size > 0);
		read_total += read_size;
		switch (ret) {
		case JSON_PARSE_INTERRUPTED:
			i_assert(stream->skip == 0 ||
				 !jstream->buffer_overflowed);
			jstream->buffer_overflowed = TRUE;
			break;
		case JSON_PARSE_BOUNDARY:
			jstream->ended = TRUE;
			if (str_len(parser->buffer) == old_pos) {
				stream->istream.eof = TRUE;
				return -1;
			}
			stop_loop = TRUE;
			break;
		case JSON_PARSE_NO_DATA:
			stop_loop = TRUE;
			break;
		case JSON_PARSE_ERROR:
			io_stream_set_error(&stream->iostream,
					    "%s", parser->error);
			stream->istream.stream_errno = EINVAL;
			return -1;
		case JSON_PARSE_UNEXPECTED_EOF:
			io_stream_set_error(&stream->iostream,
					    "%s", parser->error);
			stream->istream.stream_errno = EPIPE;
			return -1;
		default:
			i_unreached();
		}
	} while (jstream->buffer_overflowed && !stop_loop);

	stream->pos = str_len(parser->buffer);
	stream->buffer = str_data(parser->buffer);
	return (ssize_t)read_total;
}

static void
json_string_istream_set_max_buffer_size(struct iostream_private *stream,
					size_t max_size)
{
	struct json_string_istream *jstream =
		(struct json_string_istream *)stream;

	i_assert(max_size > 0);
	jstream->parser->str_stream_max_buffer_size = max_size;
}

static void
json_string_istream_close(struct iostream_private *stream,
			  bool close_parent ATTR_UNUSED)
{
	struct json_string_istream *jstream =
		(struct json_string_istream *)stream;

	if (jstream->parser != NULL)
		jstream->parser->str_stream = NULL;
}

static struct istream *
json_string_stream_create(struct json_parser *parser, bool complete)
{
	struct json_string_istream *jstream;
	struct istream *stream;
	const char *name;

	i_assert(parser->str_stream == NULL);

	jstream = i_new(struct json_string_istream, 1);
	jstream->parser = parser;

	jstream->ended = complete;
	jstream->istream.pos = str_len(parser->buffer);
	jstream->istream.buffer = str_data(parser->buffer);

	jstream->istream.max_buffer_size = parser->str_stream_max_buffer_size;
	jstream->istream.iostream.set_max_buffer_size =
		json_string_istream_set_max_buffer_size;
	jstream->istream.iostream.close =
		json_string_istream_close;
	jstream->istream.read = json_string_istream_read;

	jstream->istream.istream.readable_fd = FALSE;
	jstream->istream.istream.blocking = parser->input->blocking;
	jstream->istream.istream.seekable = FALSE;

	parser->str_stream = jstream;

	stream = i_stream_create(&jstream->istream, NULL,
				 i_stream_get_fd(parser->input), 0);

	name = i_stream_get_name(parser->input);
	if (name == NULL || *name == '\0') {
		i_stream_set_name(stream, "(JSON string)");
	} else {
		i_stream_set_name(stream, t_strdup_printf(
			"(JSON string parsed from %s)", name));
	}
	return stream;
}

void json_parser_enable_string_stream(struct json_parser *parser,
				      size_t threshold, size_t max_buffer_size)
{
	i_assert(max_buffer_size > 0);
	if (threshold > max_buffer_size)
		threshold = max_buffer_size;
	parser->str_stream_threshold = threshold;
	parser->str_stream_max_buffer_size = max_buffer_size;
}

void json_parser_disable_string_stream(struct json_parser *parser)
{
	parser->str_stream_max_buffer_size = 0;
}
