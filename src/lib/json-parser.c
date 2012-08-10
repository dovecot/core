/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "hex-dec.h"
#include "unichar.h"
#include "json-parser.h"

enum json_state {
	JSON_STATE_ROOT = 0,
	JSON_STATE_OBJECT_KEY,
	JSON_STATE_OBJECT_COLON,
	JSON_STATE_OBJECT_VALUE,
	JSON_STATE_OBJECT_VALUE_NEXT,
	JSON_STATE_DONE
};

struct json_parser {
	const unsigned char *data, *end;
	const char *error;
	string_t *value;

	enum json_state state;
};

struct json_parser *
json_parser_init(const unsigned char *data, unsigned int len)
{
	struct json_parser *parser;

	parser = i_new(struct json_parser, 1);
	parser->data = data;
	parser->end = data + len;
	parser->value = str_new(default_pool, 128);
	return parser;
}

int json_parser_deinit(struct json_parser **_parser, const char **error_r)
{
	struct json_parser *parser = *_parser;

	*_parser = NULL;

	if (parser->error == NULL && parser->data == parser->end &&
	    parser->state != JSON_STATE_ROOT &&
	    parser->state != JSON_STATE_DONE)
		parser->error = "Missing '}'";

	*error_r = parser->error;
	str_free(&parser->value);
	i_free(parser);
	return *error_r != NULL ? -1 : 0;
}

static bool json_parse_whitespace(struct json_parser *parser)
{
	for (; parser->data != parser->end; parser->data++) {
		switch (*parser->data) {
		case ' ':
		case '\t':
		case '\r':
		case '\n':
			break;
		default:
			return TRUE;
		}
	}
	return FALSE;
}

static int json_parse_string(struct json_parser *parser, const char **value_r)
{
	const unsigned char *p;

	if (*parser->data != '"')
		return -1;

	str_truncate(parser->value, 0);
	for (p = parser->data + 1; p < parser->end; p++) {
		if (*p == '"') {
			parser->data = p + 1;
			*value_r = str_c(parser->value);
			return 0;
		}
		if (*p != '\\')
			str_append_c(parser->value, *p);
		else {
			switch (*++p) {
			case '"':
			case '\\':
			case '/':
				str_append_c(parser->value, *p);
				break;
			case 'b':
				str_append_c(parser->value, '\b');
				break;
			case 'f':
				str_append_c(parser->value, '\f');
				break;
			case 'n':
				str_append_c(parser->value, '\n');
				break;
			case 'r':
				str_append_c(parser->value, '\r');
				break;
			case 't':
				str_append_c(parser->value, '\t');
				break;
			case 'u':
				if (parser->end - p < 4)
					return -1;
				uni_ucs4_to_utf8_c(hex2dec(p, 4),
						   parser->value);
				p += 3;
				break;
			default:
				return -1;
			}
		}
	}
	return -1;
}

static int
json_parse_digits(struct json_parser *parser, const unsigned char **_p)
{
	const unsigned char *p = *_p;

	if (p >= parser->end || *p < '0' || *p > '9')
		return -1;

	for (; p < parser->end && *p >= '0' && *p <= '9'; p++)
		str_append_c(parser->value, *p++);
	*_p = p;
	return 0;
}

static int json_parse_int(struct json_parser *parser, const unsigned char **_p)
{
	const unsigned char *p = *_p;

	if (*p == '-') {
		str_append_c(parser->value, *p++);
		if (p == parser->end)
			return -1;
	}
	if (*p == '0')
		str_append_c(parser->value, *p++);
	else {
		if (json_parse_digits(parser, &p) < 0)
			return -1;
	}
	*_p = p;
	return 0;
}

static int json_parse_number(struct json_parser *parser, const char **value_r)
{
	const unsigned char *p = parser->data;

	str_truncate(parser->value, 0);
	if (json_parse_int(parser, &p) < 0)
		return -1;
	if (p < parser->end && *p == '.') {
		/* frac */
		str_append_c(parser->value, *p++);
		if (json_parse_digits(parser, &p) < 0)
			return -1;
	}
	if (p < parser->end && (*p == 'e' || *p == 'E')) {
		/* exp */
		str_append_c(parser->value, *p++);
		if (p == parser->end)
			return -1;
		if (*p == '+' || *p == '-')
			str_append_c(parser->value, *p++);
		if (json_parse_digits(parser, &p) < 0)
			return -1;
	}
	*value_r = str_c(parser->value);
	return 0;
}

static int json_parse_atom(struct json_parser *parser, const char *atom)
{
	unsigned int len = strlen(atom);

	if (parser->end - parser->data < len)
		return -1;
	if (memcmp(parser->data, atom, len) != 0)
		return -1;
	parser->data += len;
	return 0;
}

bool json_parse_next(struct json_parser *parser, enum json_type *type_r,
		     const char **value_r)
{
	*value_r = NULL;

	if (!json_parse_whitespace(parser) || parser->error != NULL)
		return FALSE;

	switch (parser->state) {
	case JSON_STATE_ROOT:
		if (*parser->data == '{') {
			parser->data++;
			parser->state = JSON_STATE_OBJECT_KEY;
			return json_parse_next(parser, type_r, value_r);
		}
		/* fall through */
	case JSON_STATE_OBJECT_VALUE:
		if (json_parse_string(parser, value_r) == 0)
			*type_r = JSON_TYPE_STRING;
		else if (json_parse_number(parser, value_r) == 0)
			*type_r = JSON_TYPE_NUMBER;
		else if (json_parse_atom(parser, "true") == 0) {
			*type_r = JSON_TYPE_TRUE;
			*value_r = "true";
		} else if (json_parse_atom(parser, "false") == 0) {
			*type_r = JSON_TYPE_FALSE;
			*value_r = "false";
		} else if (json_parse_atom(parser, "null") == 0) {
			*type_r = JSON_TYPE_NULL;
			*value_r = NULL;
		} else if (*parser->data == '[') {
			parser->error = "Arrays not supported";
			return FALSE;
		} else if (*parser->data == '{') {
			parser->error = "Nested objects not supported";
			return FALSE;
		} else {
			parser->error = "Invalid data as value";
			return FALSE;
		}
		parser->state = parser->state == JSON_STATE_ROOT ?
			JSON_STATE_DONE :
			JSON_STATE_OBJECT_VALUE_NEXT;
		break;
	case JSON_STATE_OBJECT_KEY:
		*type_r = JSON_TYPE_OBJECT_KEY;
		if (json_parse_string(parser, value_r) < 0) {
			parser->error = "Expected string as object key";
			return FALSE;
		}
		parser->state = JSON_STATE_OBJECT_COLON;
		break;
	case JSON_STATE_OBJECT_COLON:
		if (*parser->data != ':') {
			parser->error = "Expected ':' after key";
			return FALSE;
		}
		parser->data++;
		parser->state = JSON_STATE_OBJECT_VALUE;
		return json_parse_next(parser, type_r, value_r);
	case JSON_STATE_OBJECT_VALUE_NEXT:
		if (*parser->data == ',')
			parser->state = JSON_STATE_OBJECT_KEY;
		else if (*parser->data == '}')
			parser->state = JSON_STATE_DONE;
		else {
			parser->error = "Expected ',' or '}' after object value";
			return FALSE;
		}
		parser->data++;
		return json_parse_next(parser, type_r, value_r);
	case JSON_STATE_DONE:
		parser->error = "Unexpected data at the end";
		return FALSE;
	}
	return TRUE;
}
