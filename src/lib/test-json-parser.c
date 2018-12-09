/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "json-parser.h"

#define TYPE_SKIP 100
#define TYPE_STREAM 101

static const char json_input[] =
	"{\n"
	"\t\"key\"\t:\t\t\"string\","
	" \"key2\"  :  1234,  \n"
	"\"key3\":true,"
	"\"key4\":false,"
	"\"skip1\": \"jsifjaisfjiasji\","
	"\"skip2\": { \"x\":{ \"y\":123}, \"z\":[5,[6],{\"k\":0},3]},"
	"\"key5\":null,"
	"\"key6\": {},"
	"\"key7\": {"
	"  \"sub1\":\"value\""
	"},"
	"\"key8\": {"
	"  \"sub2\":-12.456,\n"
	"  \"sub3\":12.456e9,\n"
	"  \"sub4\":0.456e-789"
	"},"
	"\"key9\": \"foo\\\\\\\"\\b\\f\\n\\r\\t\\u0001\\u10ff\","
	"\"key10\": \"foo\\\\\\\"\\b\\f\\n\\r\\t\\u0001\\u10ff\","
	"\"key11\": [],"
	"\"key12\": [ \"foo\" , 5.24,[true],{\"aobj\":[]}],"
	"\"key13\": \"\\ud801\\udc37\""
	"}\n";

static const struct {
	enum json_type type;
	const char *value;
} json_output[] = {
	{ JSON_TYPE_OBJECT_KEY, "key" },
	{ JSON_TYPE_STRING, "string" },
	{ JSON_TYPE_OBJECT_KEY, "key2" },
	{ JSON_TYPE_NUMBER, "1234" },
	{ JSON_TYPE_OBJECT_KEY, "key3" },
	{ JSON_TYPE_TRUE, "true" },
	{ JSON_TYPE_OBJECT_KEY, "key4" },
	{ JSON_TYPE_FALSE, "false" },
	{ JSON_TYPE_OBJECT_KEY, "skip1" },
	{ TYPE_SKIP, NULL },
	{ JSON_TYPE_OBJECT_KEY, "skip2" },
	{ TYPE_SKIP, NULL },
	{ JSON_TYPE_OBJECT_KEY, "key5" },
	{ JSON_TYPE_NULL, NULL },
	{ JSON_TYPE_OBJECT_KEY, "key6" },
	{ JSON_TYPE_OBJECT, NULL },
	{ JSON_TYPE_OBJECT_END, NULL },
	{ JSON_TYPE_OBJECT_KEY, "key7" },
	{ JSON_TYPE_OBJECT, NULL },
	{ JSON_TYPE_OBJECT_KEY, "sub1" },
	{ JSON_TYPE_STRING, "value" },
	{ JSON_TYPE_OBJECT_END, NULL },
	{ JSON_TYPE_OBJECT_KEY, "key8" },
	{ JSON_TYPE_OBJECT, NULL },
	{ JSON_TYPE_OBJECT_KEY, "sub2" },
	{ JSON_TYPE_NUMBER, "-12.456" },
	{ JSON_TYPE_OBJECT_KEY, "sub3" },
	{ JSON_TYPE_NUMBER, "12.456e9" },
	{ JSON_TYPE_OBJECT_KEY, "sub4" },
	{ JSON_TYPE_NUMBER, "0.456e-789" },
	{ JSON_TYPE_OBJECT_END, NULL },
	{ JSON_TYPE_OBJECT_KEY, "key9" },
	{ JSON_TYPE_STRING, "foo\\\"\b\f\n\r\t\001\xe1\x83\xbf" },
	{ JSON_TYPE_OBJECT_KEY, "key10" },
	{ TYPE_STREAM, "foo\\\"\b\f\n\r\t\001\xe1\x83\xbf" },
	{ JSON_TYPE_OBJECT_KEY, "key11" },
	{ JSON_TYPE_ARRAY, NULL },
	{ JSON_TYPE_ARRAY_END, NULL },
	{ JSON_TYPE_OBJECT_KEY, "key12" },
	{ JSON_TYPE_ARRAY, NULL },
	{ JSON_TYPE_STRING, "foo" },
	{ JSON_TYPE_NUMBER, "5.24" },
	{ JSON_TYPE_ARRAY, NULL },
	{ JSON_TYPE_TRUE, "true" },
	{ JSON_TYPE_ARRAY_END, NULL },
	{ JSON_TYPE_OBJECT, NULL },
	{ JSON_TYPE_OBJECT_KEY, "aobj" },
	{ JSON_TYPE_ARRAY, NULL },
	{ JSON_TYPE_ARRAY_END, NULL },
	{ JSON_TYPE_OBJECT_END, NULL },
	{ JSON_TYPE_ARRAY_END, NULL },
	{ JSON_TYPE_OBJECT_KEY, "key13" },
	{ JSON_TYPE_STRING, "\xf0\x90\x90\xb7" }
};

static int
stream_read_value(struct istream **input, const char **value_r)
{
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	while ((ret = i_stream_read(*input)) > 0) ;
	if (ret == 0)
		return 0;
	i_assert(ret == -1);
	if ((*input)->stream_errno != 0)
		return -1;

	data = i_stream_get_data(*input, &size);
	*value_r = t_strndup(data, size);
	i_stream_unref(input);
	return 1;
}

static void test_json_parser_success(bool full_size)
{
	struct json_parser *parser;
	struct istream *input, *jsoninput = NULL;
	enum json_type type;
	const char *value, *error;
	unsigned int i, pos, json_input_len = strlen(json_input);
	int ret = 0;

	test_begin(full_size ? "json parser" : "json parser (nonblocking)");
	input = test_istream_create_data(json_input, json_input_len);
	test_istream_set_allow_eof(input, FALSE);
	parser = json_parser_init(input);

	i = full_size ? json_input_len : 0;
	for (pos = 0; i <= json_input_len; i++) {
		test_istream_set_size(input, i);

		for (;;) {
			value = NULL;
			if (pos < N_ELEMENTS(json_output) &&
			    json_output[pos].type == (enum json_type)TYPE_SKIP) {
				json_parse_skip_next(parser);
				pos++;
				continue;
			} else if (pos == N_ELEMENTS(json_output) ||
				   json_output[pos].type != (enum json_type)TYPE_STREAM) {
				ret = json_parse_next(parser, &type, &value);
			} else {
				ret = jsoninput != NULL ? 1 :
					json_parse_next_stream(parser, &jsoninput);
				if (ret > 0 && jsoninput != NULL)
					ret = stream_read_value(&jsoninput, &value);
				type = TYPE_STREAM;
			}
			if (ret <= 0)
				break;

			i_assert(pos < N_ELEMENTS(json_output));
			test_assert_idx(json_output[pos].type == type, pos);
			test_assert_idx(null_strcmp(json_output[pos].value, value) == 0, pos);

			pos++;
		}
		test_assert_idx(ret == 0, pos);
	}
	test_assert(pos == N_ELEMENTS(json_output));
	test_istream_set_allow_eof(input, TRUE);
	test_assert(json_parse_next(parser, &type, &value) == -1);

	i_stream_unref(&input);
	test_assert(json_parser_deinit(&parser, &error) == 0);
	test_end();
}

static void test_json_parser_skip_array(void)
{
	static const char *test_input =
		"[ 1, {\"foo\": 1 }, 2, \"bar\", 3, 1.234, 4, [], 5, [[]], 6, true ]";
	struct json_parser *parser;
	struct istream *input;
	enum json_type type;
	const char *value, *error;
	int i;

	test_begin("json parser skip array");

	input = test_istream_create_data(test_input, strlen(test_input));
	parser = json_parser_init_flags(input, JSON_PARSER_NO_ROOT_OBJECT);
	test_assert(json_parse_next(parser, &type, &value) > 0 &&
		    type == JSON_TYPE_ARRAY);
	for (i = 1; i <= 6; i++) {
		test_assert(json_parse_next(parser, &type, &value) > 0 &&
			    type == JSON_TYPE_NUMBER && atoi(value) == i);
		json_parse_skip_next(parser);
	}
	test_assert(json_parse_next(parser, &type, &value) > 0 &&
		    type == JSON_TYPE_ARRAY_END);
	test_assert(json_parser_deinit(&parser, &error) == 0);
	i_stream_unref(&input);
	test_end();
}

static void test_json_parser_skip_object_fields(void)
{
	static const char *test_input =
		"{\"access_token\":\"9a2dea3c-f8be-4271-b9c8-5b37da4f2f7e\","
		 "\"grant_type\":\"authorization_code\","
		 "\"openid\":\"\","
		 "\"scope\":[\"openid\",\"profile\",\"email\"],"
		 "\"profile\":\"\","
		 "\"realm\":\"/employees\","
		 "\"token_type\":\"Bearer\","
		 "\"expires_in\":2377,"
		 "\"client_id\":\"mosaic\","
		 "\"email\":\"\","
		 "\"extensions\":"
		 "{\"algorithm\":\"cuttlefish\","
		  "\"tentacles\":8"
		 "}"
		"}";
	static const char *const keys[] = {
		"access_token", "grant_type", "openid", "scope", "profile",
		"realm", "token_type", "expires_in", "client_id", "email",
		"extensions"
	};
	static const unsigned int keys_count = N_ELEMENTS(keys);
	struct json_parser *parser;
	struct istream *input;
	enum json_type type;
	const char *value, *error;
	unsigned int i;
	size_t pos;
	int ret;

	test_begin("json parser skip object fields (by key)");
	input = test_istream_create_data(test_input, strlen(test_input));
	parser = json_parser_init(input);
	for (i = 0; i < keys_count; i++) {
		ret = json_parse_next(parser, &type, &value);
		if (ret < 0)
			break;
		test_assert(ret > 0 && type == JSON_TYPE_OBJECT_KEY);
		test_assert(strcmp(value, keys[i]) == 0);
		json_parse_skip_next(parser);
	}
	test_assert(json_parser_deinit(&parser, &error) == 0);
	i_stream_unref(&input);

	i = 0;
	input = test_istream_create_data(test_input, strlen(test_input));
	parser = json_parser_init(input);
	for (pos = 0; pos <= strlen(test_input); pos +=2) {
		test_istream_set_size(input, pos);
		ret = json_parse_next(parser, &type, &value);
		if (ret == 0)
			continue;
		if (ret < 0)
			break;
		i_assert(i < keys_count);
		test_assert(ret > 0 && type == JSON_TYPE_OBJECT_KEY);
		test_assert(strcmp(value, keys[i]) == 0);
		json_parse_skip_next(parser);
		i++;
	}
	test_assert(json_parser_deinit(&parser, &error) == 0);
	i_stream_unref(&input);
	test_end();

	test_begin("json parser skip object fields (by value type)");
	input = test_istream_create_data(test_input, strlen(test_input));
	parser = json_parser_init(input);
	for (i = 0; i < keys_count; i++) {
		ret = json_parse_next(parser, &type, &value);
		if (ret < 0)
			break;
		test_assert(ret > 0 && type == JSON_TYPE_OBJECT_KEY);
		test_assert(strcmp(value, keys[i]) == 0);
		ret = json_parse_next(parser, &type, &value);
		test_assert(ret > 0 && type != JSON_TYPE_OBJECT_KEY);
		json_parse_skip(parser);
	}
	test_assert(json_parser_deinit(&parser, &error) == 0);
	i_stream_unref(&input);

	i = 0;
	input = test_istream_create_data(test_input, strlen(test_input));
	parser = json_parser_init(input);
	for (pos = 0; pos <= strlen(test_input); pos +=2) {
		test_istream_set_size(input, pos);
		ret = json_parse_next(parser, &type, &value);
		if (ret < 0)
			break;
		if (ret == 0)
			continue;
		test_assert(ret > 0);
		if (type == JSON_TYPE_OBJECT_KEY) {
			i_assert(i < keys_count);
			test_assert(strcmp(value, keys[i]) == 0);
			i++;
		} else {
			json_parse_skip(parser);
		}
	}
	test_assert(json_parser_deinit(&parser, &error) == 0);
	i_stream_unref(&input);

	test_end();
}

static int
test_json_parse_input(const char *test_input, enum json_parser_flags flags)
{
	struct json_parser *parser;
	struct istream *input;
	enum json_type type;
	const char *value, *error;
	int ret = 0;

	input = test_istream_create_data(test_input, strlen(test_input));
	parser = json_parser_init_flags(input, flags);
	while (json_parse_next(parser, &type, &value) > 0)
		ret++;
	if (json_parser_deinit(&parser, &error) < 0)
		ret = -1;
	i_stream_unref(&input);
	return ret;
}

static void test_json_parser_primitive_values(void)
{
	static const struct {
		const char *str;
		int ret;
	} test_inputs[] = {
		{ "\"hello\"", 1 },
		{ "null", 1 },
		{ "1234", 1 },
		{ "1234.1234", 1 },
		{ "{}", 2 },
		{ "[]", 2 },
		{ "true", 1 },
		{ "false", 1 }
	};
	unsigned int i;

	test_begin("json_parser (primitives)");
	for (i = 0; i < N_ELEMENTS(test_inputs); i++)
		test_assert_idx(test_json_parse_input(test_inputs[i].str, JSON_PARSER_NO_ROOT_OBJECT) == test_inputs[i].ret, i);
	test_end();
}

static void test_json_parser_errors(void)
{
	static const char *test_inputs[] = {
		"{",
		"{:}",
		"{\"foo\":}",
		"{\"foo\" []}",
		"{\"foo\": [1}",
		"{\"foo\": [1,]}",
		"{\"foo\": [1,]}",
		"{\"foo\": 1,}",
		"{\"foo\": 1.}}",
		"{\"foo\": 1},{}",
		"{\"foo\": \"\\ud808\"}",
		"{\"foo\": \"\\udfff\"}",
		"{\"foo\": \"\\uyyyy\"}",
	};
	unsigned int i;

	test_begin("json parser error handling");
	for (i = 0; i < N_ELEMENTS(test_inputs); i++)
		test_assert_idx(test_json_parse_input(test_inputs[i], 0) < 0, i);
	test_end();
}

static void test_json_append_escaped(void)
{
	string_t *str = t_str_new(32);

	test_begin("json_append_escaped()");
	json_append_escaped(str, "\b\f\r\n\t\"\\\001\002-\xC3\xA4\xf0\x90\x90\xb7");
	test_assert(strcmp(str_c(str), "\\b\\f\\r\\n\\t\\\"\\\\\\u0001\\u0002-\\u00e4\\ud801\\udc37") == 0);
	test_end();
}

static void test_json_append_escaped_data(void)
{
	static const unsigned char test_input[] =
		"\b\f\r\n\t\"\\\000\001\002-\xC3\xA4\xf0\x90\x90\xb7";
	string_t *str = t_str_new(32);

	test_begin("json_append_escaped()");
	json_append_escaped_data(str, test_input, sizeof(test_input)-1);
	test_assert(strcmp(str_c(str), "\\b\\f\\r\\n\\t\\\"\\\\\\u0000\\u0001\\u0002-\\u00e4\\ud801\\udc37") == 0);
	test_end();
}

void test_json_parser(void)
{
	test_json_parser_success(TRUE);
	test_json_parser_success(FALSE);
	test_json_parser_skip_array();
	test_json_parser_skip_object_fields();
	test_json_parser_primitive_values();
	test_json_parser_errors();
	test_json_append_escaped();
	test_json_append_escaped_data();
}
