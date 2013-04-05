/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

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
	"\"key9\": \"foo\\\\\\\"\\b\\f\\n\\r\\t\\u0001\\uffff\","
	"\"key10\": \"foo\\\\\\\"\\b\\f\\n\\r\\t\\u0001\\uffff\","
	"\"key11\": [],"
	"\"key12\": [ \"foo\" , 5.24,[true],{\"aobj\":[]}]"
	"}\n";

static struct {
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
	{ JSON_TYPE_STRING, "foo\\\"\b\f\n\r\t\001\xef\xbf\xbf" },
	{ JSON_TYPE_OBJECT_KEY, "key10" },
	{ TYPE_STREAM, "foo\\\"\b\f\n\r\t\001\xef\xbf\xbf" },
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
	{ JSON_TYPE_ARRAY_END, NULL }
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
				if (jsoninput != NULL)
					ret = stream_read_value(&jsoninput, &value);
				type = TYPE_STREAM;
			}
			if (ret <= 0)
				break;

			i_assert(pos < N_ELEMENTS(json_output));
			test_assert(json_output[pos].type == type);
			test_assert(null_strcmp(json_output[pos].value, value) == 0);
			pos++;
		}
		test_assert(ret == 0);
	}
	test_assert(pos == N_ELEMENTS(json_output));
	test_istream_set_allow_eof(input, TRUE);
	test_assert(json_parse_next(parser, &type, &value) == -1);

	i_stream_unref(&input);
	test_assert(json_parser_deinit(&parser, &error) == 0);
	test_end();
}

void test_json_parser(void)
{
	test_json_parser_success(TRUE);
	test_json_parser_success(FALSE);
}
