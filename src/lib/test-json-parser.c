/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "istream-private.h"
#include "json-parser.h"

static const char json_input[] =
	"{\n"
	"\t\"key\"\t:\t\t\"string\","
	" \"key2\"  :  1234,  \n"
	"\"key3\":true,"
	"\"key4\":false,"
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
	"\"key9\": \"\\\\\\\"\\b\\f\\n\\r\\t\\u0001\uffff\""
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
	{ JSON_TYPE_STRING, "\\\"\b\f\n\r\t\001\xef\xbf\xbf" }
};

static void test_json_parser_success(bool full_size)
{
	struct json_parser *parser;
	struct istream *input;
	enum json_type type;
	const char *value, *error;
	unsigned int i, pos, json_input_len = strlen(json_input);
	int ret = 0;

	test_begin("json parser");
	input = test_istream_create_data(json_input, json_input_len);
	test_istream_set_allow_eof(input, FALSE);
	parser = json_parser_init(input);

	i = full_size ? json_input_len : 0;
	for (pos = 0; i <= json_input_len; i++) {
		test_istream_set_size(input, i);

		while ((ret = json_parse_next(parser, &type, &value)) > 0) {
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
	test_json_parser_success(FALSE);
	test_json_parser_success(TRUE);
}
