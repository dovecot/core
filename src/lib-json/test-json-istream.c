/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "istream-failure-at.h"
#include "test-common.h"

#include "json-istream.h"

#include <unistd.h>

static bool debug = FALSE;

static void
test_json_read_success_text(struct json_istream **_jinput, const char *text)
{
	const char *error;
	int ret;

	ret = json_istream_finish(_jinput, &error);
	test_out_reason_quiet(text, ret > 0, error);

	/* Don't leak in case of test failure with ret == 0 */
	json_istream_destroy(_jinput);
}

static void
test_json_read_failure_text(struct json_istream **_jinput, const char *text)
{
	const char *error;
	int ret;

	ret = json_istream_finish(_jinput, &error);
	test_out_reason_quiet(text, ret < 0, error);

	/* Don't leak in case of test failure with ret == 0 */
	json_istream_destroy(_jinput);
}

static void test_json_read_success(struct json_istream **_jinput)
{
	test_json_read_success_text(_jinput, "read success");
}

static void test_json_read_failure(struct json_istream **_jinput)
{
	test_json_read_failure_text(_jinput, "read failure");
}

/*
 * Test: read number values
 */

static void test_json_istream_read_number(void)
{
	static const struct {
		const char *text;
		intmax_t number;
	} number_tests[] = {
		{
			.text = "1234",
			.number = 1234,
		},
		{
			.text = "1234e3",
			.number = 1234000,
		},
		{
			.text = "1234e-3",
			.number = 1,
		},
		{
			.text = "1234e003",
			.number = 1234000,
		},
		{
			.text = "1234e-003",
			.number = 1,
		},
		{
			.text = "123.4",
			.number = 123,
		},
		{
			.text = "12.34",
			.number = 12,
		},
		{
			.text = "1.234",
			.number = 1,
		},
		{
			.text = "0.1234",
			.number = 0,
		},
		{
			.text = "987.6e01",
			.number = 9876,
		},
		{
			.text = "98.76e02",
			.number = 9876,
		},
		{
			.text = "9.876e03",
			.number = 9876,
		},
		{
			.text = "0.9876e04",
			.number = 9876,
		},
		{
			.text = "0.9876e03",
			.number = 987,
		},
		{
			.text = "0.9876e02",
			.number = 98,
		},
		{
			.text = "0.9876e01",
			.number = 9,
		},
		{
			.text = "",
			.number = INTMAX_MAX,
		},
		{
			.text = "",
			.number = INTMAX_MIN,
		},
		{
			.text = "e00",
			.number = INTMAX_MAX,
		},
		{
			.text = "e00",
			.number = INTMAX_MIN,
		},
		{
			.text = "00e-02",
			.number = INTMAX_MAX,
		},
		{
			.text = "00e-02",
			.number = INTMAX_MIN,
		},
		{
			.text = "0000000000e-10",
			.number = INTMAX_MAX,
		},
		{
			.text = "0000000000e-10",
			.number = INTMAX_MIN,
		},
		{
			.text = ".999999999",
			.number = INTMAX_MAX,
		},
		{
			.text = ".999999999",
			.number = INTMAX_MIN,
		},
		{
			.text = "123e-10000000",
			.number = 0,
		},
		{
			.text = "2342e-2",
			.number = 23,
		},
		{
			.text = "23423232e-6",
			.number = 23,
		},
		{
			.text = "234232327654e-10",
			.number = 23,
		},
		{
			.text = "2342323276546785432098e-20",
			.number = 23,
		},
		{
			.text = "23423232765467854320984567894323e-30",
			.number = 23,
		},
		{
			.text = "23423232765467854320984567894323"
			        "000000000000000000000000000000e-60",
			.number = 23,
		},
		{
			.text = "0.23423232765467854320984567894323e2",
			.number = 23,
		},
		{
			.text = "0.0000234232327654678543209845678943e6",
			.number = 23,
		},
		{
			.text = "0.0000000023234232327654678543209845e10",
			.number = 23,
		},
		{
			.text = "0.0000000000000000002323423232765467e20",
			.number = 23,
		},
		{
			.text = "0.0000000000000000000000000000232342e30",
			.number = 23,
		},
		{
			.text = "0.000000000000000000000000000000"
			        "000000000000000000000000000023e60",
			.number = 23,
		},
	};
	static const unsigned int number_tests_count =
		N_ELEMENTS(number_tests);
	unsigned int i;

	for (i = 0; i < number_tests_count; i++) {
		const char *text;
		unsigned int text_len;
		struct json_node jnode;
		struct istream *input;
		struct json_istream *jinput;
		const char *str_val;
		intmax_t num_val = 0;
		int ret = 0;

		i_zero(&jnode);

		if (number_tests[i].number == INTMAX_MAX) {
			text = t_strdup_printf("%"PRIdMAX"%s", INTMAX_MAX,
					       number_tests[i].text);
		} else if (number_tests[i].number == INTMAX_MIN) {
			text = t_strdup_printf("%"PRIdMAX"%s", INTMAX_MIN,
					       number_tests[i].text);
		} else {
			text = number_tests[i].text;
		}
		text_len = strlen(text);

		test_begin(t_strdup_printf("json istream read number[%u]", i));

		/* As string */
		input = i_stream_create_from_data(text, text_len);
		jinput = json_istream_create(
			input, 0, NULL, JSON_PARSER_FLAG_NUMBERS_AS_STRING);

		ret = json_istream_read(jinput, &jnode);
		test_assert(ret != 0);
		test_assert(json_node_is_number(&jnode));
		if (json_node_is_number(&jnode)) {
			str_val = json_node_get_str(&jnode);
			test_assert_strcmp(str_val, text);
		}
		json_istream_skip(jinput);
		ret = json_istream_read(jinput, &jnode);
		test_assert(ret != 0);
		test_json_read_success_text(&jinput, "read str success");

		json_istream_unref(&jinput);
		i_stream_unref(&input);

		/* As number */
		input = i_stream_create_from_data(text, text_len);
		jinput = json_istream_create(input, 0, NULL, 0);

		ret = json_istream_read(jinput, &jnode);
		test_assert(ret != 0);
		test_assert(json_node_is_number(&jnode));
		if (json_node_is_number(&jnode)) {
			test_assert(json_node_get_intmax(
					&jnode, &num_val) == 0);
			test_assert(num_val == number_tests[i].number);
		}
		json_istream_skip(jinput);
		ret = json_istream_read(jinput, &jnode);
		test_assert(ret != 0);
		test_json_read_success_text(&jinput, "read int success");

		json_istream_unref(&jinput);
		i_stream_unref(&input);

		test_end();
	}
}

/*
 * Test: read string values
 */

static void test_json_istream_read_string(void)
{
	static const unsigned char data1[] = { 0x00 };
	static const unsigned char data2[] =
		{ 'a', 'a', 'a', 0x00, 'b', 'b', 'b' };
	static const struct {
		const char *text;
		const char *string;
		const unsigned char *data;
		size_t size;
	} string_tests[] = {
		{
			.text = "\"bla\"",
			.string = "bla",
		},
		{
			.text = "\"\\\"\\\\\\/\\r\\n\\t\"",
			.string = "\"\\/\r\n\t",
		},
		{
			.text = "\"\\b\\f\"",
			.string = "\x08\x0c",
		},
		{
			.text = "\"\0\"",
		},
		{
			.text = "\"\\\0\"",
		},
		{
			.text = "\"\\u0000\"",
			.data = data1,
			.size = sizeof(data1),
		},
		{
			.text = "\"aaa\\u0000bbb\"",
			.data = data2,
			.size = sizeof(data2),
		},
		{
			.text = "\"\\uD83D\\uDD4A\"",
			.string = "\xF0\x9F\x95\x8A",
		},
		{
			.text = "\"fly \\uD83D\\uDD4A fly\"",
			.string = "fly \xF0\x9F\x95\x8A fly",
		},
		{
			.text = "\"\\uD83D\\uDD4A\\uD83D\\uDD4A\"",
			.string = "\xF0\x9F\x95\x8A\xF0\x9F\x95\x8A",
		},
		{
			.text = "\"\\uD83D\\uDD4A\\uD83D\\uDD4A\"",
			.string = "\xF0\x9F\x95\x8A\xF0\x9F\x95\x8A",
		},
	};
	static const unsigned int string_tests_count =
		N_ELEMENTS(string_tests);
	unsigned int i;

	for (i = 0; i < string_tests_count; i++) {
		const char *text;
		unsigned int text_len;
		struct json_node jnode;
		struct istream *input;
		struct json_istream *jinput;
		const char *str_val;
		const unsigned char *data_val;
		size_t size_val;
		int ret = 0;

		i_zero(&jnode);

		text = string_tests[i].text;
		text_len = strlen(text);

		test_begin(t_strdup_printf("json istream read string[%u]", i));

		/* As C string */
		input = i_stream_create_from_data(text, text_len);
		jinput = json_istream_create(input, 0, NULL, 0);

		ret = json_istream_read(jinput, &jnode);
		if (string_tests[i].string == NULL) {
			test_assert(ret <  0);
			test_json_read_failure(&jinput);
		} else {
			test_assert(ret != 0);
			test_assert(json_node_is_string(&jnode));
			if (json_node_is_string(&jnode)) {
				str_val = json_node_get_str(&jnode);
				test_assert_strcmp(str_val,
						   string_tests[i].string);
			}
			json_istream_skip(jinput);
			ret = json_istream_read(jinput, &jnode);
			test_assert(ret != 0);
			test_json_read_success_text(
				&jinput, "read cstr success");
		}

		json_istream_unref(&jinput);
		i_stream_unref(&input);

		/* As DATA */
		input = i_stream_create_from_data(text, text_len);
		jinput = json_istream_create(
			input, 0, NULL, JSON_PARSER_FLAG_STRINGS_ALLOW_NUL);

		ret = json_istream_read(jinput, &jnode);
		if (string_tests[i].string != NULL) {
			test_assert(ret != 0);
			test_assert(json_node_is_string(&jnode));
			if (json_node_is_string(&jnode)) {
				str_val = json_node_get_str(&jnode);
				test_assert_strcmp(str_val,
						   string_tests[i].string);
			}
			json_istream_skip(jinput);
			ret = json_istream_read(jinput, &jnode);
			test_assert(ret != 0);
			test_json_read_success_text(
				&jinput, "read str success");
		} else if (string_tests[i].data != NULL) {
			test_assert(ret != 0);
			test_assert(json_node_is_string(&jnode));
			if (json_node_is_string(&jnode)) {
				data_val =
					json_node_get_data(&jnode, &size_val);
				test_assert_ucmp(size_val, ==,
						 string_tests[i].size);
				test_assert(
					memcmp(data_val, string_tests[i].data,
					       I_MIN(size_val,
						     string_tests[i].size)) == 0);
			}
			json_istream_skip(jinput);
			ret = json_istream_read(jinput, &jnode);
			test_assert(ret != 0);
			test_json_read_success_text(
				&jinput, "read data success");

		} else {
			test_assert(ret <  0);
			test_json_read_failure(&jinput);
		}

		json_istream_unref(&jinput);
		i_stream_unref(&input);

		test_end();
	}
}

/*
 * Test: read buffer
 */

static void test_json_istream_read_buffer(void)
{
	struct istream *input;
	struct json_istream *jinput;
	const char *text;
	struct json_node jnode;
	unsigned int text_len;
	intmax_t num_val = 0;
	int ret = 0;

	i_zero(&jnode);

	/* number */
	text = "2234234";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read buffer - number");

	ret = json_istream_read(jinput, &jnode);
	test_assert(ret != 0);
	test_assert(json_node_is_number(&jnode));
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 2234234);
	json_istream_skip(jinput);
	ret = json_istream_read(jinput, &jnode);
	test_assert(ret != 0);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* string */
	text = "\"text\"";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read buffer - string");

	ret = json_istream_read(jinput, &jnode);
	test_assert(ret != 0);
	test_assert(json_node_is_string(&jnode));
	test_assert(null_strcmp(json_node_get_str(&jnode), "text") == 0);
	json_istream_skip(jinput);
	ret = json_istream_read(jinput, &jnode);
	test_assert(ret != 0);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* array */
	text = "[\"text\"]";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read buffer - array");

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_array(&jnode));
	json_istream_skip(jinput);
	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* object */
	text = "{\"text\": 1}";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read buffer - object");

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_object(&jnode));
	json_istream_skip(jinput);
	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* array descend */
	text = "[\"text\"]";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read buffer - array descend");

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_array(&jnode));

	ret = json_istream_descend(jinput, &jnode);
	test_assert(ret > 0);
	test_assert(json_node_is_array(&jnode));

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_string(&jnode));
	test_assert(null_strcmp(json_node_get_str(&jnode),
				"text") == 0);
	json_istream_ascend(jinput);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* object descend */
	text = "{\"member\": 14234234}";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read buffer - object descend");

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_object(&jnode));

	ret = json_istream_descend(jinput, &jnode);
	test_assert(ret > 0);
	test_assert(json_node_is_object(&jnode));

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_number(&jnode));
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 14234234);
	test_assert(null_strcmp(jnode.name, "member") == 0);
	json_istream_ascend(jinput);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* type=array */
	text = "[\"text\",1,[false,[true],null],[1],{\"a\":1}]";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create_array(input, NULL, 0);

	test_begin("json istream read buffer - type=array");

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_string(&jnode));
	test_assert(null_strcmp(json_node_get_str(&jnode), "text") == 0);
	json_istream_skip(jinput);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_number(&jnode));
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 1);
	json_istream_skip(jinput);

	ret = json_istream_descend(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_array(&jnode));

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_false(&jnode));
	json_istream_skip(jinput);

	ret = json_istream_descend(jinput, &jnode);
	test_assert(ret > 0);
	test_assert(json_node_is_array(&jnode));

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_true(&jnode));
	json_istream_ascend(jinput);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_null(&jnode));
	json_istream_ascend(jinput);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_array(&jnode));
	json_istream_skip(jinput);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_object(&jnode));
	json_istream_skip(jinput);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret < 0);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* type=object */
	text = "{\"a\":\"text\",\"b\":1,\"c\":{\"d\":false,"
		"\"e\":{\"f\":true},\"g\":null},\"h\":[1],\"i\":{\"a\":1}}";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create_object(input, NULL, 0);

	test_begin("json istream read buffer - type=object");

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_string(&jnode));
	test_assert(null_strcmp(json_node_get_str(&jnode), "text") == 0);
	test_assert(null_strcmp(jnode.name, "a") == 0);
	json_istream_skip(jinput);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_number(&jnode));
	test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
	test_assert(num_val == 1);
	test_assert(null_strcmp(jnode.name, "b") == 0);
	json_istream_skip(jinput);

	ret = json_istream_descend(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_object(&jnode));
	test_assert(null_strcmp(jnode.name, "c") == 0);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_false(&jnode));
	test_assert(null_strcmp(jnode.name, "d") == 0);
	json_istream_skip(jinput);

	ret = json_istream_descend(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_object(&jnode));
	test_assert(null_strcmp(jnode.name, "e") == 0);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_true(&jnode));
	test_assert(null_strcmp(jnode.name, "f") == 0);
	json_istream_ascend(jinput);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_null(&jnode));
	test_assert(null_strcmp(jnode.name, "g") == 0);
	json_istream_ascend(jinput);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_array(&jnode));
	test_assert(null_strcmp(jnode.name, "h") == 0);
	json_istream_skip(jinput);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret != 0);
	test_assert(json_node_is_object(&jnode));
	test_assert(null_strcmp(jnode.name, "i") == 0);
	json_istream_skip(jinput);

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret < 0);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);
}

/*
 * Test: read trickle
 */

static void test_json_istream_read_trickle(void)
{
	struct istream *input;
	struct json_istream *jinput;
	const char *text;
	struct json_node jnode;
	unsigned int pos, text_len, state;
	intmax_t num_val = 0;
	int ret = 0;

	/* number */
	text = "2234234";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read trickle - number");

	pos = 0;
	state = 0;
	while (ret >= 0 && state <= 1) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		ret = json_istream_read(jinput, &jnode);
		if (ret == 0)
			continue;
		if (ret < 0)
			break;
		test_assert(json_node_is_number(&jnode));
		test_assert(json_node_get_intmax(&jnode, &num_val) == 0);
		test_assert(num_val == 2234234);
		state++;
		json_istream_skip(jinput);
	}
	test_assert(state == 1);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* string */
	text = "\"text\"";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read trickle - string");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 1) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		ret = json_istream_read(jinput, &jnode);
		if (ret == 0)
			continue;
		if (ret < 0)
			break;
		test_assert(json_node_is_string(&jnode));
		test_assert(null_strcmp(json_node_get_str(&jnode),
					"text") == 0);
		state++;
		json_istream_skip(jinput);
	}
	test_assert(state == 1);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* array */
	text = "[\"text\"]";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read trickle - array");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 1) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		ret = json_istream_read(jinput, &jnode);
		if (ret == 0)
			continue;
		if (ret < 0)
			break;
		test_assert(json_node_is_array(&jnode));
		state++;
		json_istream_skip(jinput);
	}
	test_assert(state == 1);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* object */
	text = "{\"text\": 1}";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read trickle - object");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 1) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		ret = json_istream_read(jinput, &jnode);
		if (ret == 0)
			continue;
		if (ret < 0)
			break;
		test_assert(json_node_is_object(&jnode));
		state++;
		json_istream_skip(jinput);
	}
	test_assert(state == 1);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* array descend */
	text = "[\"text\"]";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read trickle - array descend");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 3) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_descend(jinput, &jnode);
			test_assert(ret > 0);
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 2:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(null_strcmp(json_node_get_str(&jnode),
						"text") == 0);
			json_istream_ascend(jinput);
			state++;
			break;
		case 3:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 3);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* object descend */
	text = "{\"member\": 14234234}";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read trickle - object descend");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 3) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_descend(jinput, &jnode);
			test_assert(ret > 0);
			test_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 2:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_number(&jnode));
			test_assert(json_node_get_intmax(
				&jnode, &num_val) == 0);
			test_assert(num_val == 14234234);
			test_assert(null_strcmp(jnode.name, "member") == 0);
			json_istream_ascend(jinput);
			state++;
			break;
		case 3:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 3);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* array descend one */
	text = "[\"text\",1,false,true,null,[1],{\"a\":1}]";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read trickle - array descend one");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 9) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_descend(jinput, &jnode);
			test_assert(ret > 0);
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 2:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(null_strcmp(json_node_get_str(&jnode),
						"text") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 3:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_number(&jnode));
			test_assert(json_node_get_intmax(
				&jnode, &num_val) == 0);
			test_assert(num_val == 1);
			json_istream_skip(jinput);
			state++;
			break;
		case 4:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_false(&jnode));
			json_istream_skip(jinput);
			state++;
			break;
		case 5:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_true(&jnode));
			json_istream_skip(jinput);
			state++;
			break;
		case 6:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_null(&jnode));
			json_istream_skip(jinput);
			state++;
			break;
		case 7:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			json_istream_skip(jinput);
			state++;
			break;
		case 8:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			json_istream_ascend(jinput);
			state++;
			break;
		case 9:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 9);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* object descend one */
	text = "{\"a\":\"text\",\"b\":1,\"c\":false,"
		"\"d\":true,\"e\":null,\"f\":[1],\"g\":{\"a\":1}}";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read trickle - array descend one");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 9) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_descend(jinput, &jnode);
			test_assert(ret > 0);
			test_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 2:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(null_strcmp(json_node_get_str(&jnode),
						"text") == 0);
			test_assert(null_strcmp(jnode.name, "a") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 3:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_number(&jnode));
			test_assert(json_node_get_intmax(
				&jnode, &num_val) == 0);
			test_assert(num_val == 1);
			test_assert(null_strcmp(jnode.name, "b") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 4:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_false(&jnode));
			test_assert(null_strcmp(jnode.name, "c") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 5:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_true(&jnode));
			test_assert(null_strcmp(jnode.name, "d") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 6:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_null(&jnode));
			test_assert(null_strcmp(jnode.name, "e") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 7:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			test_assert(null_strcmp(jnode.name, "f") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 8:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			test_assert(null_strcmp(jnode.name, "g") == 0);
			json_istream_ascend(jinput);
			state++;
			break;
		case 9:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 9);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* array descend deep */
	text = "[\"text\",1,[false,[true],null],[1],{\"a\":1}]";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read trickle - array descend deep");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 11) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 2:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(null_strcmp(json_node_get_str(&jnode),
						"text") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 3:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_number(&jnode));
			test_assert(json_node_get_intmax(
				&jnode, &num_val) == 0);
			test_assert(num_val == 1);
			json_istream_skip(jinput);
			state++;
			break;
		case 4:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 5:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_false(&jnode));
			json_istream_skip(jinput);
			state++;
			break;
		case 6:
			ret = json_istream_descend(jinput, &jnode);
			test_assert(ret > 0);
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 7:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_true(&jnode));
			json_istream_ascend(jinput);
			state++;
			break;
		case 8:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_null(&jnode));
			json_istream_ascend(jinput);
			state++;
			break;
		case 9:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			json_istream_skip(jinput);
			state++;
			break;
		case 10:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			json_istream_ascend(jinput);
			state++;
			break;
		case 11:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 11);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* object descend deep */
	text = "{\"a\":\"text\",\"b\":1,\"c\":{\"d\":false,"
		"\"e\":{\"f\":true},\"g\":null},\"h\":[1],\"i\":{\"a\":1}}";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read trickle - array descend deep");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 11) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_descend(jinput, &jnode);
			test_assert(ret > 0);
			test_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 2:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(null_strcmp(json_node_get_str(&jnode),
						"text") == 0);
			test_assert(null_strcmp(jnode.name, "a") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 3:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_number(&jnode));
			test_assert(json_node_get_intmax(
				&jnode, &num_val) == 0);
			test_assert(num_val == 1);
			test_assert(null_strcmp(jnode.name, "b") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 4:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			test_assert(null_strcmp(jnode.name, "c") == 0);
			state++;
			break;
		case 5:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_false(&jnode));
			test_assert(null_strcmp(jnode.name, "d") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 6:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			test_assert(null_strcmp(jnode.name, "e") == 0);
			state++;
			break;
		case 7:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_true(&jnode));
			test_assert(null_strcmp(jnode.name, "f") == 0);
			json_istream_ascend(jinput);
			state++;
			break;
		case 8:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_null(&jnode));
			test_assert(null_strcmp(jnode.name, "g") == 0);
			json_istream_ascend(jinput);
			state++;
			break;
		case 9:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			test_assert(null_strcmp(jnode.name, "h") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 10:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			test_assert(null_strcmp(jnode.name, "i") == 0);
			json_istream_ascend(jinput);
			state++;
			break;
		case 11:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 11);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* array ascend ignore */
	text = "[\"text\",1,false,true,null,[1,true,false],{\"a\":[1,2,3]}]";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read trickle - array ascend ignore");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 6) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_descend(jinput, &jnode);
			test_assert(ret > 0);
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 2:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(null_strcmp(json_node_get_str(&jnode),
						"text") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 3:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_number(&jnode));
			test_assert(json_node_get_intmax(
				&jnode, &num_val) == 0);
			test_assert(num_val == 1);
			json_istream_skip(jinput);
			state++;
			break;
		case 4:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_false(&jnode));
			json_istream_skip(jinput);
			state++;
			break;
		case 5:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_true(&jnode));
			json_istream_ascend(jinput);
			state++;
			break;
		case 6:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 6);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* object ascend ignore */
	text = "{\"a\":\"text\",\"b\":[\"bbb\",1],\"c\":false,"
		"\"d\":true,\"e\":null,\"f\":[1,2,3,4],"
		"\"g\":{\"a\":[1,false,null]}}";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read trickle - object ascend ignore");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 6) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_descend(jinput, &jnode);
			test_assert(ret > 0);
			test_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 2:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(null_strcmp(json_node_get_str(&jnode),
						"text") == 0);
			test_assert(null_strcmp(jnode.name, "a") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 3:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			test_assert(null_strcmp(jnode.name, "b") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 4:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_false(&jnode));
			test_assert(null_strcmp(jnode.name, "c") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 5:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_true(&jnode));
			test_assert(null_strcmp(jnode.name, "d") == 0);
			json_istream_ascend(jinput);
			state++;
			break;
		case 6:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 6);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* type=array */
	text = "[\"text\",1,[false,[true],null],[1],{\"a\":1}]";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create_array(input, NULL, 0);

	test_begin("json istream read trickle - type=array");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 9) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(null_strcmp(json_node_get_str(&jnode),
						"text") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 1:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_number(&jnode));
			test_assert(json_node_get_intmax(
				&jnode, &num_val) == 0);
			test_assert(num_val == 1);
			json_istream_skip(jinput);
			state++;
			break;
		case 2:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 3:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_false(&jnode));
			json_istream_skip(jinput);
			state++;
			break;
		case 4:
			ret = json_istream_descend(jinput, &jnode);
			test_assert(ret > 0);
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 5:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_true(&jnode));
			json_istream_ascend(jinput);
			state++;
			break;
		case 6:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_null(&jnode));
			json_istream_ascend(jinput);
			state++;
			break;
		case 7:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			json_istream_skip(jinput);
			state++;
			break;
		case 8:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			json_istream_skip(jinput);
			state++;
			break;
		case 9:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 9);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* type=object */
	text = "{\"a\":\"text\",\"b\":1,\"c\":{\"d\":false,"
		"\"e\":{\"f\":true},\"g\":null},\"h\":[1],\"i\":{\"a\":1}}";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create_object(input, NULL, 0);

	test_begin("json istream read trickle - type=object");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 9) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(null_strcmp(json_node_get_str(&jnode),
						"text") == 0);
			test_assert(null_strcmp(jnode.name, "a") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 1:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_number(&jnode));
			test_assert(json_node_get_intmax(
				&jnode, &num_val) == 0);
			test_assert(num_val == 1);
			test_assert(null_strcmp(jnode.name, "b") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 2:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			test_assert(null_strcmp(jnode.name, "c") == 0);
			state++;
			break;
		case 3:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_false(&jnode));
			test_assert(null_strcmp(jnode.name, "d") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 4:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			test_assert(null_strcmp(jnode.name, "e") == 0);
			state++;
			break;
		case 5:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_true(&jnode));
			test_assert(null_strcmp(jnode.name, "f") == 0);
			json_istream_ascend(jinput);
			state++;
			break;
		case 6:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_null(&jnode));
			test_assert(null_strcmp(jnode.name, "g") == 0);
			json_istream_ascend(jinput);
			state++;
			break;
		case 7:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			test_assert(null_strcmp(jnode.name, "h") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 8:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			test_assert(null_strcmp(jnode.name, "i") == 0);
			json_istream_skip(jinput);
			state++;
			break;
		case 9:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 9);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* json istream walk - object descend deep */
	text = "{\"a\":\"text\",\"b\":1,\"c\":{\"d\":false,"
		"\"e\":{\"f\":true},\"g\":null},\"h\":[1],\"i\":{\"a\":1}}";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream walk trickle - object descend deep");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 18) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_walk(jinput, &jnode);
			test_assert(ret > 0);
			test_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 2:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(null_strcmp(json_node_get_str(&jnode),
						"text") == 0);
			test_assert(null_strcmp(jnode.name, "a") == 0);
			state++;
			break;
		case 3:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_number(&jnode));
			test_assert(json_node_get_intmax(
				&jnode, &num_val) == 0);
			test_assert(num_val == 1);
			test_assert(null_strcmp(jnode.name, "b") == 0);
			state++;
			break;
		case 4:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			test_assert(null_strcmp(jnode.name, "c") == 0);
			state++;
			break;
		case 5:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_false(&jnode));
			test_assert(null_strcmp(jnode.name, "d") == 0);
			state++;
			break;
		case 6:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			test_assert(null_strcmp(jnode.name, "e") == 0);
			state++;
			break;
		case 7:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_true(&jnode));
			test_assert(null_strcmp(jnode.name, "f") == 0);
			state++;
			break;
		case 8:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object_end(&jnode));
			state++;
			break;
		case 9:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_null(&jnode));
			test_assert(null_strcmp(jnode.name, "g") == 0);
			state++;
			break;
		case 10:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object_end(&jnode));
			state++;
			break;
		case 11:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			test_assert(null_strcmp(jnode.name, "h") == 0);
			state++;
			break;
		case 12:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_number(&jnode));
			test_assert(json_node_get_intmax(
				&jnode, &num_val) == 0);
			test_assert(num_val == 1);
			state++;
			break;
		case 13:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array_end(&jnode));
			state++;
			break;
		case 14:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			test_assert(null_strcmp(jnode.name, "i") == 0);
			state++;
			break;
		case 15:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_number(&jnode));
			test_assert(json_node_get_intmax(
				&jnode, &num_val) == 0);
			test_assert(num_val == 1);
			test_assert(null_strcmp(jnode.name, "a") == 0);
			state++;
			break;
		case 16:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object_end(&jnode));
			state++;
			break;
		case 17:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object_end(&jnode));
			state++;
			break;
		case 18:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 18);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);
}

/*
 * Test: finish
 */

static void test_json_istream_finish(void)
{
	struct istream *input;
	struct json_istream *jinput;
	const char *text, *error;
	struct json_node jnode;
	unsigned int pos, text_len, state;
	int ret = 0;

	/* json istream finish buffer */
	text = "{\"a\":\"text\",\"b\":1,\"c\":{\"d\":false,"
		"\"e\":{\"f\":true},\"g\":null},\"h\":[1],\"i\":{\"a\":1}}";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create_object(input, NULL, 0);

	test_begin("json istream finish buffer");

	ret = json_istream_read(jinput, &jnode);
	i_assert(ret >= 0);
	test_assert(json_node_is_string(&jnode));
	test_assert(null_strcmp(json_node_get_str(&jnode), "text") == 0);
	test_assert(null_strcmp(jnode.name, "a") == 0);
	json_istream_skip(jinput);

	ret = json_istream_finish(&jinput, &error);
	test_out_reason_quiet("read success", ret > 0,
			      (ret == 0 ? "ret == 0" : error));

	test_end();

	json_istream_destroy(&jinput);
	i_stream_unref(&input);

	/* json istream finish trickle */
	text = "{\"a\":\"text\",\"b\":1,\"c\":{\"d\":false,"
		"\"e\":{\"f\":true},\"g\":null},\"h\":[1],\"i\":{\"a\":1}}";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream finish trickle");

	ret = 0; pos = 0; state = 0;
	while (ret >= 0 && state <= 3) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_walk(jinput, &jnode);
			test_assert(ret > 0);
			test_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 2:
			ret = json_istream_walk(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(null_strcmp(json_node_get_str(&jnode),
						"text") == 0);
			test_assert(null_strcmp(jnode.name, "a") == 0);
			state++;
			break;
		case 3:
			ret = json_istream_finish(&jinput, &error);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_out_reason_quiet("read success", ret > 0,
			      (error != NULL || jinput == NULL ? error :
			       json_istream_get_error(jinput)));
	test_assert(state == 4);

	test_end();

	json_istream_destroy(&jinput);
	i_stream_unref(&input);
}

/*
 * Test: read tree
 */

static void test_json_istream_read_tree(void)
{
	struct istream *input;
	struct json_istream *jinput;
	const char *text;
	struct json_tree *jtree;
	struct json_tree_node *jtnode;
	struct json_node jnode;
	unsigned int pos, text_len, state;
	int ret = 0;

	/* number */
	text = "2234234";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read tree - number");

	pos = 0; state = 0; ret = 0;
	while (ret >= 0 && state <= 1) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		ret = json_istream_read_tree(jinput, &jtree);
		if (ret == 0)
			continue;
		if (ret < 0)
			break;
		jtnode = json_tree_get_root(jtree);
		test_assert(json_tree_node_get_type(jtnode) ==
			    JSON_TYPE_NUMBER);
		test_assert(json_tree_node_get_next(jtnode) == NULL);
		json_tree_unref(&jtree);
		state++;
	}
	test_assert(state == 1);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* string */
	text = "\"frop\"";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read tree - string");

	pos = 0; state = 0; ret = 0;
	while (ret >= 0 && state <= 1) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		ret = json_istream_read_tree(jinput, &jtree);
		if (ret == 0)
			continue;
		if (ret < 0)
			break;
		jtnode = json_tree_get_root(jtree);
		test_assert(json_tree_node_get_type(jtnode) ==
			    JSON_TYPE_STRING);
		test_assert(json_tree_node_get_next(jtnode) == NULL);
		json_tree_unref(&jtree);
		state++;
	}
	test_assert(state == 1);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* array */
	text = "[\"frop\"]";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read tree - array");

	pos = 0; state = 0; ret = 0;
	while (ret >= 0 && state <= 1) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		ret = json_istream_read_tree(jinput, &jtree);
		if (ret == 0)
			continue;
		if (ret < 0)
			break;
		jtnode = json_tree_get_root(jtree);
		test_assert(json_tree_node_get_type(jtnode) ==
			    JSON_TYPE_ARRAY);
		jtnode = json_tree_node_get_child(jtnode);
		test_assert(json_tree_node_get_type(jtnode) ==
			    JSON_TYPE_STRING);
		test_assert(json_tree_node_get_next(jtnode) == NULL);
		jtnode = json_tree_node_get_parent(jtnode);
		test_assert(json_tree_node_get_type(jtnode) ==
			    JSON_TYPE_ARRAY);
		test_assert(json_tree_node_get_next(jtnode) == NULL);
		json_tree_unref(&jtree);
		state++;
	}
	test_assert(state == 1);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* array */
	text = "[\"frop\", {\"a\":1234, \"b\":[1, 2, 3, 4], "
		"\"c\":1234}, \"frop\"]";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read tree - sequence");

	pos = 0; state = 0; ret = 0;
	while (ret >= 0 && state <= 4) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_read_tree(jinput, &jtree);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			jtnode = json_tree_get_root(jtree);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_STRING);
			test_assert(json_tree_node_get_next(jtnode) == NULL);
			json_tree_unref(&jtree);
			state++;
			break;
		case 2:
			ret = json_istream_read_tree(jinput, &jtree);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			jtnode = json_tree_get_root(jtree);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_OBJECT);
			jtnode = json_tree_node_get_child(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_NUMBER);
			jtnode = json_tree_node_get_next(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_ARRAY);
			jtnode = json_tree_node_get_child(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_NUMBER);
			jtnode = json_tree_node_get_next(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_NUMBER);
			jtnode = json_tree_node_get_next(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_NUMBER);
			jtnode = json_tree_node_get_next(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_NUMBER);
			test_assert(json_tree_node_get_next(jtnode) == NULL);
			jtnode = json_tree_node_get_parent(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_ARRAY);
			jtnode = json_tree_node_get_next(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_NUMBER);
			test_assert(json_tree_node_get_next(jtnode) == NULL);
			jtnode = json_tree_node_get_parent(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_OBJECT);
			test_assert(json_tree_node_get_next(jtnode) == NULL);
			json_tree_unref(&jtree);
			state++;
			break;
		case 3:
			ret = json_istream_read_tree(jinput, &jtree);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			jtnode = json_tree_get_root(jtree);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_STRING);
			test_assert(json_tree_node_get_next(jtnode) == NULL);
			json_tree_unref(&jtree);
			json_istream_ascend(jinput);
			state++;
			break;
		case 4:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 4);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);
}

/*
 * Test: read into tree
 */

static void test_json_istream_read_into_tree(void)
{
	struct istream *input;
	struct json_istream *jinput;
	const char *text;
	struct json_tree *jtree;
	struct json_node jnode;
	struct json_tree_node *jtnode;
	unsigned int pos, text_len, state;
	int ret = 0;

	/* number */
	jtree = json_tree_create();
	text = "2234234";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read into tree - number");

	pos = 0; state = 0; ret = 0;
	while (ret >= 0 && state <= 1) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		ret = json_istream_read_into_tree(jinput, jtree);
		if (ret == 0)
			continue;
		if (ret < 0)
			break;
		jtnode = json_tree_get_root(jtree);
		test_assert(json_tree_node_get_type(jtnode) ==
			    JSON_TYPE_NUMBER);
		test_assert(json_tree_node_get_next(jtnode) == NULL);
		state++;
	}
	test_assert(state == 1);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);
	json_tree_unref(&jtree);

	/* string */
	jtree = json_tree_create();
	text = "\"frop\"";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read into tree - string");

	pos = 0; state = 0; ret = 0;
	while (ret >= 0 && state <= 1) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		ret = json_istream_read_into_tree(jinput, jtree);
		if (ret == 0)
			continue;
		if (ret < 0)
			break;
		jtnode = json_tree_get_root(jtree);
		test_assert(json_tree_node_get_type(jtnode) ==
			    JSON_TYPE_STRING);
		test_assert(json_tree_node_get_next(jtnode) == NULL);
		state++;
	}
	test_assert(state == 1);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);
	json_tree_unref(&jtree);

	/* array */
	jtree = json_tree_create();
	text = "[\"frop\"]";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read into tree - array");

	pos = 0; state = 0; ret = 0;
	while (ret >= 0 && state <= 1) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		ret = json_istream_read_into_tree(jinput, jtree);
		if (ret == 0)
			continue;
		if (ret < 0)
			break;
		jtnode = json_tree_get_root(jtree);
		test_assert(json_tree_node_get_type(jtnode) ==
			    JSON_TYPE_ARRAY);
		jtnode = json_tree_node_get_child(jtnode);
		test_assert(json_tree_node_get_type(jtnode) ==
			    JSON_TYPE_STRING);
		test_assert(json_tree_node_get_next(jtnode) == NULL);
		jtnode = json_tree_node_get_parent(jtnode);
		test_assert(json_tree_node_get_type(jtnode) ==
			    JSON_TYPE_ARRAY);
		test_assert(json_tree_node_get_next(jtnode) == NULL);
		state++;
	}
	test_assert(state == 1);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);
	json_tree_unref(&jtree);

	/* sequence */
	jtree = json_tree_create();
	json_tree_node_add_array(json_tree_get_root(jtree), NULL);
	text = "[\"frop\", {\"a\":1234, \"b\":[1, 2, 3, 4], "
		"\"c\":1234}, \"frop\"]";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read into tree - sequence");

	pos = 0; state = 0; ret = 0;
	while (ret >= 0 && state <= 4) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_read_into_tree(jinput, jtree);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		case 2:
			ret = json_istream_read_into_tree(jinput, jtree);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		case 3:
			ret = json_istream_read_into_tree(jinput, jtree);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		case 4:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;

			jtnode = json_tree_get_root(jtree);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_ARRAY);
			jtnode = json_tree_node_get_child(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_STRING);
			jtnode = json_tree_node_get_next(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_OBJECT);
			jtnode = json_tree_node_get_child(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_NUMBER);
			test_assert_strcmp(json_tree_node_get_name(jtnode),
					   "a");
			jtnode = json_tree_node_get_next(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_ARRAY);
			test_assert_strcmp(json_tree_node_get_name(jtnode),
					   "b");
			jtnode = json_tree_node_get_child(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_NUMBER);
			jtnode = json_tree_node_get_next(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_NUMBER);
			jtnode = json_tree_node_get_next(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_NUMBER);
			jtnode = json_tree_node_get_next(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_NUMBER);
			test_assert(json_tree_node_get_next(jtnode) == NULL);
			jtnode = json_tree_node_get_parent(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_ARRAY);
			jtnode = json_tree_node_get_next(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_NUMBER);
			test_assert_strcmp(json_tree_node_get_name(jtnode),
					   "c");
			test_assert(json_tree_node_get_next(jtnode) == NULL);
			jtnode = json_tree_node_get_parent(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_OBJECT);
			jtnode = json_tree_node_get_next(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_STRING);
			test_assert(json_tree_node_get_next(jtnode) == NULL);
			jtnode = json_tree_node_get_parent(jtnode);
			test_assert(json_tree_node_get_type(jtnode) ==
				    JSON_TYPE_ARRAY);
			test_assert(json_tree_node_get_next(jtnode) == NULL);

			json_istream_ascend(jinput);
			state++;
			break;
		}
	}
	test_assert(state == 5);
	test_istream_set_size(input, text_len);
	test_json_read_success(&jinput);

	test_end();

	i_stream_unref(&input);
	json_tree_unref(&jtree);
}

/*
 * Test: read stream
 */

static void test_json_istream_read_stream(void)
{
	struct istream *input, *val_input;
	struct json_istream *jinput;
	const char *str_text, *text;
	struct json_node jnode;
	unsigned int pos, text_len, state;
	string_t *buffer;
	int ret = 0;

	buffer = str_new(default_pool, 256);

	str_text =
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789";

	text = "[\"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789\"]";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read stream (array)");

	pos = 0; state = 0; ret = 0;
	val_input = NULL;
	while (ret >= 0 && state <= 2) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_read_stream(
				jinput, 0, IO_BLOCK_SIZE,
				"/tmp/dovecot-test-json.", &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(jnode.value.content_type ==
				    JSON_CONTENT_TYPE_STREAM);
			test_assert(jnode.value.content.stream != NULL);
			val_input = jnode.value.content.stream;
			i_stream_ref(val_input);
			json_istream_ascend(jinput);
			state++;
			break;
		case 2:
			ret = json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 2);

	test_assert(val_input != NULL);
	if (!test_has_failed() && val_input != NULL) {
		const unsigned char *data;
		size_t size;

		while ((ret = i_stream_read_more(val_input,
						 &data, &size)) > 0) {
			buffer_append(buffer, data, size);
			i_stream_skip(val_input, size);
		}
		if (ret < 0) {
			test_assert(!i_stream_have_bytes_left(val_input));
			test_assert_cmp(val_input->stream_errno, ==, 0);
			i_stream_unref(&val_input);
		}
	}
	test_out_quiet("stream output", strcmp(str_c(buffer), str_text) == 0);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	str_truncate(buffer, 0);

	text = "[[{\"data\": \"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789"
		"012345678901234567890123456789\"}, \"frop\"]]";
	text_len = strlen(text);

	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream read stream (object)");

	pos = 0; state = 0; ret = 0;
	val_input = NULL;
	while (ret >= 0 && state <= 8) {
		if (pos <= text_len)
			pos++;
		test_istream_set_size(input, pos);
		switch (state) {
		case 0:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			i_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 1:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			i_assert(json_node_is_array(&jnode));
			state++;
			break;
		case 2:
			ret = json_istream_descend(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			i_assert(json_node_is_object(&jnode));
			state++;
			break;
		case 3:
			ret = json_istream_read_stream(
				jinput, 0, IO_BLOCK_SIZE,
				"/tmp/dovecot-test-json.", &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			test_assert(json_node_is_string(&jnode));
			test_assert(jnode.value.content_type ==
				    JSON_CONTENT_TYPE_STREAM);
			test_assert(jnode.value.content.stream != NULL);
			val_input = jnode.value.content.stream;
			i_stream_ref(val_input);
			json_istream_skip(jinput);
			state++;
			break;
		case 4:
			ret = json_istream_read_next(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			i_assert(json_node_is_object_end(&jnode));
			json_istream_ascend(jinput);
			state++;
			break;
		case 5:
			ret = json_istream_read_next(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			i_assert(json_node_is_string(&jnode));
			state++;
			break;
		case 6:
			ret = json_istream_read_next(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			i_assert(json_node_is_array_end(&jnode));
			json_istream_ascend(jinput);
			state++;
			break;
		case 7:
			ret = json_istream_read_next(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			i_assert(json_node_is_array_end(&jnode));
			json_istream_ascend(jinput);
			state++;
			break;
		case 8:
			ret = json_istream_read_next(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret < 0)
				break;
			state++;
			break;
		}
	}
	test_assert(state == 8);

	test_assert(val_input != NULL);
	if (!test_has_failed() && val_input != NULL) {
		const unsigned char *data;
		size_t size;

		while ((ret = i_stream_read_more(val_input,
						 &data, &size)) > 0) {
			buffer_append(buffer, data, size);
			i_stream_skip(val_input, size);
		}
		if (ret < 0) {
			test_assert(!i_stream_have_bytes_left(val_input));
			test_assert_cmp(val_input->stream_errno, ==, 0);
			i_stream_unref(&val_input);
		}
	}
	test_out_quiet("stream output", strcmp(str_c(buffer), str_text) == 0);
	test_json_read_success(&jinput);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	str_free(&buffer);
}

/*
 * Test: tokens
 */

static const char test_json_tokens_input[] =
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
	"\"key13\": \"\\ud801\\udc37\","
	"\"key14\": \"\xd8\xb3\xd9\x84\xd8\xa7\xd9\x85\","
	"\"key15\": \"\\u10000\""
	"}\n";

static struct json_node test_json_tokens_output[] = {
	{
		.name = "key", .type = JSON_TYPE_STRING,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STRING,
			.content = { .str = "string" } },
	}, {
		.name = "key2", .type = JSON_TYPE_NUMBER,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STRING,
			.content = { .str = "1234" } },
	}, {
		.name = "key3", .type = JSON_TYPE_TRUE,
		.value = {
			.content_type = JSON_CONTENT_TYPE_NONE },
	}, {
		.name = "key4", .type = JSON_TYPE_FALSE,
		.value = {
			.content_type = JSON_CONTENT_TYPE_NONE },
	}, {
		.name = "skip1", .type = JSON_TYPE_NONE,
	}, {
		.name = "skip2", .type = JSON_TYPE_NONE,
	}, {
		.name = "key5", .type = JSON_TYPE_NULL,
		.value = {
			.content_type = JSON_CONTENT_TYPE_NONE },
	}, {
		.name = "key6", .type = JSON_TYPE_OBJECT,
		.value = {
			.content_type = JSON_CONTENT_TYPE_LIST },
	}, {
		.type = JSON_TYPE_OBJECT,
		.value = {
			.content_type = JSON_CONTENT_TYPE_NONE },
	}, {
		.name = "key7", .type = JSON_TYPE_OBJECT,
		.value = {
			.content_type = JSON_CONTENT_TYPE_LIST },
	}, {
		.name = "sub1", .type = JSON_TYPE_STRING,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STRING,
			.content = { .str = "value" } },
	}, {
		.type = JSON_TYPE_OBJECT,
		.value = {
			.content_type = JSON_CONTENT_TYPE_NONE },
	}, {
		.name = "key8", .type = JSON_TYPE_OBJECT,
		.value = {
			.content_type = JSON_CONTENT_TYPE_LIST },
	}, {
		.name = "sub2", .type = JSON_TYPE_NUMBER,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STRING,
			.content = { .str = "-12.456" } },
	}, {
		.name = "sub3", .type = JSON_TYPE_NUMBER,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STRING,
			.content = { .str = "12.456e9" } },
	}, {
		.name = "sub4", .type = JSON_TYPE_NUMBER,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STRING,
			.content = { .str = "0.456e-789" } },
	}, {
		.type = JSON_TYPE_OBJECT,
		.value = {
			.content_type = JSON_CONTENT_TYPE_NONE },
	}, {
		.name = "key9", .type = JSON_TYPE_STRING,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STRING,
			.content = {
				.str = "foo\\\"\b\f\n\r\t\001\xe1\x83\xbf" } },
	}, {
		.name = "key10", .type = JSON_TYPE_STRING,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STREAM,
			.content = {
				.str = "foo\\\"\b\f\n\r\t\001\xe1\x83\xbf" } },
	}, {
		.name = "key11", .type = JSON_TYPE_ARRAY,
		.value = {
			.content_type = JSON_CONTENT_TYPE_LIST },
	}, {
		.type = JSON_TYPE_ARRAY,
		.value = {
			.content_type = JSON_CONTENT_TYPE_NONE },
	}, {
		.name = "key12", .type = JSON_TYPE_ARRAY,
		.value = {
			.content_type = JSON_CONTENT_TYPE_LIST },
	}, {
		.type = JSON_TYPE_STRING,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STRING,
			.content = {
				.str = "foo" } },
	}, {
		.type = JSON_TYPE_NUMBER,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STRING,
			.content = {
				.str = "5.24" } },
	}, {
		.type = JSON_TYPE_ARRAY,
		.value = {
			.content_type = JSON_CONTENT_TYPE_LIST },
	}, {
		.type = JSON_TYPE_TRUE,
		.value = {
			.content_type = JSON_CONTENT_TYPE_NONE },
	}, {
		.type = JSON_TYPE_ARRAY,
		.value = {
			.content_type = JSON_CONTENT_TYPE_NONE },
	}, {
		.type = JSON_TYPE_OBJECT,
		.value = {
			.content_type = JSON_CONTENT_TYPE_LIST },
	}, {
		.name = "aobj", .type = JSON_TYPE_ARRAY,
		.value = {
			.content_type = JSON_CONTENT_TYPE_LIST },
	}, {
		.type = JSON_TYPE_ARRAY,
		.value = {
			.content_type = JSON_CONTENT_TYPE_NONE },
	}, {
		.type = JSON_TYPE_OBJECT,
		.value = {
			.content_type = JSON_CONTENT_TYPE_NONE },
	}, {
		.type = JSON_TYPE_ARRAY,
		.value = {
			.content_type = JSON_CONTENT_TYPE_NONE },
	}, {
		.name = "key13", .type = JSON_TYPE_STRING,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STRING,
			.content = { .str = "\xf0\x90\x90\xb7" } },
	}, {
		.name = "key14", .type = JSON_TYPE_STRING,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STRING,
			.content = {
				.str = "\xd8\xb3\xd9\x84\xd8\xa7\xd9\x85" } },
	}, {
		.name = "key15", .type = JSON_TYPE_STRING,
		.value = {
			.content_type = JSON_CONTENT_TYPE_STRING,
			.content = { .str = "\xe1\x80\x80""0" } },
	}
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

static void test_json_istream_tokens(bool full_size)
{
	struct json_istream *jinput;
	struct istream *input, *jsoninput = NULL;
	struct json_node jnode;
	const char *value;
	unsigned int i, pos, json_input_len = strlen(test_json_tokens_input);
	unsigned int ntokens = N_ELEMENTS(test_json_tokens_output);
	int ret = 0;

	input = test_istream_create_data(test_json_tokens_input,
					 json_input_len);
	test_istream_set_allow_eof(input, FALSE);
	jinput = json_istream_create_object(
		input, NULL, JSON_PARSER_FLAG_NUMBERS_AS_STRING);

	i = full_size ? json_input_len : 0;
	for (pos = 0; i <= json_input_len; i++) {
		test_istream_set_size(input, i);

		for (;;) {
			const struct json_node *test_output =
				&test_json_tokens_output[pos];

			value = NULL;
			if (pos < ntokens &&
			    test_output->type == JSON_TYPE_NONE) {
				json_istream_ignore(jinput, 1);
				pos++;
				continue;
			} else if (pos == ntokens ||
				   test_output->value.content_type !=
					JSON_CONTENT_TYPE_STREAM) {
				ret = json_istream_walk(jinput, &jnode);
				if (ret > 0 &&
				    test_output->value.content_type ==
					JSON_CONTENT_TYPE_STRING)
					value = jnode.value.content.str;
			} else {
				if (jsoninput != NULL)
					ret = 1;
				else {
					ret = json_istream_read_next_stream(
						jinput, 0, 1024, NULL, &jnode);
					if (ret > 0 &&
					    json_node_get_stream(
						&jnode, &jsoninput) < 0)
						ret = -1;
				}

				if (ret > 0 && jsoninput != NULL) {
					ret = stream_read_value(&jsoninput,
								&value);
				}
			}
			if (ret <= 0)
				break;

			i_assert(pos < ntokens);
			test_assert_idx(test_output->type == jnode.type, pos);
			test_assert_idx(test_output->value.content_type ==
					jnode.value.content_type, pos);
			test_assert_idx(
				null_strcmp(test_output->name,
					    jnode.name) == 0, pos);
			test_assert_idx(
				test_output->value.content_type !=
					JSON_CONTENT_TYPE_STRING ||
				null_strcmp(test_output->value.content.str,
					    value) == 0, pos);

			pos++;
		}
		test_assert_idx(ret == 0, pos);
	}
	test_assert(pos == N_ELEMENTS(test_json_tokens_output));
	test_istream_set_allow_eof(input, TRUE);
	ret = json_istream_read_next(jinput, &jnode);
	test_assert(ret < 0);
	test_json_read_success(&jinput);

	json_istream_unref(&jinput);
	i_stream_unref(&input);
}

static void test_json_istream_tokens_buffer(void)
{
	test_begin("json istream tokens (buffer)");
	test_json_istream_tokens(TRUE);
	test_end();
}

static void test_json_istream_tokens_trickle(void)
{
	test_begin("json istream tokens (trickle)");
	test_json_istream_tokens(FALSE);
	test_end();
}

/*
 * Test: skip array
 */

static void test_json_istream_skip_array(void)
{
	static const char *test_input =
		"[ 1, {\"foo\": 1 }, 2, \"bar\", 3, "
		"1.234, 4, [], 5, [[]], 6, true ]";
	struct istream *input;
	struct json_istream *jinput;
	struct json_node jnode;
	intmax_t num;
	int ret, i;

	test_begin("json istream skip array");

	input = test_istream_create_data(test_input, strlen(test_input));
	jinput = json_istream_create_array(input, NULL, 0);
	for (i = 1; i <= 6; i++) {
		ret = json_istream_read_next(jinput, &jnode);
		test_assert(ret > 0 && jnode.type == JSON_TYPE_NUMBER &&
			    json_node_get_intmax(&jnode, &num) == 0 &&
			    num == i);
		json_istream_ignore(jinput, 1);
	}

	ret = json_istream_read_next(jinput, &jnode);
	test_assert(ret < 0);
	test_assert(json_istream_is_at_end(jinput));
	test_json_read_success(&jinput);

	json_istream_destroy(&jinput);
	i_stream_unref(&input);

	test_end();
}

/*
 * Test: skip object fields
 */

static void test_json_istream_skip_object_fields(void)
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
	struct istream *input;
	struct json_istream *jinput;
	struct json_node jnode;
	const char *key;
	unsigned int i;
	size_t pos;
	int ret;

	test_begin("json istream skip object fields (by key)");

	input = test_istream_create_data(test_input, strlen(test_input));
	jinput = json_istream_create_object(input, NULL, 0);
	for (i = 0; i < keys_count; i++) {
		ret =  json_istream_read_object_member(jinput, &key);
		if (ret < 0)
			break;
		test_assert(ret > 0);
		test_assert(strcmp(key, keys[i]) == 0);
		json_istream_skip(jinput);
	}
	ret =  json_istream_read_object_member(jinput, &key);
	test_assert(ret < 0);
	test_assert(json_istream_is_at_end(jinput));
	test_json_read_success(&jinput);

	json_istream_destroy(&jinput);
	i_stream_unref(&input);

	i = 0;
	input = test_istream_create_data(test_input, strlen(test_input));
	jinput = json_istream_create_object(input, NULL, 0);
	for (pos = 0; pos <= strlen(test_input); pos +=2) {
		test_istream_set_size(input, pos);
		ret =  json_istream_read_object_member(jinput, &key);
		if (ret == 0)
			continue;
		if (ret < 0)
			break;
		i_assert(i < keys_count);
		test_assert(strcmp(key, keys[i]) == 0);
		json_istream_skip(jinput);
		i++;
	}
	ret =  json_istream_read_object_member(jinput, &key);
	test_assert(ret < 0);
	test_assert(json_istream_is_at_end(jinput));
	test_json_read_success(&jinput);

	json_istream_destroy(&jinput);
	i_stream_unref(&input);

	test_end();

	test_begin("json istream skip object fields (by value type)");

	input = test_istream_create_data(test_input, strlen(test_input));
	jinput = json_istream_create_object(input, NULL, 0);
	for (i = 0; i < keys_count; i++) {
		ret =  json_istream_read_object_member(jinput, &key);
		if (ret < 0)
			break;
		test_assert(ret > 0);
		test_assert(strcmp(key, keys[i]) == 0);
		ret =  json_istream_read(jinput, &jnode);
		test_assert(ret > 0);
		test_assert(strcmp(jnode.name, keys[i]) == 0);
		json_istream_skip(jinput);
	}
	ret =  json_istream_read_object_member(jinput, &key);
	test_assert(ret < 0);
	test_assert(json_istream_is_at_end(jinput));
	test_json_read_success(&jinput);

	json_istream_destroy(&jinput);
	i_stream_unref(&input);

	i = 0;
	input = test_istream_create_data(test_input, strlen(test_input));
	jinput = json_istream_create_object(input, NULL, 0);
	for (;;) {
		for (pos = 0; pos <= strlen(test_input); pos +=2) {
			test_istream_set_size(input, pos);
			ret =  json_istream_read_object_member(jinput, &key);
			if (ret == 0)
				continue;
			if (ret > 0) {
				i_assert(i < keys_count);
				test_assert(strcmp(key, keys[i]) == 0);
			}
			break;
		}
		if (ret < 0)
			break;
		for (pos = 0; pos <= strlen(test_input); pos +=2) {
			test_istream_set_size(input, pos);
			ret =  json_istream_read(jinput, &jnode);
			if (ret == 0)
				continue;
			if (ret > 0) {
				i_assert(i < keys_count);
				test_assert(strcmp(jnode.name, keys[i]) == 0);
				i++;
			}
			break;
		}
		if (ret < 0)
			break;
		json_istream_skip(jinput);
	}
	ret =  json_istream_read_object_member(jinput, &key);
	test_assert(ret < 0);
	test_assert(json_istream_is_at_end(jinput));
	test_json_read_success(&jinput);

	json_istream_destroy(&jinput);
	i_stream_unref(&input);

	test_end();
}

/*
 * Test: error
 */

static void test_json_istream_error(void)
{
	struct istream *input, *err_input, *val_input;
	struct json_istream *jinput;
	const char *text, *error;
	struct json_node jnode;
	struct json_tree *jtree;
	unsigned int text_len;
	int ret = 0;

	/* stream error */
	text = "[\"array\"]";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	err_input = i_stream_create_failure_at(input, 5, EIO, "IO Error");
	i_stream_unref(&input);
	jinput = json_istream_create(err_input, 0, NULL, 0);
	i_stream_unref(&err_input);

	test_begin("json istream error - stream error");

	ret = json_istream_read(jinput, &jnode);
	test_out_reason_quiet("read success", ret > 0,
			      json_istream_get_error(jinput));
	test_assert(json_node_is_array(&jnode));
	ret = json_istream_descend(jinput, &jnode);
	test_out_reason_quiet("read success", ret > 0,
			      json_istream_get_error(jinput));
	test_assert(json_node_is_array(&jnode));
	ret = json_istream_read(jinput, &jnode);
	test_assert(ret != 0);
	ret = json_istream_read(jinput, &jnode);
	error = json_istream_get_error(jinput);
	test_out_reason("read failure", (ret < 0 && error != NULL), error);

	test_end();

	json_istream_unref(&jinput);

	/* parse error */
	text = "[\"unclosed array\"";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream error - parse error");

	ret = json_istream_read(jinput, &jnode);
	test_out_reason_quiet("read success", ret > 0,
			      json_istream_get_error(jinput));
	test_assert(json_node_is_array(&jnode));
	ret = json_istream_descend(jinput, &jnode);
	test_out_reason_quiet("read success", ret > 0,
			      json_istream_get_error(jinput));
	test_assert(json_node_is_array(&jnode));
	ret = json_istream_read(jinput, &jnode);
	test_out_reason_quiet("read success", ret > 0,
			      json_istream_get_error(jinput));
	test_assert(json_node_is_string(&jnode));
	json_istream_skip(jinput);
	ret = json_istream_read(jinput, &jnode);
	error = json_istream_get_error(jinput);
	test_out_reason("read failure", (ret < 0 && error != NULL), error);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* tree parse error */
	text = "{\"a\":[0],\"b\":[1],\"c\":[2],\"d\":[\"unclosed array\"}";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream error - tree parse error");

	ret = json_istream_read_tree(jinput, &jtree);
	error = json_istream_get_error(jinput);
	test_out_reason("read failure", (ret < 0 && error != NULL), error);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* spurious data at end of input */
	text = "[\"data\"][\"junk\"]";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream error - spurious data at end of input");

	ret = json_istream_read(jinput, &jnode);
	test_out_reason_quiet("read success", ret > 0,
			      json_istream_get_error(jinput));
	test_assert(json_node_is_array(&jnode));
	ret = json_istream_descend(jinput, &jnode);
	test_out_reason_quiet("read success", ret > 0,
			      json_istream_get_error(jinput));
	test_assert(json_node_is_array(&jnode));
	ret = json_istream_read(jinput, &jnode);
	test_out_reason_quiet("read success", ret > 0,
			      json_istream_get_error(jinput));
	test_assert(json_node_is_string(&jnode));
	json_istream_skip(jinput);
	ret = json_istream_read(jinput, &jnode);
	test_out_reason_quiet("read success", ret > 0,
			      json_istream_get_error(jinput));
	test_assert(json_node_is_array_end(&jnode));
	json_istream_ascend(jinput);
	ret = json_istream_finish(&jinput, &error);
	test_out_reason("finish failure", (ret < 0 && error != NULL), error);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* root not array */
	text = "\"string\"";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create_array(input, NULL, 0);

	test_begin("json istream error - root not array");

	ret = json_istream_read(jinput, &jnode);
	error = json_istream_get_error(jinput);
	test_out_reason("read failure", (ret < 0 && error != NULL), error);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* root not object */
	text = "[\"string\"]";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create_object(input, NULL, 0);

	test_begin("json istream error - root not object");

	ret = json_istream_read(jinput, &jnode);
	error = json_istream_get_error(jinput);
	test_out_reason("read failure", (ret < 0 && error != NULL), error);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* bad string stream */
	text = "\"\xed\xa2\xab <-- encoded surrogate half\"";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream error - bad string stream");

	ret = json_istream_read_stream(jinput, 0, 16, NULL, &jnode);
	error = json_istream_get_error(jinput);
	test_out_reason("read failure", (ret < 0 && error != NULL), error);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* bad string seekable stream */
	text = "\"\xed\xa2\xab <-- encoded surrogate half\"";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream error - bad seekable string stream");

	ret = json_istream_read_stream(jinput, 0, IO_BLOCK_SIZE,
					"/tmp/dovecot-test-json.", &jnode);
	test_assert(ret != 0);
	ret = json_istream_read(jinput, &jnode);	
	error = json_istream_get_error(jinput);
	test_out_reason("read failure", (ret < 0 && error != NULL), error);

	test_end();

	json_istream_unref(&jinput);
	i_stream_unref(&input);

	/* string stream with bad end */
	text = "\"bladiebladiebladiebladiebladiebladiebladiebla \xed\xa2\xab\"";
	text_len = strlen(text);

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	test_begin("json istream error - string stream with bad end");

	ret = json_istream_read_stream(jinput, 0, 16,
					"/tmp/dovecot-test-json.", &jnode);
	test_out_reason_quiet("read success", ret > 0,
			      json_istream_get_error(jinput));
	test_assert(json_node_is_string(&jnode));
	test_assert(jnode.value.content_type == JSON_CONTENT_TYPE_STREAM);
	test_assert(jnode.value.content.stream != NULL);
	val_input = jnode.value.content.stream;
	if (val_input != NULL)
		i_stream_ref(val_input);
	json_istream_skip(jinput);
	ret = json_istream_read(jinput, &jnode);	
	error = json_istream_get_error(jinput);
	test_out_reason("read failure", (ret < 0 && error != NULL), error);

	test_end();

	i_stream_unref(&val_input);
	json_istream_unref(&jinput);
	i_stream_unref(&input);
}

/*
 * Main
 */

int main(int argc, char *argv[])
{
	int c;

	static void (*test_functions[])(void) = {
		test_json_istream_read_number,
		test_json_istream_read_string,
		test_json_istream_read_buffer,
		test_json_istream_read_trickle,
		test_json_istream_finish,
		test_json_istream_read_tree,
		test_json_istream_read_into_tree,
		test_json_istream_read_stream,
		test_json_istream_tokens_buffer,
		test_json_istream_tokens_trickle,
		test_json_istream_skip_array,
		test_json_istream_skip_object_fields,
		test_json_istream_error,
		NULL
	};

	while ((c = getopt(argc, argv, "D")) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			i_fatal("Usage: %s [-D]", argv[0]);
		}
	}

	return test_run(test_functions);
}
