/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"

#include "json-ostream.h"

#include <unistd.h>

static bool debug = FALSE;

static void test_json_ostream_write(void)
{
	string_t *buffer;
	struct istream *input;
	struct ostream *output;
	struct json_ostream *joutput;
	const char *data;
	unsigned int state, pos;
	int ret;

	buffer = str_new(default_pool, 256);
	output = o_stream_create_buffer(buffer);
	o_stream_set_no_error_handling(output, TRUE);

	/* number */
	test_begin("json ostream write - number");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_write_number(joutput, NULL, 23423);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("23423", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* false */
	test_begin("json ostream write - false");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_write_false(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("false", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* false */
	test_begin("json ostream write - null");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_write_null(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("null", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* true */
	test_begin("json ostream write - true");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_write_true(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("true", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string */
	test_begin("json ostream write - string");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_write_string(joutput, NULL, "frop!");
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("\"frop!\"", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string stream */
	test_begin("json ostream write - string stream");
	joutput = json_ostream_create(output, 0);
	data = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ";
	input = i_stream_create_from_data(data, strlen(data));
	ret = json_ostream_write_string_stream(joutput, NULL, input);
	i_assert(ret > 0);
	i_stream_unref(&input);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp(
		"\"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ\"",
		str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* <JSON-text> */
	test_begin("json ostream write - <JSON-text>");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_write_text(joutput, NULL, "\"frop!\"");
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("\"frop!\"", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ ] */
	test_begin("json ostream write - array [ ]");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_descend_array(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_ascend_array(joutput);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("[]", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ string ] */
	test_begin("json ostream write - array [ string ]");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_descend_array(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_write_string(joutput, NULL, "frop");
	i_assert(ret > 0);
	ret = json_ostream_ascend_array(joutput);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("[\"frop\"]", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ string string stream ] */
	test_begin("json ostream write - array [ string stream ]");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_descend_array(joutput, NULL);
	i_assert(ret > 0);
	data = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ";
	input = i_stream_create_from_data(data, strlen(data));
	ret = json_ostream_write_string_stream(joutput, NULL, input);
	i_assert(ret > 0);
	i_stream_unref(&input);
	ret = json_ostream_ascend_array(joutput);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp(
		"[\"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ\"]",
		str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ <JSON-text> ] */
	test_begin("json ostream write - array [ <JSON-text> ]");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_descend_array(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_write_text(joutput, NULL, "[1,\"frop\",2]");
	i_assert(ret > 0);
	ret = json_ostream_ascend_array(joutput);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("[[1,\"frop\",2]]", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { } */
	test_begin("json ostream write - object { }");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_descend_object(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_ascend_object(joutput);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("{}", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": "friep" } */
	test_begin("json ostream write - object { \"frop\": \"friep\" }");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_descend_object(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_write_string(joutput, "frop", "friep");
	i_assert(ret > 0);
	ret = json_ostream_ascend_object(joutput);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("{\"frop\":\"friep\"}", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": 1234 } */
	test_begin("json ostream write - object { \"frop\": 1234 }");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_descend_object(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_write_object_member(joutput, "frop");
	i_assert(ret > 0);
	ret = json_ostream_write_number(joutput, NULL, 1234);
	i_assert(ret > 0);
	ret = json_ostream_ascend_object(joutput);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("{\"frop\":1234}", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": string stream } */
	test_begin("json ostream write - object { \"frop\": string stream }");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_descend_object(joutput, NULL);
	i_assert(ret > 0);
	data = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ";
	input = i_stream_create_from_data(data, strlen(data));
	ret = json_ostream_write_string_stream(joutput, "frop", input);
	i_assert(ret > 0);
	i_stream_unref(&input);
	ret = json_ostream_ascend_object(joutput);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp(
		"{\"frop\":"
		"\"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ\"}",
		str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "a": [{"d": 1}], "b": [{"e": 2}], "c": [{"f": 3}] } */
	test_begin("json ostream write - "
		   "object { \"a\": [{\"d\": 1}], \"b\": [{\"e\": 2}], "
			    "\"c\": [{\"f\": 3}] }");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_descend_object(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_descend_array(joutput, "a");
	i_assert(ret > 0);
	ret = json_ostream_descend_object(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_write_number(joutput, "d", 1);
	i_assert(ret > 0);
	ret = json_ostream_ascend_object(joutput);
	i_assert(ret > 0);
	ret = json_ostream_ascend_array(joutput);
	i_assert(ret > 0);
	ret = json_ostream_descend_array(joutput, "b");
	i_assert(ret > 0);
	ret = json_ostream_descend_object(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_write_number(joutput, "e", 2);
	i_assert(ret > 0);
	ret = json_ostream_ascend_object(joutput);
	i_assert(ret > 0);
	ret = json_ostream_ascend_array(joutput);
	i_assert(ret > 0);
	ret = json_ostream_descend_array(joutput, "c");
	i_assert(ret > 0);
	ret = json_ostream_descend_object(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_write_number(joutput, "f", 3);
	i_assert(ret > 0);
	ret = json_ostream_ascend_object(joutput);
	i_assert(ret > 0);
	ret = json_ostream_ascend_array(joutput);
	i_assert(ret > 0);
	ret = json_ostream_ascend_object(joutput);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp(
		"{\"a\":[{\"d\":1}],\"b\":[{\"e\":2}],\"c\":[{\"f\":3}]}",
		str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": <JSON-text> } */
	test_begin("json ostream write - object { \"frop\": <JSON-text> }");
	joutput = json_ostream_create(output, 0);
	ret = json_ostream_descend_object(joutput, NULL);
	i_assert(ret > 0);
	ret = json_ostream_write_text(joutput, "frop",
				      "[false,\"friep\",true]");
	i_assert(ret > 0);
	ret = json_ostream_ascend_object(joutput);
	i_assert(ret > 0);
	ret = json_ostream_flush(joutput);
	i_assert(ret > 0);
	json_ostream_unref(&joutput);
	test_assert_strcmp("{\"frop\":[false,\"friep\",true]}", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* trickle[1] */
	test_begin("json ostream write - object, trickle[1]");
	o_stream_set_max_buffer_size(output, 0);
	joutput = json_ostream_create(output, 0);
	state = 0;
	for (pos = 0; pos < 400 && state <= 17; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 1:
			ret = json_ostream_descend_array(joutput, "aaaaaa");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 2:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 3:
			ret = json_ostream_write_number(joutput, "dddddd", 1);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 4:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 5:
			ret = json_ostream_ascend_array(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 6:
			ret = json_ostream_descend_array(joutput, "bbbbbb");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 7:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 8:
			ret = json_ostream_write_number(joutput, "eeeeee", 2);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 9:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 10:
			ret = json_ostream_ascend_array(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 11:
			ret = json_ostream_descend_array(joutput, "cccccc");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 12:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 13:
			ret = json_ostream_write_object_member(
				joutput, "ffffff");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 14:
			ret = json_ostream_write_number(joutput, NULL, 3);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 15:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 16:
			ret = json_ostream_ascend_array(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 17:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		}
	}
	json_ostream_unref(&joutput);
	test_assert_strcmp("{\"aaaaaa\":[{\"dddddd\":1}],"
			   "\"bbbbbb\":[{\"eeeeee\":2}],"
			   "\"cccccc\":[{\"ffffff\":3}]}", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* trickle[2] */
	test_begin("json ostream write - object, trickle[2]");
	o_stream_set_max_buffer_size(output, 0);
	joutput = json_ostream_create(output, 0);
	state = 0;
	for (pos = 0; pos < 65535 && state <= 25; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 1:
			ret = json_ostream_descend_array(joutput, "aaaaaa");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 2:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 3:
			ret = json_ostream_write_number(joutput, "dddddd", 1);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 4:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 5:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 6:
			ret = json_ostream_write_number(joutput, "gggggg", 4);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 7:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 8:
			ret = json_ostream_ascend_array(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 9:
			ret = json_ostream_descend_array(joutput, "bbbbbb");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 10:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 11:
			ret = json_ostream_write_number(joutput, "eeeeee", 2);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 12:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 13:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 14:
			ret = json_ostream_write_number(joutput, "hhhhhh", 5);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 15:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 16:
			ret = json_ostream_ascend_array(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 17:
			ret = json_ostream_descend_array(joutput, "cccccc");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 18:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 19:
			ret = json_ostream_write_number(joutput, "ffffff", 3);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 20:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 21:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 22:
			ret = json_ostream_write_number(joutput, "iiiiii", 6);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 23:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 24:
			ret = json_ostream_ascend_array(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 25:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		}
	}
	json_ostream_unref(&joutput);
	test_assert_strcmp("{\"aaaaaa\":[{\"dddddd\":1},{\"gggggg\":4}],"
			   "\"bbbbbb\":[{\"eeeeee\":2},{\"hhhhhh\":5}],"
			   "\"cccccc\":[{\"ffffff\":3},{\"iiiiii\":6}]}",
			   str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* trickle[3] */
	test_begin("json ostream write - object, trickle[3]");
	o_stream_set_max_buffer_size(output, 0);
	joutput = json_ostream_create(output, 0);
	state = 0;
	for (pos = 0; pos < 400 && state <= 16; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 1:
			ret = json_ostream_descend_array(joutput, "aaaaaa");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 2:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 3:
			ret = json_ostream_write_text(joutput, "dddddd",
						      "1234567");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 4:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 5:
			ret = json_ostream_ascend_array(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 6:
			ret = json_ostream_descend_array(joutput, "bbbbbb");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 7:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 8:
			ret = json_ostream_write_text(joutput, "eeeeee",
						      "[1,2,3,4,5,6,7]");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 9:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 10:
			ret = json_ostream_ascend_array(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 11:
			ret = json_ostream_descend_array(joutput, "cccccc");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 12:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 13:
			ret = json_ostream_write_text(joutput, "ffffff",
						      "\"1234567\"");
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 14:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 15:
			ret = json_ostream_ascend_array(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 16:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		}
	}
	json_ostream_unref(&joutput);
	test_assert_strcmp("{\"aaaaaa\":[{\"dddddd\":1234567}],"
			   "\"bbbbbb\":[{\"eeeeee\":[1,2,3,4,5,6,7]}],"
			   "\"cccccc\":[{\"ffffff\":\"1234567\"}]}",
			   str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* trickle[4] */
	test_begin("json ostream write - object, trickle[4]");
	o_stream_set_max_buffer_size(output, 0);
	joutput = json_ostream_create(output, 0);
	state = 0;
	for (pos = 0; pos < 400 && state <= 16; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 1:
			ret = json_ostream_descend_array(joutput, "aaaaaa");
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 2:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			data = "AAAAA";
			input = i_stream_create_from_data(data, strlen(data));
			state++;
			continue;
		case 3:
			ret = json_ostream_write_string_stream(
				joutput, "dddddd", input);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			i_stream_unref(&input);
			state++;
			continue;
		case 4:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 5:
			ret = json_ostream_ascend_array(joutput);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 6:
			ret = json_ostream_descend_array(joutput, "bbbbbb");
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 7:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			data = "BBBBB";
			input = i_stream_create_from_data(data, strlen(data));
			state++;
			continue;
		case 8:
			ret = json_ostream_write_string_stream(
				joutput, "eeeeee", input);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			i_stream_unref(&input);
			state++;
			continue;
		case 9:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 10:
			ret = json_ostream_ascend_array(joutput);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 11:
			ret = json_ostream_descend_array(joutput, "cccccc");
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 12:
			ret = json_ostream_descend_object(joutput, NULL);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			data = "CCCCC";
			input = i_stream_create_from_data(data, strlen(data));
			state++;
			continue;
		case 13:
			ret = json_ostream_write_string_stream(
				joutput, "ffffff", input);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			i_stream_unref(&input);
			state++;
			continue;
		case 14:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 15:
			ret = json_ostream_ascend_array(joutput);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 16:
			ret = json_ostream_ascend_object(joutput);
			i_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		}
	}
	json_ostream_unref(&joutput);
	test_assert_strcmp("{\"aaaaaa\":[{\"dddddd\":\"AAAAA\"}],"
			   "\"bbbbbb\":[{\"eeeeee\":\"BBBBB\"}],"
			   "\"cccccc\":[{\"ffffff\":\"CCCCC\"}]}",
			   str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	o_stream_destroy(&output);
	str_free(&buffer);
}

static void test_json_ostream_nwrite(void)
{
	string_t *buffer;
	struct istream *input;
	struct ostream *output;
	struct json_ostream *joutput;
	const char *data;

	buffer = str_new(default_pool, 256);
	output = o_stream_create_buffer(buffer);
	o_stream_set_no_error_handling(output, TRUE);

	/* number */
	test_begin("json ostream nwrite - number");
	joutput = json_ostream_create(output, 0);
	json_ostream_nwrite_number(joutput, NULL, 23423);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("23423", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* false */
	test_begin("json ostream nwrite - false");
	joutput = json_ostream_create(output, 0);
	json_ostream_nwrite_false(joutput, NULL);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("false", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* false */
	test_begin("json ostream nwrite - null");
	joutput = json_ostream_create(output, 0);
	json_ostream_nwrite_null(joutput, NULL);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("null", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* true */
	test_begin("json ostream nwrite - true");
	joutput = json_ostream_create(output, 0);
	json_ostream_nwrite_true(joutput, NULL);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("true", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string */
	test_begin("json ostream nwrite - string");
	joutput = json_ostream_create(output, 0);
	json_ostream_nwrite_string(joutput, NULL, "frop!");
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("\"frop!\"", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* formatted string */
	test_begin("json ostream nwrite - formatted string");
	joutput = json_ostream_create(output, 0);
	json_ostream_nwritef_string(joutput, NULL, "%u", 12345);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("\"12345\"", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string stream */
	test_begin("json ostream nwrite - string stream");
	joutput = json_ostream_create(output, 0);
	data = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ";
	input = i_stream_create_from_data(data, strlen(data));
	json_ostream_nwrite_string_stream(joutput, NULL, input);
	i_stream_unref(&input);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp(
		"\"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ\"",
		str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* <JSON-text> */
	test_begin("json ostream nwrite - <JSON-text>");
	joutput = json_ostream_create(output, 0);
	json_ostream_nwrite_text(joutput, NULL, "\"frop!\"");
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("\"frop!\"", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ ] */
	test_begin("json ostream nwrite - array [ ]");
	joutput = json_ostream_create(output, 0);
	json_ostream_ndescend_array(joutput, NULL);
	json_ostream_nascend_array(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("[]", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ string ] */
	test_begin("json ostream nwrite - array [ string ]");
	joutput = json_ostream_create(output, 0);
	json_ostream_ndescend_array(joutput, NULL);
	json_ostream_nwrite_string(joutput, NULL, "frop");
	json_ostream_nascend_array(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("[\"frop\"]", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ string string stream ] */
	test_begin("json ostream nwrite - array [ string stream ]");
	joutput = json_ostream_create(output, 0);
	json_ostream_ndescend_array(joutput, NULL);
	data = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ";
	input = i_stream_create_from_data(data, strlen(data));
	json_ostream_nwrite_string_stream(joutput, NULL, input);
	i_stream_unref(&input);
	json_ostream_nascend_array(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp(
		"[\"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ\"]",
		str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ <JSON-text> ] */
	test_begin("json ostream nwrite - array [ <JSON-text> ]");
	joutput = json_ostream_create(output, 0);
	json_ostream_ndescend_array(joutput, NULL);
	json_ostream_nwrite_text(joutput, NULL, "[1,\"frop\",2]");
	json_ostream_nascend_array(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("[[1,\"frop\",2]]", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { } */
	test_begin("json ostream nwrite - object { }");
	joutput = json_ostream_create(output, 0);
	json_ostream_ndescend_object(joutput, NULL);
	json_ostream_nascend_object(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("{}", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": "friep" } */
	test_begin("json ostream nwrite - object { \"frop\": \"friep\" }");
	joutput = json_ostream_create(output, 0);
	json_ostream_ndescend_object(joutput, NULL);
	json_ostream_nwrite_string(joutput, "frop", "friep");
	json_ostream_nascend_object(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("{\"frop\":\"friep\"}", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* complex example */
	test_begin("json ostream nwrite - complex example");
	joutput = json_ostream_create_str(buffer, 0);
	json_ostream_ndescend_object(joutput, NULL);
	json_ostream_nwrite_string(joutput, "user", "testuser3");
	json_ostream_nwrite_string(joutput, "event", "messageNew");
	json_ostream_nwrite_string(joutput, "folder", "INBOX");
	json_ostream_nwrite_number(joutput, "imap-uidvalidity", 1588805816);
	json_ostream_nwrite_number(joutput, "imap-uid", 1);
	json_ostream_nwrite_string(
		joutput, "from",
		"Source =?utf8?q?p=C3=A4_=3Dutf8=3Fq=3Fencoding=3F=3D?= "
		"<from@example.com>");
	json_ostream_nwrite_string(
		joutput, "subject",
		"Stuff =?utf8?q?p=C3=A4_=3Dutf8=3Fq=3Fencoding=3F=3D?=");
	json_ostream_nwrite_string(joutput, "snippet",
				    "P\xc3\xa4iv\xc3\xa4\xc3\xa4.");
	json_ostream_nwrite_number(joutput,  "unseen", 1);
	json_ostream_nascend_object(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp(
		"{\"user\":\"testuser3\","
		 "\"event\":\"messageNew\","
		 "\"folder\":\"INBOX\","
		 "\"imap-uidvalidity\":1588805816,"
		 "\"imap-uid\":1,"
		 "\"from\":\"Source =?utf8?q?p=C3=A4_=3Dutf8=3Fq=3Fencoding=3F=3D?= <from@example.com>\","
		 "\"subject\":\"Stuff =?utf8?q?p=C3=A4_=3Dutf8=3Fq=3Fencoding=3F=3D?=\","
		 "\"snippet\":\"P\xc3\xa4iv\xc3\xa4\xc3\xa4.\","
		 "\"unseen\":1}", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": string stream } */
	test_begin("json ostream nwrite - object { \"frop\": string stream }");
	joutput = json_ostream_create(output, 0);
	json_ostream_ndescend_object(joutput, NULL);
	data = "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ";
	input = i_stream_create_from_data(data, strlen(data));
	json_ostream_nwrite_string_stream(joutput, "frop", input);
	i_stream_unref(&input);
	json_ostream_nascend_object(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp(
		"{\"frop\":"
		"\"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ\"}",
		str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* concatenated string */
	test_begin("json ostream nwrite - concatenated string");
	joutput = json_ostream_create(output, 0);
	json_ostream_nopen_string(joutput, NULL);
	json_ostream_nwrite_string(joutput, NULL, "friep!");
	json_ostream_nwrite_string(joutput, NULL, "frop!");
	json_ostream_nwrite_string(joutput, NULL, "frml!");
	json_ostream_nclose_string(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("\"friep!frop!frml!\"", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* array [ concatenated string ] */
	test_begin("json ostream nwrite - array [ concatenated string ]");
	joutput = json_ostream_create(output, 0);
	json_ostream_ndescend_array(joutput, NULL);
	json_ostream_nopen_string(joutput, NULL);
	json_ostream_nwrite_string(joutput, NULL, "friep!");
	json_ostream_nwrite_string(joutput, NULL, "frop!");
	json_ostream_nwrite_string(joutput, NULL, "frml!");
	json_ostream_nclose_string(joutput);
	json_ostream_nascend_array(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("[\"friep!frop!frml!\"]", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* object { concatenated string } */
	test_begin("json ostream nwrite - object { concatenated string }");
	joutput = json_ostream_create(output, 0);
	json_ostream_ndescend_object(joutput, NULL);
	json_ostream_nopen_string(joutput, "foo");
	json_ostream_nwrite_string(joutput, NULL, "friep!");
	json_ostream_nwrite_string(joutput, NULL, "frop!");
	json_ostream_nwrite_string(joutput, NULL, "frml!");
	json_ostream_nclose_string(joutput);
	json_ostream_nascend_object(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("{\"foo\":\"friep!frop!frml!\"}", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* array [ complex concatenated string ] */
	test_begin("json ostream nwrite - "
		   "array [ complex concatenated string ]");
	joutput = json_ostream_create(output, 0);
	json_ostream_ndescend_array(joutput, NULL);
	json_ostream_nopen_string(joutput, NULL);
	json_ostream_nwrite_string(joutput, NULL, "friep!");
	json_ostream_nwrite_string(joutput, NULL, "frop!");
	json_ostream_nwrite_string(joutput, NULL, "frml!");
	json_ostream_nclose_string(joutput);
	json_ostream_nwrite_string(joutput, NULL, "friep!");
	json_ostream_nwrite_string(joutput, NULL, "frop!");
	json_ostream_nwrite_string(joutput, NULL, "frml!");
	json_ostream_nopen_string(joutput, NULL);
	json_ostream_nwrite_string(joutput, NULL, "frml!");
	json_ostream_nwrite_string(joutput, NULL, "frop!");
	json_ostream_nwrite_string(joutput, NULL, "friep!");
	json_ostream_nclose_string(joutput);
	json_ostream_nascend_array(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("[\"friep!frop!frml!\","
			    "\"friep!\",\"frop!\",\"frml!\","
			    "\"frml!frop!friep!\"]", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* object [ complex concatenated string ] */
	test_begin("json ostream nwrite - "
		   "object [ complex concatenated string ]");
	joutput = json_ostream_create(output, 0);
	json_ostream_ndescend_object(joutput, NULL);
	json_ostream_nopen_string(joutput, "a");
	json_ostream_nwrite_string(joutput, NULL, "friep!");
	json_ostream_nwrite_string(joutput, NULL, "frop!");
	json_ostream_nwrite_string(joutput, NULL, "frml!");
	json_ostream_nclose_string(joutput);
	json_ostream_nwrite_string(joutput, "b", "friep!");
	json_ostream_nwrite_string(joutput, "c", "frop!");
	json_ostream_nwrite_string(joutput, "d", "frml!");
	json_ostream_nopen_string(joutput, "e");
	json_ostream_nwrite_string(joutput, NULL, "frml!");
	json_ostream_nwrite_string(joutput, NULL, "frop!");
	json_ostream_nwrite_string(joutput, NULL, "friep!");
	json_ostream_nclose_string(joutput);
	json_ostream_nascend_object(joutput);
	json_ostream_nfinish_destroy(&joutput);
	test_assert_strcmp("{\"a\":\"friep!frop!frml!\","
			    "\"b\":\"friep!\",\"c\":\"frop!\",\"d\":\"frml!\","
			    "\"e\":\"frml!frop!friep!\"}", str_c(buffer));
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	o_stream_destroy(&output);
	str_free(&buffer);
}

int main(int argc, char *argv[])
{
	int c;

	static void (*test_functions[])(void) = {
		test_json_ostream_write,
		test_json_ostream_nwrite,
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
