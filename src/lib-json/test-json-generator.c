/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "unichar.h"
#include "test-common.h"

#include "json-generator.h"

#include <unistd.h>

static bool debug = FALSE;

static void test_json_generate_buffer(void)
{
	string_t *buffer;
	struct ostream *output;
	struct istream *input;
	const char *data;
	struct json_generator *generator;
	unsigned int state, pos;
	ssize_t sret;
	int ret;

	buffer = str_new(default_pool, 256);
	output = o_stream_create_buffer(buffer);
	o_stream_set_no_error_handling(output, TRUE);

	/* number - integer */
	test_begin("json write number - integer");
	generator = json_generator_init(output, 0);
	ret = json_generate_number(generator, 23423);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("23423", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* number - raw */
	test_begin("json write number - raw");
	generator = json_generator_init(output, 0);
	ret = json_generate_number_raw(generator, "23423");
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("23423", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* false */
	test_begin("json write false");
	generator = json_generator_init(output, 0);
	ret = json_generate_false(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("false", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* false */
	test_begin("json write null");
	generator = json_generator_init(output, 0);
	ret = json_generate_null(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("null", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* true */
	test_begin("json write true");
	generator = json_generator_init(output, 0);
	ret = json_generate_true(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("true", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string */
	test_begin("json write string");
	generator = json_generator_init(output, 0);
	ret = json_generate_string(generator, "frop!");
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"frop!\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string - TAB */
	test_begin("json write string - TAB");
	generator = json_generator_init(output, 0);
	ret = json_generate_string(generator, "frop\tfriep");
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"frop\\tfriep\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string - LF */
	test_begin("json write string - LF");
	generator = json_generator_init(output, 0);
	ret = json_generate_string(generator, "frop\nfriep");
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"frop\\nfriep\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string - LF,TAB */
	test_begin("json write string - CR,LF,TAB");
	generator = json_generator_init(output, 0);
	ret = json_generate_string(generator, "frop\r\n\tfriep");
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"frop\\r\\n\\tfriep\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string - quotes */
	test_begin("json write string - quotes");
	generator = json_generator_init(output, 0);
	ret = json_generate_string(generator, "\"frop\"");
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"\\\"frop\\\"\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string - slashes */
	test_begin("json write string - slashes");
	generator = json_generator_init(output, 0);
	ret = json_generate_string(generator, "frop\\friep/frml");
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"frop\\\\friep/frml\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string - slashes */
	test_begin("json write string - BS,FF");
	generator = json_generator_init(output, 0);
	ret = json_generate_string(generator, "\x08\x0c");
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"\\b\\f\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string - bad UTF-8 */
	test_begin("json write string - bad UTF-8");
	generator = json_generator_init(output, 0);
	ret = json_generate_string(generator, "\xc3\x28");
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"\xEF\xBF\xBD(\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string - bad UTF-8 code point */
	test_begin("json write string - bad UTF-8 code point");
	generator = json_generator_init(output, 0);
	ret = json_generate_string(generator, "\xed\xa0\xbd");
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	// FIXME: this should ideally produce just one replacement char
	test_assert(strcmp("\"\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\"",
		    str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string - long */
	test_begin("json write string - long");
	generator = json_generator_init(output, 0);
	json_generate_string_open(generator);
	sret = (int)json_generate_string_more(generator,
		"frop", strlen("frop"), FALSE);
	test_assert(sret > 0);
	sret = (int)json_generate_string_more(generator,
		"frop", strlen("frop"), FALSE);
	test_assert(sret > 0);
	sret = (int)json_generate_string_more(generator,
		"frop", strlen("frop"), TRUE);
	test_assert(sret > 0);
	json_generate_string_close(generator);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"fropfropfrop\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* string - input stream */
	test_begin("json write string - input stream");
	generator = json_generator_init(output, 0);
	data = "ABC\tDEF\nGHI\tJKL\nMNO\x19PQR\nSTU\tVWX\nYZ";
	input = i_stream_create_from_data(data, strlen(data));
	ret = json_generate_string_stream(generator, input);
	test_assert(ret > 0);
	i_stream_unref(&input);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"ABC\\tDEF\\nGHI\\tJKL\\nMNO\\u0019PQR\\nSTU\\tVWX\\nYZ\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* <JSON-text> */
	test_begin("json write <JSON-text>");
	generator = json_generator_init(output, 0);
	ret = json_generate_text(generator, "[\"frop!\"]");
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[\"frop!\"]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* <JSON-text> - long */
	test_begin("json write <JSON-text> - long");
	generator = json_generator_init(output, 0);
	json_generate_text_open(generator);
	sret = (int)json_generate_text_more(generator,
		"\"frop", strlen("\"frop"));
	test_assert(sret > 0);
	sret = (int)json_generate_text_more(generator,
		"frop", strlen("frop"));
	test_assert(sret > 0);
	sret = (int)json_generate_text_more(generator,
		"frop\"", strlen("frop\""));
	test_assert(sret > 0);
	ret = json_generate_text_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"fropfropfrop\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* <JSON-text> - input stream */
	test_begin("json write <JSON-text> - input stream");
	generator = json_generator_init(output, 0);
	data = "[\"frop!\",\"friep!\",\"frml!\"]";
	input = i_stream_create_from_data(data, strlen(data));
	ret = json_generate_text_stream(generator, input);
	test_assert(ret > 0);
	i_stream_unref(&input);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp(data, str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ ] */
	test_begin("json write array - [ ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ number ] */
	test_begin("json write array - [ number ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	ret = json_generate_number(generator, 23423);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[23423]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ string ] */
	test_begin("json write array - [ string ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	ret = json_generate_string(generator, "frop");
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[\"frop\"]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ false ] */
	test_begin("json write array - [ false ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	ret = json_generate_false(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[false]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ null ] */
	test_begin("json write array - [ null ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	ret = json_generate_null(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[null]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ true ] */
	test_begin("json write array - [ true ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	ret = json_generate_true(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[true]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ [] ] */
	test_begin("json write array - [ [] ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[[]]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ {} ] */
	test_begin("json write array - [ {} ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	json_generate_object_open(generator);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[{}]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ <JSON-text> ] */
	test_begin("json write array - [ <JSON-text> ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	ret = json_generate_text(generator, "{\"a\":1,\"b\":2,\"c\":3}");
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[{\"a\":1,\"b\":2,\"c\":3}]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ string, <JSON-text> ] */
	test_begin("json write array - [ string, <JSON-text> ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	json_generate_string(generator, "frop");
	ret = json_generate_text(generator, "{\"a\":1,\"b\":2,\"c\":3}");
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[\"frop\",{\"a\":1,\"b\":2,\"c\":3}]",
		    str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ true, true ] */
	test_begin("json write array - [ true, true ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	ret = json_generate_true(generator);
	test_assert(ret > 0);
	ret = json_generate_true(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[true,true]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ true, true, true ] */
	test_begin("json write array - [ true, true, true ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	ret = json_generate_true(generator);
	test_assert(ret > 0);
	ret = json_generate_true(generator);
	test_assert(ret > 0);
	ret = json_generate_true(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[true,true,true]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ "frop", "friep", "frml" ] */
	test_begin("json write array - [ \"frop\", \"friep\", \"frml\" ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	ret = json_generate_string(generator, "frop");
	test_assert(ret > 0);
	ret = json_generate_string(generator, "friep");
	test_assert(ret > 0);
	ret = json_generate_string(generator, "frml");
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[\"frop\",\"friep\",\"frml\"]",
		    str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ 1, 2, 3 ] */
	test_begin("json write array - [ 1, 2, 3 ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	ret = json_generate_number(generator, 1);
	test_assert(ret > 0);
	ret = json_generate_number(generator, 2);
	test_assert(ret > 0);
	ret = json_generate_number(generator, 3);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[1,2,3]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ [], [], [] ] */
	test_begin("json write array - [ [], [], [] ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[[],[],[]]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ {}, {}, {} ] */
	test_begin("json write array - [ {}, {}, {} ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	json_generate_object_open(generator);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	json_generate_object_open(generator);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	json_generate_object_open(generator);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[{},{},{}]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ [ [], [], [] ], [ [], [], [] ], [ [], [], [] ] ] */
	test_begin("json write array - "
		"[ [ [], [], [] ], [ [], [], [] ], [ [], [], [] ] ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	json_generate_array_open(generator);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	json_generate_array_open(generator);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	json_generate_array_open(generator);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[[[],[],[]],[[],[],[]],[[],[],[]]]",
		    str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ <JSON-text>, <JSON-text>, <JSON-text> ] */
	test_begin("json write array - "
		   "[ <JSON-text>, <JSON-text>, <JSON-text> ]");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	ret = json_generate_text(generator, "true");
	test_assert(ret > 0);
	ret = json_generate_text(generator, "1234234");
	test_assert(ret > 0);
	ret = json_generate_text(generator, "\"frml\"");
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[true,1234234,\"frml\"]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* array - hidden root */
	test_begin("json write array - hidden_root");
	generator = json_generator_init(output, JSON_GENERATOR_FLAG_HIDE_ROOT);
	json_generate_array_open(generator);
	ret = json_generate_string(generator, "frop");
	test_assert(ret > 0);
	ret = json_generate_string(generator, "friep");
	test_assert(ret > 0);
	ret = json_generate_string(generator, "frml");
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"frop\",\"friep\",\"frml\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* array - string input stream nested */
	test_begin("json write array - string input stream nested");
	generator = json_generator_init(output, 0);
	data = "ABC\tDEF\nGHI\tJKL\nMNO\x19PQR\nSTU\tVWX\nYZ";
	input = i_stream_create_from_data(data, strlen(data));
	json_generate_array_open(generator);
	ret = json_generate_string_stream(generator, input);
	test_assert(ret > 0);
	i_stream_unref(&input);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp(
		"[\"ABC\\tDEF\\nGHI\\tJKL\\nMNO\\u0019PQR\\nSTU\\tVWX\\nYZ\"]",
		str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* array - string input stream nested, second */
	test_begin("json write array - string input stream nested, second");
	generator = json_generator_init(output, 0);
	data = "ABC\tDEF\nGHI\tJKL\nMNO\x19PQR\nSTU\tVWX\nYZ";
	input = i_stream_create_from_data(data, strlen(data));
	json_generate_array_open(generator);
	ret = json_generate_string(generator, "frop");
	test_assert(ret > 0);
	ret = json_generate_string_stream(generator, input);
	test_assert(ret > 0);
	i_stream_unref(&input);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp(
		"[\"frop\",\"ABC\\tDEF\\nGHI\\tJKL\\nMNO\\u0019PQR\\nSTU\\tVWX\\nYZ\"]",
		str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* array - <JSON-text> input stream nested */
	test_begin("json write array - <JSON-text> input stream nested");
	generator = json_generator_init(output, 0);
	data = "[\"frop!\",\"friep!\",\"frml!\"]";
	input = i_stream_create_from_data(data, strlen(data));
	json_generate_array_open(generator);
	ret = json_generate_text_stream(generator, input);
	test_assert(ret > 0);
	i_stream_unref(&input);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[[\"frop!\",\"friep!\",\"frml!\"]]",
			   str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* array - <JSON-text> input stream nested, second */
	test_begin("json write array - <JSON-text> input stream nested, second");
	generator = json_generator_init(output, 0);
	data = "[\"frop!\",\"friep!\",\"frml!\"]";
	input = i_stream_create_from_data(data, strlen(data));
	json_generate_array_open(generator);
	ret = json_generate_string(generator, "frop");
	test_assert(ret > 0);
	ret = json_generate_text_stream(generator, input);
	test_assert(ret > 0);
	i_stream_unref(&input);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[\"frop\",[\"frop!\",\"friep!\",\"frml!\"]]",
			   str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { } */
	test_begin("json write object - { }");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{}", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": 1 } */
	test_begin("json write object - { \"frop\": 1 }");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "frop");
	test_assert(ret > 0);
	ret = json_generate_number(generator, 1);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"frop\":1}", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": "friep" } */
	test_begin("json write object - { \"frop\": \"friep\" }");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "frop");
	test_assert(ret > 0);
	ret = json_generate_string(generator, "friep");
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"frop\":\"friep\"}", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": false } */
	test_begin("json write object - { \"frop\": false }");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "frop");
	test_assert(ret > 0);
	ret = json_generate_false(generator);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"frop\":false}", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": [] } */
	test_begin("json write object - { \"frop\": [] }");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "frop");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"frop\":[]}", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": {} } */
	test_begin("json write object - { \"frop\": {} }");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "frop");
	test_assert(ret > 0);
	json_generate_object_open(generator);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"frop\":{}}", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": <JSON-text> } */
	test_begin("json write object - { \"frop\": <JSON-text> }");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "frop");
	test_assert(ret > 0);
	ret = json_generate_text(generator, "[\"friep\",1,true]");
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"frop\":[\"friep\",1,true]}",
		    str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": {}, "friep": {} } */
	test_begin("json write object - { \"frop\": {}, \"friep\": {} }");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "frop");
	test_assert(ret > 0);
	json_generate_object_open(generator);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_member(generator, "friep");
	test_assert(ret > 0);
	json_generate_object_open(generator);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"frop\":{},\"friep\":{}}", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": [], "friep": [], "frml": [] } */
	test_begin("json write object - "
		   "{ \"frop\": [], \"friep\": [], \"frml\": [] }");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "frop");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_member(generator, "friep");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_member(generator, "frml");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"frop\":[],\"friep\":[],\"frml\":[]}",
		    str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "frop": [1], "friep": [true], "frml": ["a"] } */
	test_begin("json write object - "
		   "{ \"frop\": [1], \"friep\": [true], \"frml\": [\"a\"] }");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "frop");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_number(generator, 1);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_member(generator, "friep");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_true(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_member(generator, "frml");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_string(generator, "a");
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"frop\":[1],\"friep\":[true],\"frml\":[\"a\"]}",
		    str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "a": [{"d": 1}], "b": [{"e": 2}], "c": [{"f": 3}] } */
	test_begin("json write object - "
		   "{ \"a\": [{\"d\": 1}], \"b\": [{\"e\": 2}], "
		   "\"c\": [{\"f\": 3}] }");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "a");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "d");
	test_assert(ret > 0);
	ret = json_generate_number(generator, 1);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_member(generator, "b");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "e");
	test_assert(ret > 0);
	ret = json_generate_number(generator, 2);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_member(generator, "c");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "f");
	test_assert(ret > 0);
	ret = json_generate_number(generator, 3);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"a\":[{\"d\":1}],"
			     "\"b\":[{\"e\":2}],\"c\":[{\"f\":3}]}",
		    str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* object - hidden root */
	test_begin("json write object - hidden root");
	generator = json_generator_init(output, JSON_GENERATOR_FLAG_HIDE_ROOT);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "frop");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_number(generator, 1);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_member(generator, "friep");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_true(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_member(generator, "frml");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	ret = json_generate_string(generator, "a");
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"frop\":[1],\"friep\":[true],\"frml\":[\"a\"]",
			   str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* object - string input stream nested */
	test_begin("json write object - string input stream nested");
	generator = json_generator_init(output, 0);
	data = "ABC\tDEF\nGHI\tJKL\nMNO\x19PQR\nSTU\tVWX\nYZ";
	input = i_stream_create_from_data(data, strlen(data));
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "a");
	test_assert(ret > 0);
	ret = json_generate_string_stream(generator, input);
	test_assert(ret > 0);
	i_stream_unref(&input);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"a\":\"ABC\\tDEF\\nGHI\\tJKL\\nMNO\\u0019PQR\\nSTU\\tVWX\\nYZ\"}", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* object - <JSON-text> input stream nested */
	test_begin("json write object - <JSON-text> input stream nested");
	generator = json_generator_init(output, 0);
	data = "[\"frop!\",\"friep!\",\"frml!\"]";
	input = i_stream_create_from_data(data, strlen(data));
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "a");
	test_assert(ret > 0);
	ret = json_generate_text_stream(generator, input);
	test_assert(ret > 0);
	i_stream_unref(&input);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"a\":[\"frop!\",\"friep!\",\"frml!\"]}",
		str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* trickle [1] */
	test_begin("json write object - trickle[1]");
	o_stream_set_max_buffer_size(output, 0);
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	state = 0;
	for (pos = 0; pos < 65535 && state <= 15; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			ret = json_generate_object_member(generator, "aaaaaa");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 1:
			ret = json_generate_object_member(generator, "dddddd");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 2:
			ret = json_generate_number(generator, 1);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 3:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 4:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 5:
			ret = json_generate_object_member(generator, "bbbbbb");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 6:
			ret = json_generate_object_member(generator, "eeeeee");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 7:
			ret = json_generate_number(generator, 2);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 8:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 9:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 10:
			ret = json_generate_object_member(generator, "cccccc");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 11:
			ret = json_generate_object_member(generator, "ffffff");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 12:
			ret = json_generate_number(generator, 3);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 13:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 14:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 15:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		}
	}
	json_generator_deinit(&generator);
	test_assert(state == 16);
	test_assert(strcmp("{\"aaaaaa\":[{\"dddddd\":1}],"
			   "\"bbbbbb\":[{\"eeeeee\":2}],"
			   "\"cccccc\":[{\"ffffff\":3}]}",
			   str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* trickle [2] */
	test_begin("json write object - trickle[2]");
	o_stream_set_max_buffer_size(output, 0);
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	state = 0;
	for (pos = 0; pos < 65535 && state <= 24; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			ret = json_generate_object_member(generator, "aaaaaa");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 1:
			ret = json_generate_object_member(generator, "dddddd");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 2:
			ret = json_generate_number(generator, 1);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 3:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_object_open(generator);
			state++;
			continue;
		case 4:
			ret = json_generate_object_member(generator, "gggggg");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 5:
			ret = json_generate_number(generator, 4);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 6:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 7:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 8:
			ret = json_generate_object_member(generator, "bbbbbb");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 9:
			ret = json_generate_object_member(generator, "eeeeee");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 10:
			ret = json_generate_number(generator, 2);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 11:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_object_open(generator);
			state++;
			continue;
		case 12:
			ret = json_generate_object_member(generator, "hhhhhh");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 13:
			ret = json_generate_number(generator, 5);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 14:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 15:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 16:
			ret = json_generate_object_member(generator, "cccccc");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 17:
			ret = json_generate_object_member(generator, "ffffff");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 18:
			ret = json_generate_number(generator, 3);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 19:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_object_open(generator);
			state++;
			continue;
		case 20:
			ret = json_generate_object_member(generator, "iiiiii");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 21:
			ret = json_generate_number(generator, 6);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 22:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 23:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 24:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		}
	}
	json_generator_deinit(&generator);
	test_assert(state == 25);
	test_assert(strcmp("{\"aaaaaa\":[{\"dddddd\":1},{\"gggggg\":4}],"
			   "\"bbbbbb\":[{\"eeeeee\":2},{\"hhhhhh\":5}],"
			   "\"cccccc\":[{\"ffffff\":3},{\"iiiiii\":6}]}",
			   str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* trickle[3] */
	test_begin("json write object - trickle[3]");
	o_stream_set_max_buffer_size(output, 0);
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	state = 0;
	for (pos = 0; pos < 65535 && state <= 15; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			ret = json_generate_object_member(generator, "aaaaaa");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 1:
			ret = json_generate_object_member(generator, "dddddd");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 2:
			ret = json_generate_text(generator, "1234567");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 3:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 4:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 5:
			ret = json_generate_object_member(generator, "bbbbbb");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 6:
			ret = json_generate_object_member(generator, "eeeeee");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 7:
			ret = json_generate_text(generator, "[1,2,3,4,5,6,7]");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 8:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 9:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 10:
			ret = json_generate_object_member(generator, "cccccc");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 11:
			ret = json_generate_object_member(generator, "ffffff");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 12:
			ret = json_generate_text(generator, "\"1234567\"");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 13:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 14:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 15:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		}
	}
	json_generator_deinit(&generator);
	test_assert(state == 16);
	test_assert(strcmp("{\"aaaaaa\":[{\"dddddd\":1234567}],"
			   "\"bbbbbb\":[{\"eeeeee\":[1,2,3,4,5,6,7]}],"
			   "\"cccccc\":[{\"ffffff\":\"1234567\"}]}",
			   str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* trickle [4] */
	test_begin("json write object - trickle[4]");
	o_stream_set_max_buffer_size(output, 0);
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	state = 0;
	for (pos = 0; pos < 65535 && state <= 15; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			ret = json_generate_object_member(generator, "aaaaaa");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 1:
			ret = json_generate_object_member(generator, "dddddd");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 2:
			data = "AAAAA";
			input = i_stream_create_from_data(data, strlen(data));
			ret = json_generate_string_stream(generator, input);
			test_assert(ret > 0);
			i_stream_unref(&input);
			state++;
			continue;
		case 3:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 4:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 5:
			ret = json_generate_object_member(generator, "bbbbbb");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 6:
			ret = json_generate_object_member(generator, "eeeeee");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 7:
			data = "BBBBB";
			input = i_stream_create_from_data(data, strlen(data));
			ret = json_generate_string_stream(generator, input);
			test_assert(ret > 0);
			i_stream_unref(&input);
			state++;
			continue;
		case 8:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 9:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 10:
			ret = json_generate_object_member(generator, "cccccc");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 11:
			ret = json_generate_object_member(generator, "ffffff");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 12:
			data = "CCCCC";
			input = i_stream_create_from_data(data, strlen(data));
			ret = json_generate_string_stream(generator, input);
			test_assert(ret > 0);
			i_stream_unref(&input);
			state++;
			continue;
		case 13:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 14:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 15:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		}
	}
	json_generator_deinit(&generator);
	test_assert(state == 16);
	test_assert(strcmp("{\"aaaaaa\":[{\"dddddd\":\"AAAAA\"}],"
		"\"bbbbbb\":[{\"eeeeee\":\"BBBBB\"}],"
		"\"cccccc\":[{\"ffffff\":\"CCCCC\"}]}", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* trickle [5] */
	test_begin("json write object - trickle[5]");
	o_stream_set_max_buffer_size(output, 0);
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	state = 0;
	for (pos = 0; pos < 65535 && state <= 15; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			ret = json_generate_object_member(generator, "aaaaaa");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 1:
			ret = json_generate_object_member(generator, "dddddd");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 2:
			data = "[\"GGGGG\"]";
			input = i_stream_create_from_data(data, strlen(data));
			ret = json_generate_text_stream(generator, input);
			test_assert(ret > 0);
			i_stream_unref(&input);
			state++;
			continue;
		case 3:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 4:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 5:
			ret = json_generate_object_member(generator, "bbbbbb");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 6:
			ret = json_generate_object_member(generator, "eeeeee");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 7:
			data = "[\"HHHHH\"]";
			input = i_stream_create_from_data(data, strlen(data));
			ret = json_generate_text_stream(generator, input);
			test_assert(ret > 0);
			i_stream_unref(&input);
			state++;
			continue;
		case 8:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 9:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 10:
			ret = json_generate_object_member(generator, "cccccc");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 11:
			ret = json_generate_object_member(generator, "ffffff");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 12:
			data = "[\"IIIII\"]";
			input = i_stream_create_from_data(data, strlen(data));
			ret = json_generate_text_stream(generator, input);
			test_assert(ret > 0);
			i_stream_unref(&input);
			state++;
			continue;
		case 13:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 14:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 15:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		}
	}
	json_generator_deinit(&generator);
	test_assert(state == 16);
	test_assert(strcmp("{\"aaaaaa\":[{\"dddddd\":[\"GGGGG\"]}],"
			   "\"bbbbbb\":[{\"eeeeee\":[\"HHHHH\"]}],"
			   "\"cccccc\":[{\"ffffff\":[\"IIIII\"]}]}",
			   str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	o_stream_destroy(&output);
	str_free(&buffer);
}

static void test_json_generate_stream(void)
{
	string_t *buffer;
	struct ostream *output, *str_stream;
	struct json_generator *generator;
	unsigned int state, pos;
	const char *data;
	size_t data_len, dpos;
	ssize_t sret;
	int ret;

	buffer = str_new(default_pool, 256);
	output = o_stream_create_buffer(buffer);
	o_stream_set_no_error_handling(output, TRUE);

	test_begin("json write string stream");
	generator = json_generator_init(output, 0);
	str_stream = json_generate_string_open_stream(generator);
	sret = o_stream_send_str(str_stream, "FROPFROPFROPFROPFROP");
	test_assert(sret > 0);
	o_stream_unref(&str_stream);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"FROPFROPFROPFROPFROP\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	test_begin("json write string stream - empty");
	generator = json_generator_init(output, 0);
	str_stream = json_generate_string_open_stream(generator);
	o_stream_unref(&str_stream);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("\"\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	test_begin("json write string stream - nested in array");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	str_stream = json_generate_string_open_stream(generator);
	sret = o_stream_send_str(str_stream, "FROPFROPFROPFROPFROP");
	test_assert(sret > 0);
	o_stream_unref(&str_stream);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[\"FROPFROPFROPFROPFROP\"]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	test_begin("json write string stream - nested in object");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "a");
	test_assert(ret > 0);
	str_stream = json_generate_string_open_stream(generator);
	sret = o_stream_send_str(str_stream, "FROPFROPFROPFROPFROP");
	test_assert(sret > 0);
	o_stream_unref(&str_stream);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"a\":\"FROPFROPFROPFROPFROP\"}",
			   str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	test_begin("json write string stream - empty nested in array");
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	str_stream = json_generate_string_open_stream(generator);
	o_stream_unref(&str_stream);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[\"\"]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	test_begin("json write string stream - empty nested in object");
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "a");
	test_assert(ret > 0);
	str_stream = json_generate_string_open_stream(generator);
	o_stream_unref(&str_stream);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\"a\":\"\"}", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	test_begin("json write string stream - trickle [1]");
	o_stream_set_max_buffer_size(output, 0);
	generator = json_generator_init(output, 0);
	data = "FROPFROPFROPFROPFROP";
	data_len = strlen(data);
	str_stream = json_generate_string_open_stream(generator);
	state = 0;
	dpos = 0;
	for (pos = 0; pos < 65535 && state < 3; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			sret = o_stream_send(str_stream, data + dpos,
					     data_len - dpos);
			if (sret > 0) {
				dpos += sret;
				i_assert(dpos <= data_len);
			}
			if (dpos < data_len)
				continue;
			state++;
			/* fall through */
		case 1:
			ret = o_stream_flush(str_stream);
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			o_stream_unref(&str_stream);
			state++;
			/* fall through */
		case 2:
			ret = json_generator_flush(generator);
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		}
	}
	json_generator_deinit(&generator);
	test_assert(state == 3);
	test_assert(strcmp("\"FROPFROPFROPFROPFROP\"", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	test_begin("json write string stream - trickle [2]");
	o_stream_set_max_buffer_size(output, 0);
	generator = json_generator_init(output, 0);
	data = "FROPFROPFROPFROPFROP";
	data_len = strlen(data);
	json_generate_array_open(generator);
	str_stream = json_generate_string_open_stream(generator);
	state = 0;
	dpos = 0;
	for (pos = 0; pos < 65535 && state < 4; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			sret = o_stream_send(str_stream, data + dpos,
					     data_len - dpos);
			if (sret > 0) {
				dpos += sret;
				i_assert(dpos <= data_len);
			}
			if (dpos < data_len)
				continue;
			state++;
			/* fall through */
		case 1:
			ret = o_stream_flush(str_stream);
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			o_stream_unref(&str_stream);
			state++;
			/* fall through */
		case 2:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 3:
			ret = json_generator_flush(generator);
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		}
	}
	json_generator_deinit(&generator);
	test_assert(state == 4);
	test_assert(strcmp("[\"FROPFROPFROPFROPFROP\"]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	test_begin("json write string stream - trickle [3]");
	o_stream_set_max_buffer_size(output, 0);
	generator = json_generator_init(output, 0);
	data = "FROPFROPFROPFROPFROP";
	data_len = strlen(data);
	json_generate_object_open(generator);
	state = 0;
	dpos = 0;
	for (pos = 0; pos < 65535 && state < 5; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			ret = json_generate_object_member(generator, "a");
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			str_stream = json_generate_string_open_stream(generator);
			state++;
			continue;
		case 1:
			sret = o_stream_send(str_stream, data + dpos,
					     data_len - dpos);
			if (sret > 0) {
				dpos += sret;
				i_assert(dpos <= data_len);
			}
			if (dpos < data_len)
				continue;
			state++;
			/* fall through */
		case 2:
			ret = o_stream_flush(str_stream);
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			o_stream_unref(&str_stream);
			state++;
			/* fall through */
		case 3:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 4:
			ret = json_generator_flush(generator);
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		}
	}
	json_generator_deinit(&generator);
	test_assert(state == 5);
	test_assert(strcmp("{\"a\":\"FROPFROPFROPFROPFROP\"}",
			   str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	test_begin("json write string stream - trickle [4]");
	o_stream_set_max_buffer_size(output, 0);
	generator = json_generator_init(output, 0);
	json_generate_array_open(generator);
	str_stream = json_generate_string_open_stream(generator);
	state = 0;
	for (pos = 0; pos < 65535 && state < 3; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			o_stream_unref(&str_stream);
			state++;
			/* fall through */
		case 1:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 2:
			ret = json_generator_flush(generator);
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		}
	}
	json_generator_deinit(&generator);
	test_assert(state == 3);
	test_assert(strcmp("[\"\"]", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	test_begin("json write string stream - trickle [5]");
	o_stream_set_max_buffer_size(output, 0);
	generator = json_generator_init(output, 0);
	json_generate_object_open(generator);
	state = 0;
	for (pos = 0; pos < 65535 && state < 3; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			ret = json_generate_object_member(generator, "a");
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			str_stream =
				json_generate_string_open_stream(generator);
			o_stream_unref(&str_stream);
			state++;
			/* fall through */
		case 1:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		case 2:
			ret = json_generator_flush(generator);
			test_assert(ret >= 0);
			if (ret == 0)
				break;
			state++;
			continue;
		}
	}
	json_generator_deinit(&generator);
	test_assert(state == 3);
	test_assert(strcmp("{\"a\":\"\"}", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	o_stream_destroy(&output);
	str_free(&buffer);
}

static void test_json_generate_formatted(void)
{
	string_t *buffer;
	struct ostream *output;
	struct json_format format;
	struct json_generator *generator;
	unsigned int state, pos;
	int ret;

	i_zero(&format);
	format.indent_chars = 2;
	format.indent_tab = FALSE;
	format.whitespace = TRUE;
	format.new_line = TRUE;

	buffer = str_new(default_pool, 256);
	output = o_stream_create_buffer(buffer);
	o_stream_set_no_error_handling(output, TRUE);

	/* value */
	test_begin("json format value");
	generator = json_generator_init(output, 0);
	json_generator_set_format(generator, &format);
	ret = json_generate_number(generator, 23423);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("23423\n", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ value ] */
	test_begin("json format array - [ string ]");
	generator = json_generator_init(output, 0);
	json_generator_set_format(generator, &format);
	json_generate_array_open(generator);
	ret = json_generate_string(generator, "frop");
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[\n"
			   "  \"frop\"\n"
			   "]\n", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ true, true, true ] */
	test_begin("json format array - [ true, true, true ]");
	generator = json_generator_init(output, 0);
	json_generator_set_format(generator, &format);
	json_generate_array_open(generator);
	ret = json_generate_true(generator);
	test_assert(ret > 0);
	ret = json_generate_true(generator);
	test_assert(ret > 0);
	ret = json_generate_true(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[\n"
			   "  true,\n"
			   "  true,\n"
			   "  true\n"
			   "]\n",
			   str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* [ "frop", "friep", "frml" ] */
	test_begin("json format array - [ \"frop\", \"friep\", \"frml\" ]");
	generator = json_generator_init(output, 0);
	json_generator_set_format(generator, &format);
	json_generate_array_open(generator);
	ret = json_generate_string(generator, "frop");
	test_assert(ret > 0);
	ret = json_generate_string(generator, "friep");
	test_assert(ret > 0);
	ret = json_generate_string(generator, "frml");
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("[\n"
			   "  \"frop\",\n"
			   "  \"friep\",\n"
			   "  \"frml\"\n"
			   "]\n",
			   str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* { "a": [{"d": 1}], "b": [{"e": 2}], "c": [{"f": 3}] } */
	test_begin("json format object - "
		   "{ \"a\": [{\"d\": 1}], \"b\": [{\"e\": 2}], "
		     "\"c\": [{\"f\": 3}] }");
	generator = json_generator_init(output, 0);
	json_generator_set_format(generator, &format);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "a");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "d");
	test_assert(ret > 0);
	ret = json_generate_number(generator, 1);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_member(generator, "b");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "e");
	test_assert(ret > 0);
	ret = json_generate_number(generator, 2);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_member(generator, "c");
	test_assert(ret > 0);
	json_generate_array_open(generator);
	json_generate_object_open(generator);
	ret = json_generate_object_member(generator, "f");
	test_assert(ret > 0);
	ret = json_generate_number(generator, 3);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generate_array_close(generator);
	test_assert(ret > 0);
	ret = json_generate_object_close(generator);
	test_assert(ret > 0);
	ret = json_generator_flush(generator);
	test_assert(ret > 0);
	json_generator_deinit(&generator);
	test_assert(strcmp("{\n"
			   "  \"a\": [\n"
			   "    {\n"
			   "      \"d\": 1\n"
			   "    }\n"
			   "  ],\n"
			   "  \"b\": [\n"
			   "    {\n"
			   "      \"e\": 2\n"
			   "    }\n"
			   "  ],\n"
			   "  \"c\": [\n"
			   "    {\n"
			   "      \"f\": 3\n"
			   "    }\n"
			   "  ]\n"
			   "}\n", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	/* trickle */
	test_begin("json format object - trickle");
	o_stream_set_max_buffer_size(output, 0);
	generator = json_generator_init(output, 0);
	json_generator_set_format(generator, &format);
	json_generate_object_open(generator);
	state = 0;
	for (pos = 0; pos < 65535 && state <= 25; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		switch (state) {
		case 0:
			ret = json_generate_object_member(generator, "aaaaaa");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 1:
			ret = json_generate_object_member(generator, "dddddd");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 2:
			ret = json_generate_number(generator, 1);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 3:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_object_open(generator);
			state++;
			continue;
		case 4:
			ret = json_generate_object_member(generator, "gggggg");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 5:
			ret = json_generate_number(generator, 4);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 6:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 7:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 8:
			ret = json_generate_object_member(generator, "bbbbbb");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 9:
			ret = json_generate_object_member(generator, "eeeeee");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 10:
			ret = json_generate_number(generator, 2);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 11:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_object_open(generator);
			state++;
			continue;
		case 12:
			ret = json_generate_object_member(generator, "hhhhhh");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 13:
			ret = json_generate_number(generator, 5);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 14:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 15:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 16:
			ret = json_generate_object_member(generator, "cccccc");
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_array_open(generator);
			json_generate_object_open(generator);
			state++;
			continue;
		case 17:
			ret = json_generate_object_member(generator, "ffffff");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 18:
			ret = json_generate_number(generator, 3);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 19:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			json_generate_object_open(generator);
			state++;
			continue;
		case 20:
			ret = json_generate_object_member(generator, "iiiiii");
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 21:
			ret = json_generate_number(generator, 6);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 22:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 23:
			ret = json_generate_array_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 24:
			ret = json_generate_object_close(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		case 25:
			ret = json_generator_flush(generator);
			test_assert(ret >= 0);
			if (ret == 0) break;
			state++;
			continue;
		}
	}
	json_generator_deinit(&generator);
	test_assert(state == 26);
	test_assert(strcmp("{\n"
			   "  \"aaaaaa\": [\n"
			   "    {\n"
			   "      \"dddddd\": 1\n"
			   "    },\n"
			   "    {\n"
			   "      \"gggggg\": 4\n"
			   "    }\n"
			   "  ],\n"
			   "  \"bbbbbb\": [\n"
			   "    {\n"
			   "      \"eeeeee\": 2\n"
			   "    },\n"
			   "    {\n"
			   "      \"hhhhhh\": 5\n"
			   "    }\n"
			   "  ],\n"
			   "  \"cccccc\": [\n"
			   "    {\n"
			   "      \"ffffff\": 3\n"
			   "    },\n"
			   "    {\n"
			   "      \"iiiiii\": 6\n"
			   "    }\n"
			   "  ]\n"
			   "}\n", str_c(buffer)) == 0);
	test_end();
	str_truncate(buffer, 0);
	output->offset = 0;

	o_stream_destroy(&output);
	str_free(&buffer);
}

static void test_json_append_escaped(void)
{
	string_t *str = t_str_new(32);

	test_begin("json_append_escaped()");
	json_append_escaped(str, "\b\f\r\n\t\"\\\001\002-\xC3\xA4\xf0\x90"
				 "\x90\xb7\xe2\x80\xa8\xe2\x80\xa9\xff");
	test_assert(strcmp(str_c(str),
			   "\\b\\f\\r\\n\\t\\\"\\\\\\u0001\\u0002-"
			   "\xC3\xA4\xf0\x90\x90\xb7\\u2028\\u2029"
			   ""UNICODE_REPLACEMENT_CHAR_UTF8) == 0);
	test_end();
}

static void test_json_append_escaped_data(void)
{
	static const unsigned char test_input[] =
		"\b\f\r\n\t\"\\\000\001\002-\xC3\xA4\xf0\x90"
		"\x90\xb7\xe2\x80\xa8\xe2\x80\xa9\xff";
	string_t *str = t_str_new(32);

	test_begin("json_append_escaped_data()");
	json_append_escaped_data(str, test_input, sizeof(test_input)-1);
	test_assert(strcmp(str_c(str),
			   "\\b\\f\\r\\n\\t\\\"\\\\\\u0000\\u0001\\u0002-"
			   "\xC3\xA4\xf0\x90\x90\xb7\\u2028\\u2029"
			   UNICODE_REPLACEMENT_CHAR_UTF8) == 0);
	test_end();
}

int main(int argc, char *argv[])
{
	int c;

	static void (*test_functions[])(void) = {
		test_json_generate_buffer,
		test_json_generate_stream,
		test_json_generate_formatted,
		test_json_append_escaped,
		test_json_append_escaped_data,
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
