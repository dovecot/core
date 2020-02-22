/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"

#include "json-istream.h"
#include "json-ostream.h"
#include "json-tree-io.h"

#include <unistd.h>

static bool debug = FALSE;

struct json_io_test {
	const char *input;
	const char *output;
	struct json_limits limits;
	enum json_parser_flags flags;
};

static const struct json_io_test
tests[] = {
	{
		.input = "{\"kty\":\"EC\","
			  "\"crv\":\"P-256\","
			  "\"x\":\"Kp0Y4-Wpt-D9t_2XenFIj0LmvaZByLG69yOisek4aMI\","
			  "\"y\":\"wjEPB5BhH5SRPw1cCN5grWrLCphrW19fCFR8p7c9O5o\","
			  "\"use\":\"sig\","
			  "\"kid\":\"123\","
			  "\"d\":\"Po2z9rs86J2Qb_xWprr4idsWNPlgKf3G8-mftnE2ync\""
			 "}",
	},
	{
		.input =
			"{\r\n"
			"    \"$schema\": \"http://json-schema.org/draft-06/schema#\",\r\n"
			"    \"$id\": \"http://json-schema.org/draft-06/schema#\",\r\n"
			"    \"title\": \"Core schema meta-schema\",\r\n"
			"    \"definitions\": {\r\n"
			"        \"schemaArray\": {\r\n"
			"            \"type\": \"array\",\r\n"
			"            \"minItems\": 1,\r\n"
			"            \"items\": { \"$ref\": \"#\" }\r\n"
			"        },\r\n"
			"        \"nonNegativeInteger\": {\r\n"
			"            \"type\": \"integer\",\r\n"
			"            \"minimum\": 0\r\n"
			"        },\r\n"
			"        \"nonNegativeIntegerDefault0\": {\r\n"
			"            \"allOf\": [\r\n"
			"                { \"$ref\": \"#/definitions/nonNegativeInteger\" },\r\n"
			"                { \"default\": 0 }\r\n"
			"            ]\r\n"
			"        },\r\n"
			"        \"simpleTypes\": {\r\n"
			"            \"enum\": [\r\n"
			"                \"array\",\r\n"
			"                \"boolean\",\r\n"
			"                \"integer\",\r\n"
			"                \"null\",\r\n"
			"                \"number\",\r\n"
			"                \"object\",\r\n"
			"                \"string\"\r\n"
			"            ]\r\n"
			"        },\r\n"
			"        \"stringArray\": {\r\n"
			"            \"type\": \"array\",\r\n"
			"            \"items\": { \"type\": \"string\" },\r\n"
			"            \"uniqueItems\": true,\r\n"
			"            \"default\": []\r\n"
			"        }\r\n"
			"    },\r\n"
			"    \"type\": [\"object\", \"boolean\"],\r\n"
			"    \"properties\": {\r\n"
			"        \"$id\": {\r\n"
			"            \"type\": \"string\",\r\n"
			"            \"format\": \"uri-reference\"\r\n"
			"        },\r\n"
			"        \"$schema\": {\r\n"
			"            \"type\": \"string\",\r\n"
			"            \"format\": \"uri\"\r\n"
			"        },\r\n"
			"        \"$ref\": {\r\n"
			"            \"type\": \"string\",\r\n"
			"            \"format\": \"uri-reference\"\r\n"
			"        },\r\n"
			"        \"title\": {\r\n"
			"            \"type\": \"string\"\r\n"
			"        },\r\n"
			"        \"description\": {\r\n"
			"            \"type\": \"string\"\r\n"
			"        },\r\n"
			"        \"default\": {},\r\n"
			"        \"multipleOf\": {\r\n"
			"            \"type\": \"number\",\r\n"
			"            \"exclusiveMinimum\": 0\r\n"
			"        },\r\n"
			"        \"maximum\": {\r\n"
			"            \"type\": \"number\"\r\n"
			"        },\r\n"
			"        \"exclusiveMaximum\": {\r\n"
			"            \"type\": \"number\"\r\n"
			"        },\r\n"
			"        \"minimum\": {\r\n"
			"            \"type\": \"number\"\r\n"
			"        },\r\n"
			"        \"exclusiveMinimum\": {\r\n"
			"            \"type\": \"number\"\r\n"
			"        },\r\n"
			"        \"maxLength\": { \"$ref\": \"#/definitions/nonNegativeInteger\" },\r\n"
			"        \"minLength\": { \"$ref\": \"#/definitions/nonNegativeIntegerDefault0\" },\r\n"
			"        \"pattern\": {\r\n"
			"            \"type\": \"string\",\r\n"
			"            \"format\": \"regex\"\r\n"
			"        },\r\n"
			"        \"additionalItems\": { \"$ref\": \"#\" },\r\n"
			"        \"items\": {\r\n"
			"            \"anyOf\": [\r\n"
			"                { \"$ref\": \"#\" },\r\n"
			"                { \"$ref\": \"#/definitions/schemaArray\" }\r\n"
			"            ],\r\n"
			"            \"default\": {}\r\n"
			"        },\r\n"
			"        \"maxItems\": { \"$ref\": \"#/definitions/nonNegativeInteger\" },\r\n"
			"        \"minItems\": { \"$ref\": \"#/definitions/nonNegativeIntegerDefault0\" },\r\n"
			"        \"uniqueItems\": {\r\n"
			"            \"type\": \"boolean\",\r\n"
			"            \"default\": false\r\n"
			"        },\r\n"
			"        \"contains\": { \"$ref\": \"#\" },\r\n"
			"        \"maxProperties\": { \"$ref\": \"#/definitions/nonNegativeInteger\" },\r\n"
			"        \"minProperties\": { \"$ref\": \"#/definitions/nonNegativeIntegerDefault0\" },\r\n"
			"        \"required\": { \"$ref\": \"#/definitions/stringArray\" },\r\n"
			"        \"additionalProperties\": { \"$ref\": \"#\" },\r\n"
			"        \"definitions\": {\r\n"
			"            \"type\": \"object\",\r\n"
			"            \"additionalProperties\": { \"$ref\": \"#\" },\r\n"
			"            \"default\": {}\r\n"
			"        },\r\n"
			"        \"properties\": {\r\n"
			"            \"type\": \"object\",\r\n"
			"            \"additionalProperties\": { \"$ref\": \"#\" },\r\n"
			"            \"default\": {}\r\n"
			"        },\r\n"
			"        \"patternProperties\": {\r\n"
			"            \"type\": \"object\",\r\n"
			"            \"additionalProperties\": { \"$ref\": \"#\" },\r\n"
			"            \"default\": {}\r\n"
			"        },\r\n"
			"        \"dependencies\": {\r\n"
			"            \"type\": \"object\",\r\n"
			"            \"additionalProperties\": {\r\n"
			"                \"anyOf\": [\r\n"
			"                    { \"$ref\": \"#\" },\r\n"
			"                    { \"$ref\": \"#/definitions/stringArray\" }\r\n"
			"                ]\r\n"
			"            }\r\n"
			"        },\r\n"
			"        \"propertyNames\": { \"$ref\": \"#\" },\r\n"
			"        \"const\": {},\r\n"
			"        \"enum\": {\r\n"
			"            \"type\": \"array\",\r\n"
			"            \"minItems\": 1,\r\n"
			"            \"uniqueItems\": true\r\n"
			"        },\r\n"
			"        \"type\": {\r\n"
			"            \"anyOf\": [\r\n"
			"                { \"$ref\": \"#/definitions/simpleTypes\" },\r\n"
			"                {\r\n"
			"                    \"type\": \"array\",\r\n"
			"                    \"items\": { \"$ref\": \"#/definitions/simpleTypes\" },\r\n"
			"                    \"minItems\": 1,\r\n"
			"                    \"uniqueItems\": true\r\n"
			"                }\r\n"
			"            ]\r\n"
			"        },\r\n"
			"        \"format\": { \"type\": \"string\" },\r\n"
			"        \"allOf\": { \"$ref\": \"#/definitions/schemaArray\" },\r\n"
			"        \"anyOf\": { \"$ref\": \"#/definitions/schemaArray\" },\r\n"
			"        \"oneOf\": { \"$ref\": \"#/definitions/schemaArray\" },\r\n"
			"        \"not\": { \"$ref\": \"#\" }\r\n"
			"    },\r\n"
			"    \"default\": {}\r\n"
			"}\r\n",
		.output =
			"{\"$schema\":\"http://json-schema.org/draft-06/schema#\","
			"\"$id\":\"http://json-schema.org/draft-06/schema#\","
			"\"title\":\"Core schema meta-schema\",\"definitions\":{"
			"\"schemaArray\":{\"type\":\"array\",\"minItems\":1,"
			"\"items\":{\"$ref\":\"#\"}},\"nonNegativeInteger\":{"
			"\"type\":\"integer\",\"minimum\":0},"
			"\"nonNegativeIntegerDefault0\":{\"allOf\":["
			"{\"$ref\":\"#/definitions/nonNegativeInteger\"},"
			"{\"default\":0}]},\"simpleTypes\":{\"enum\":["
			"\"array\",\"boolean\",\"integer\",\"null\","
			"\"number\",\"object\",\"string\"]},\"stringArray\":{"
			"\"type\":\"array\",\"items\":{\"type\":\"string\"},"
			"\"uniqueItems\":true,\"default\":[]}},"
			"\"type\":[\"object\",\"boolean\"],"
			"\"properties\":{\"$id\":{\"type\":\"string\","
			"\"format\":\"uri-reference\"},\"$schema\":{"
			"\"type\":\"string\",\"format\":\"uri\"},"
			"\"$ref\":{\"type\":\"string\",\"format\":\"uri-reference\""
			"},\"title\":{\"type\":\"string\"},\"description\":{"
			"\"type\":\"string\"},\"default\":{},\"multipleOf\":{"
			"\"type\":\"number\",\"exclusiveMinimum\":0},"
			"\"maximum\":{\"type\":\"number\"},\"exclusiveMaximum\":{"
			"\"type\":\"number\"},\"minimum\":{\"type\":\"number\""
			"},\"exclusiveMinimum\":{\"type\":\"number\"},"
			"\"maxLength\":{\"$ref\":\"#/definitions/nonNegativeInteger\"},"
			"\"minLength\":{\"$ref\":\"#/definitions/nonNegativeIntegerDefault0\"},"
			"\"pattern\":{\"type\":\"string\",\"format\":\"regex\""
			"},\"additionalItems\":{\"$ref\":\"#\"},\"items\":{"
			"\"anyOf\":[{\"$ref\":\"#\"},{\"$ref\":\"#/definitions/schemaArray\"}"
			"],\"default\":{}},"
			"\"maxItems\":{\"$ref\":\"#/definitions/nonNegativeInteger\"},"
			"\"minItems\":{\"$ref\":\"#/definitions/nonNegativeIntegerDefault0\"},"
			"\"uniqueItems\":{\"type\":\"boolean\",\"default\":false},"
			"\"contains\":{\"$ref\":\"#\"},"
			"\"maxProperties\":{\"$ref\":\"#/definitions/nonNegativeInteger\"},"
			"\"minProperties\":{\"$ref\":\"#/definitions/nonNegativeIntegerDefault0\"},"
			"\"required\":{\"$ref\":\"#/definitions/stringArray\"},"
			"\"additionalProperties\":{\"$ref\":\"#\"},\"definitions\":{"
			"\"type\":\"object\",\"additionalProperties\":{\"$ref\":\"#\"},"
			"\"default\":{}},\"properties\":{\"type\":\"object\","
			"\"additionalProperties\":{\"$ref\":\"#\"},\"default\":{}"
			"},\"patternProperties\":{\"type\":\"object\","
			"\"additionalProperties\":{\"$ref\":\"#\"},"
			"\"default\":{}},\"dependencies\":{\"type\":\"object\","
			"\"additionalProperties\":{\"anyOf\":[{\"$ref\":\"#\"},"
			"{\"$ref\":\"#/definitions/stringArray\"}"
			"]}},\"propertyNames\":{\"$ref\":\"#\"},\"const\":{},"
			"\"enum\":{\"type\":\"array\",\"minItems\":1,\"uniqueItems\":true"
			"},\"type\":{\"anyOf\":[{\"$ref\":\"#/definitions/simpleTypes\"},"
			"{\"type\":\"array\",\"items\":{\"$ref\":\"#/definitions/simpleTypes\"},"
			"\"minItems\":1,\"uniqueItems\":true}]},\"format\":{\"type\":\"string\"},"
			"\"allOf\":{\"$ref\":\"#/definitions/schemaArray\"},"
			"\"anyOf\":{\"$ref\":\"#/definitions/schemaArray\"},"
			"\"oneOf\":{\"$ref\":\"#/definitions/schemaArray\"},"
			"\"not\":{\"$ref\":\"#\"}},\"default\":{}}"
	}
};

static const unsigned tests_count = N_ELEMENTS(tests);

static void test_json_tree_io(void)
{
	string_t *outbuf;
	unsigned int i;

	outbuf = str_new(default_pool, 1024);

	for (i = 0; i < tests_count; i++) T_BEGIN {
		const struct json_io_test *test;
		const char *text, *text_out;
		unsigned int text_len;
		struct json_tree *jtree = NULL;
		const char *error = NULL;
		int ret = 0;

		test = &tests[i];
		text = test->input;
		text_out = test->output;
		if (text_out == NULL)
			text_out = test->input;
		text_len = strlen(text);

		test_begin(t_strdup_printf("json tree io [%d]", i));

		buffer_set_used_size(outbuf, 0);

		ret = json_tree_read_data(text, text_len, 0, &jtree, &error);
		test_out_reason_quiet("input ok", ret >= 0, error);

		if (jtree != NULL)
			json_tree_write_buffer(jtree, outbuf, 0, NULL);

		test_out_quiet("io match",
			       strcmp(text_out, str_c(outbuf)) == 0);

		if (debug) {
			i_debug("OUT: >%s<", text_out);
			i_debug("OUT: >%s<", str_c(outbuf));
		}

		json_tree_unref(&jtree);

		test_end();

	} T_END;

	buffer_free(&outbuf);
}

static void test_json_tree_stream_io(void)
{
	string_t *outbuf;
	unsigned int i;

	outbuf = str_new(default_pool, 1024);

	for (i = 0; i < tests_count; i++) T_BEGIN {
		const struct json_io_test *test;
		const char *text, *text_out;
		unsigned int pos, text_len;
		struct istream *input;
		struct ostream *output;
		struct json_istream *jinput;
		struct json_ostream *joutput;
		struct json_tree *jtree;
		const char *error = NULL;
		int ret = 0;

		test = &tests[i];
		text = test->input;
		text_out = test->output;
		if (text_out == NULL)
			text_out = test->input;
		text_len = strlen(text);

		test_begin(t_strdup_printf("json tree stream io [%d]", i));

		buffer_set_used_size(outbuf, 0);

		input = test_istream_create_data(text, text_len);
		output = o_stream_create_buffer(outbuf);
		o_stream_set_no_error_handling(output, TRUE);

		jinput = json_istream_create(input, 0, NULL, 0);
		joutput = json_ostream_create(output, 0);

		o_stream_set_max_buffer_size(output, 0);
		ret = 0;
		for (pos = 0; pos <= text_len && ret == 0; pos++) {
			test_istream_set_size(input, pos);
			ret = json_istream_read_tree(jinput, &jtree);
		}
		test_assert(ret > 0);

		test_istream_set_size(input, text_len);
		ret = json_istream_finish(&jinput, &error);
		test_out_reason_quiet("input stream ok (trickle)",
				      ret > 0, error);

		ret = 0;
		for (pos = 0;	pos <= 65535 && ret == 0; pos++) {
			o_stream_set_max_buffer_size(output, pos);
			if (jtree != NULL) {
				ret = json_ostream_write_tree(joutput, NULL, jtree);
				if (ret > 0)
					json_tree_unref(&jtree);
			}
			if (jtree == NULL)
				ret = json_ostream_flush(joutput);
		}
		json_ostream_unref(&joutput);
		test_out_quiet("output stream ok (trickle)", ret > 0);

		test_out_quiet("io match (trickle)",
			       strcmp(text_out, str_c(outbuf)) == 0);

		if (debug) {
			i_debug("OUT: >%s<", text_out);
			i_debug("OUT: >%s<", str_c(outbuf));
		}

		json_tree_unref(&jtree);
		i_stream_unref(&input);
		o_stream_unref(&output);

		buffer_set_used_size(outbuf, 0);

		input = test_istream_create_data(text, text_len);
		output = o_stream_create_buffer(outbuf);
		o_stream_set_no_error_handling(output, TRUE);

		jinput = json_istream_create(input, 0, NULL, 0);
		joutput = json_ostream_create(output, 0);

		ret = json_istream_read_tree(jinput, &jtree);
		test_assert(ret > 0);

		ret = json_istream_finish(&jinput, &error);
		test_out_reason_quiet("input stream ok (buffer)",
				      ret > 0, error);

		if (jtree != NULL) {
			ret = json_ostream_write_tree(joutput, NULL, jtree);
			if (ret > 0) {
				json_tree_unref(&jtree);
				ret = json_ostream_flush(joutput);
			}
		}
		json_ostream_unref(&joutput);
		test_out_quiet("output stream ok (buffer)", ret > 0);

		test_out_quiet("io match (buffer)",
			       strcmp(text_out, str_c(outbuf)) == 0);

		if (debug) {
			i_debug("OUT: >%s<", text_out);
			i_debug("OUT: >%s<", str_c(outbuf));
		}

		json_tree_unref(&jtree);
		i_stream_unref(&input);
		o_stream_unref(&output);

		test_end();

	} T_END;

	buffer_free(&outbuf);
}

static void test_json_tree_file(const char *file)
{
	struct istream *input;
	struct ostream *output;
	struct json_istream *jinput;
	struct json_ostream *joutput;
	struct json_tree *jtree;
	int ret = 0;

	input = i_stream_create_file(file, 1024);
	output = o_stream_create_fd(1, 1024);
	o_stream_set_no_error_handling(output, TRUE);

	jinput = json_istream_create(input, 0, NULL,
		JSON_PARSER_FLAG_NUMBERS_AS_STRING);
	joutput = json_ostream_create(output, 0);

	ret = 0;
	while (ret == 0)
		ret = json_istream_read_tree(jinput, &jtree);

	if (ret < 0) {
		i_fatal("Failed to read JSON: %s",
			json_istream_get_error(jinput));
	}

	ret = 0;
	while (ret == 0) {
		if (jtree != NULL) {
			ret = json_ostream_write_tree(joutput, NULL, jtree);
			if (ret > 0)
				json_tree_unref(&jtree);
		}
		if (jtree == NULL)
			ret = json_ostream_flush(joutput);
	}

	if (ret < 0) {
		i_fatal("Failed to write JSON: %s",
			o_stream_get_error(output));
	}

	json_istream_unref(&jinput);
	json_ostream_unref(&joutput);

	o_stream_nsend_str(output, "\n");
	i_stream_unref(&input);
	o_stream_unref(&output);
}

int main(int argc, char *argv[])
{
	int c;

	static void (*test_functions[])(void) = {
		test_json_tree_io,
		test_json_tree_stream_io,
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
	argc -= optind;
	argv += optind;

	if (argc > 0) {
		test_json_tree_file(argv[0]);
		return 0;
	}

	return test_run(test_functions);
}
