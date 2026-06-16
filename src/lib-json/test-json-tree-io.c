/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"

#include "json-istream.h"
#include "json-ostream.h"
#include "json-tree.h"
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

/* Read all bytes from stream into a string_t. */
static void stream_read_all(struct istream *stream, string_t *out)
{
	const unsigned char *data;
	size_t size;
	int ret;

	while ((ret = i_stream_read_more(stream, &data, &size)) > 0) {
		str_append_data(out, data, size);
		i_stream_skip(stream, size);
	}
	i_assert(ret < 0 && stream->stream_errno == 0);
}

struct stream_limit_test {
	const char *input;
	/* name of the key whose value to check */
	const char *key;
	const char *expected;
	/* threshold to use */
	size_t threshold;
	/* TRUE if the string has escape sequences */
	bool has_escapes;
	/* expected content_type of the large-string node */
	enum json_content_type expected_ctype;
};

static const struct stream_limit_test stream_limit_tests[] = {
	/* String > threshold, no escapes → limit stream, no filter */
	{
		.input = "{\"k\":\"AABBCCDDEEFFGGHH\"}",
		.key = "k",
		.expected = "AABBCCDDEEFFGGHH",
		.threshold = 4,
		.has_escapes = FALSE,
		.expected_ctype = JSON_CONTENT_TYPE_STREAM,
	},
	/* String > threshold with escapes → limit stream + filter */
	{
		.input = "{\"k\":\"hello\\nworld\"}",
		.key = "k",
		.expected = "hello\nworld",
		.threshold = 4,
		.has_escapes = TRUE,
		.expected_ctype = JSON_CONTENT_TYPE_STREAM,
	},
	/* String < threshold → copied to pool as STRING */
	{
		.input = "{\"k\":\"hi\"}",
		.key = "k",
		.expected = "hi",
		.threshold = 10,
		.has_escapes = FALSE,
		.expected_ctype = JSON_CONTENT_TYPE_STRING,
	},
	/* Unicode escape */
	{
		.input = "{\"k\":\"A\\u0042CD\"}",
		.key = "k",
		.expected = "ABCD",
		.threshold = 2,
		.has_escapes = TRUE,
		.expected_ctype = JSON_CONTENT_TYPE_STREAM,
	},
	/* Surrogate pair: 𐐷 = U+10437 */
	{
		.input = "{\"k\":\"\\ud801\\udc37\"}",
		.key = "k",
		.expected = "\xf0\x90\x90\xb7",
		.threshold = 0,
		.has_escapes = TRUE,
		.expected_ctype = JSON_CONTENT_TYPE_STREAM,
	},
};

static void test_json_tree_stream_limit_io(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(stream_limit_tests); i++) T_BEGIN {
		const struct stream_limit_test *test = &stream_limit_tests[i];
		const char *text = test->input;
		size_t text_len = strlen(text);
		struct istream *input, *strm;
		struct json_istream *jinput;
		struct json_tree *jtree = NULL;
		struct json_tree_node *node, *member;
		const char *error = NULL;
		string_t *out;
		int ret;

		test_begin(t_strdup_printf(
			"json tree stream limit io [%u]", i));

		/* Use i_stream_create_from_data which is seekable */
		input = i_stream_create_from_data(text, text_len);
		jinput = json_istream_create(input, 0, NULL, 0);
		i_stream_unref(&input);

		while ((ret = json_istream_read_tree_lazy_strings(
					jinput, test->threshold,
					65536, &jtree)) == 0)
			;
		test_assert_idx(ret > 0, i);
		ret = json_istream_finish(&jinput, &error);
		test_assert_idx(ret > 0, i);

		node = json_tree_get_root(jtree);
		test_assert_idx(json_node_is_object(json_tree_node_get(node)), i);

		member = json_tree_node_get_member(node, test->key);
		test_assert_idx(member != NULL, i);
		if (member != NULL) {
			const struct json_node *jn =
				json_tree_node_get(member);
			test_assert_idx(
				jn->value.content_type == test->expected_ctype, i);

			out = t_str_new(64);
			test_assert(json_tree_node_get_str_istream(member, &strm) == 0);
			stream_read_all(strm, out);
			i_stream_unref(&strm);

			test_assert_strcmp_idx(str_c(out), test->expected, i);
		}

		json_tree_unref(&jtree);
		test_end();

	} T_END;
}

/* Test json_tree_node_get_str_istream for STRING and DATA content types */
static void test_json_tree_str_istream_types(void)
{
	struct json_tree *jtree;
	struct json_tree_node *root, *node;
	struct istream *strm;
	string_t *out;

	test_begin("json tree str_istream STRING type");
	jtree = json_tree_create();
	root = json_tree_node_add_object(json_tree_get_root(jtree), NULL);
	json_tree_node_add_string(root, "k", "hello");

	node = json_tree_node_get_member(root, "k");
	test_assert(node != NULL);
	test_assert(json_tree_node_get(node)->value.content_type ==
		    JSON_CONTENT_TYPE_STRING);

	out = t_str_new(16);
	test_assert(json_tree_node_get_str_istream(node, &strm) == 0);
	stream_read_all(strm, out);
	i_stream_unref(&strm);
	test_assert(strcmp(str_c(out), "hello") == 0);

	json_tree_unref(&jtree);
	test_end();

	test_begin("json tree str_istream DATA type");
	jtree = json_tree_create();
	root = json_tree_node_add_object(json_tree_get_root(jtree), NULL);
	/* data with embedded NUL */
	json_tree_node_add_data(root, "k",
				(const unsigned char *)"a\x00b", 3);

	node = json_tree_node_get_member(root, "k");
	test_assert(node != NULL);
	test_assert(json_tree_node_get(node)->value.content_type ==
		    JSON_CONTENT_TYPE_DATA);

	out = t_str_new(8);
	test_assert(json_tree_node_get_str_istream(node, &strm) == 0);
	stream_read_all(strm, out);
	i_stream_unref(&strm);
	test_assert_memcmp(out->data, out->used, "a\x00b", 3);

	json_tree_unref(&jtree);
	test_end();
}

/* Regression test: json_tree_node_get_str_istream()'s STREAM-content
   wrapper re-seeks the shared parent stream stored in the tree node as a
   side effect of tracking its own read progress.  json_tree_to_text()
   later reads that same parent stream directly, from wherever it was left,
   with no seek of its own - so serializing a lazy tree after draining one
   of its string values used to come out with that value silently missing
   (empty string), and serializing the same tree a second time (even
   without ever calling get_str_istream()) had the identical problem, since
   the first serialize pass itself leaves the stream at EOF. */
static void test_json_tree_stream_serialize_after_drain(void)
{
	const char *text = "{\"k\":\"AAAABBBBCCCC\"}";
	size_t text_len = strlen(text);
	struct istream *input;
	struct json_istream *jinput;
	struct json_tree *jtree = NULL;
	struct json_tree_node *root, *node;
	struct istream *strm;
	string_t *out;
	const char *error = NULL;
	int ret;

	test_begin("json tree serialize after draining a lazy string");

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);
	i_stream_unref(&input);

	while ((ret = json_istream_read_tree_lazy_strings(
				jinput, 4, 65536, &jtree)) == 0)
		;
	test_assert(ret > 0);
	ret = json_istream_finish(&jinput, &error);
	test_assert(ret > 0);

	root = json_tree_get_root(jtree);
	node = json_tree_node_get_member(root, "k");
	test_assert(node != NULL);

	if (node != NULL) {
		test_assert(json_tree_node_get(node)->value.content_type ==
			    JSON_CONTENT_TYPE_STREAM);

		out = t_str_new(32);
		test_assert(json_tree_node_get_str_istream(node, &strm) == 0);
		stream_read_all(strm, out);
		i_stream_unref(&strm);
		test_assert_strcmp(str_c(out), "AAAABBBBCCCC");

		test_assert_strcmp(json_tree_to_text(jtree, 0, NULL),
				   "{\"k\":\"AAAABBBBCCCC\"}");
	}

	json_tree_unref(&jtree);
	test_end();
}

static void test_json_tree_stream_serialize_twice(void)
{
	const char *text = "{\"k\":\"AAAABBBBCCCC\"}";
	size_t text_len = strlen(text);
	struct istream *input;
	struct json_istream *jinput;
	struct json_tree *jtree = NULL;
	const char *error = NULL;
	const char *out1, *out2;
	int ret;

	test_begin("json tree serialize lazy-strings tree twice");

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);
	i_stream_unref(&input);

	while ((ret = json_istream_read_tree_lazy_strings(
				jinput, 4, 65536, &jtree)) == 0)
		;
	test_assert(ret > 0);
	ret = json_istream_finish(&jinput, &error);
	test_assert(ret > 0);

	out1 = t_strdup(json_tree_to_text(jtree, 0, NULL));
	out2 = json_tree_to_text(jtree, 0, NULL);
	test_assert_strcmp(out1, "{\"k\":\"AAAABBBBCCCC\"}");
	test_assert_strcmp(out2, "{\"k\":\"AAAABBBBCCCC\"}");

	json_tree_unref(&jtree);
	test_end();
}

/* Regression test: json_generate_stream_rewind() runs once, at
   json_generate_value()'s single entry point for a STREAM-typed value -
   confirm that resuming a write after the output buffer fills mid-string
   (which drains generator->value_input directly, without ever calling
   json_generate_value() again for the same value) does not re-trigger the
   rewind and duplicate/corrupt the string content. */
static void test_json_tree_stream_serialize_small_buffer(void)
{
	const char *text = "{\"k\":\"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH\"}";
	size_t text_len = strlen(text);
	struct istream *input;
	struct json_istream *jinput;
	struct json_tree *jtree = NULL;
	struct ostream *output;
	struct json_ostream *joutput;
	string_t *outbuf;
	const char *error = NULL;
	unsigned int pos;
	int ret;

	test_begin("json tree serialize lazy string through small buffer");

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);
	i_stream_unref(&input);

	while ((ret = json_istream_read_tree_lazy_strings(
				jinput, 4, 65536, &jtree)) == 0)
		;
	test_assert(ret > 0);
	ret = json_istream_finish(&jinput, &error);
	test_assert(ret > 0);

	outbuf = str_new(default_pool, 64);
	output = o_stream_create_buffer(outbuf);
	o_stream_set_no_error_handling(output, TRUE);
	joutput = json_ostream_create(output, 0);

	ret = 0;
	for (pos = 0; pos <= 64 && ret == 0; pos++) {
		o_stream_set_max_buffer_size(output, pos);
		ret = json_ostream_write_tree(joutput, NULL, jtree);
	}
	test_assert(ret > 0);
	if (ret > 0)
		json_tree_unref(&jtree);
	o_stream_set_max_buffer_size(output, 65536);
	ret = json_ostream_flush(joutput);
	test_assert(ret > 0);

	test_assert_strcmp(str_c(outbuf), text);

	json_ostream_unref(&joutput);
	json_tree_unref(&jtree);
	o_stream_unref(&output);
	str_free(&outbuf);

	test_end();
}

/* Regression test: json_tree_node_get_str_istream() used to abort the
   process (i_unreached()) when called on a node whose content type isn't
   STRING/DATA/STREAM, instead of returning -1 like every sibling
   json_tree_node_get_*() accessor does on a type mismatch. */
static void test_json_tree_str_istream_type_mismatch(void)
{
	struct json_tree *jtree;
	struct json_tree_node *root, *node;
	struct istream *strm;

	test_begin("json tree str_istream type mismatch returns -1");

	jtree = json_tree_create();
	root = json_tree_node_add_object(json_tree_get_root(jtree), NULL);
	json_tree_node_add_number_int(root, "k", 42);

	node = json_tree_node_get_member(root, "k");
	test_assert(node != NULL);
	if (node != NULL)
		test_assert(json_tree_node_get_str_istream(node, &strm) == -1);

	json_tree_unref(&jtree);
	test_end();
}

/* Regression test: STRING/DATA-backed streams from get_str_istream() point
   directly into the tree's pool memory.  Unlike the STREAM case (which
   holds an explicit ref via the tree's own stream array), nothing used to
   keep the tree alive for as long as such a stream was - unref the tree,
   then read the stream, and it read freed pool memory. */
static void test_json_tree_str_istream_outlives_tree(void)
{
	struct json_tree *jtree;
	struct json_tree_node *root;
	struct istream *strm;
	string_t *out;

	test_begin("json tree str_istream outlives source tree");

	jtree = json_tree_create();
	root = json_tree_node_add_object(json_tree_get_root(jtree), NULL);
	json_tree_node_add_string(root, "k", "hello world");

	test_assert(json_tree_node_get_str_istream(
		json_tree_node_get_member(root, "k"), &strm) == 0);
	json_tree_unref(&jtree);

	out = t_str_new(16);
	stream_read_all(strm, out);
	i_stream_unref(&strm);
	test_assert_strcmp(str_c(out), "hello world");

	test_end();
}

/* Multiple large strings in one tree */
static void test_json_tree_stream_limit_multi(void)
{
	const char *text = "{\"a\":\"AAAABBBBCCCC\",\"b\":\"DDDDEEEEFFFF\"}";
	size_t text_len = strlen(text);
	struct istream *input;
	struct json_istream *jinput;
	struct json_tree *jtree = NULL;
	struct json_tree_node *root, *na, *nb;
	struct istream *sa, *sb;
	string_t *out;
	const char *error = NULL;
	int ret;

	test_begin("json tree stream limit multi-string");

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);
	i_stream_unref(&input);

	while ((ret = json_istream_read_tree_lazy_strings(
				jinput, 4, 65536, &jtree)) == 0)
		;
	test_assert(ret > 0);
	ret = json_istream_finish(&jinput, &error);
	test_assert(ret > 0);

	root = json_tree_get_root(jtree);
	na = json_tree_node_get_member(root, "a");
	nb = json_tree_node_get_member(root, "b");
	test_assert(na != NULL && nb != NULL);

	if (na != NULL && nb != NULL) {
		test_assert(json_tree_node_get(na)->value.content_type ==
			    JSON_CONTENT_TYPE_STREAM);
		test_assert(json_tree_node_get(nb)->value.content_type ==
			    JSON_CONTENT_TYPE_STREAM);

		out = t_str_new(32);
		test_assert(json_tree_node_get_str_istream(na, &sa) == 0);
		stream_read_all(sa, out);
		i_stream_unref(&sa);
		test_assert(strcmp(str_c(out), "AAAABBBBCCCC") == 0);

		str_truncate(out, 0);
		test_assert(json_tree_node_get_str_istream(nb, &sb) == 0);
		stream_read_all(sb, out);
		i_stream_unref(&sb);
		test_assert(strcmp(str_c(out), "DDDDEEEEFFFF") == 0);
	}

	json_tree_unref(&jtree);
	test_end();
}

/* Regression test: json_parser_deliver_range_stream() (json-parser.c) hands
   out a range stream that wraps parser->input directly. Reading or
   unref'ing that range stream seeks parser->input (see
   i_stream_limit_read()/i_stream_limit_destroy() in istream-limit.c), which
   used to move parser->input out from under the parser if that happened
   after the parser had already gone on to read further elements. Every
   other test in this file calls json_istream_finish() before touching any
   string stream, which never exercises this: strings must be read (and
   their trees unref'd) one array element at a time, interleaved with
   parsing the next element, and json_istream_finish() must not be called
   until after all elements are done. */
static void test_json_tree_stream_limit_interleaved(void)
{
	const char *text =
		"[\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
		 "\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\"]";
	const char *const expected[] = {
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	};
	size_t text_len = strlen(text);
	struct istream *input;
	struct json_istream *jinput;
	const char *error = NULL;
	unsigned int i;
	int ret;

	test_begin("json tree stream limit interleaved with parsing");

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create_array(input, NULL, 0);
	i_stream_unref(&input);

	for (i = 0; i < N_ELEMENTS(expected); i++) {
		struct json_tree *jtree = NULL;
		struct json_tree_node *root;
		struct istream *strm;
		string_t *out;

		while ((ret = json_istream_read_tree_lazy_strings(
					jinput, 4, 65536, &jtree)) == 0)
			;
		test_assert_idx(ret > 0, i);
		if (ret <= 0)
			break;

		root = json_tree_get_root(jtree);
		test_assert_idx(json_node_is_string(json_tree_node_get(root)),
				i);
		test_assert_idx(json_tree_node_get(root)->value.content_type ==
				JSON_CONTENT_TYPE_STREAM, i);

		out = t_str_new(32);
		test_assert_idx(
			json_tree_node_get_str_istream(root, &strm) == 0, i);
		stream_read_all(strm, out);
		i_stream_unref(&strm);
		test_assert_strcmp_idx(str_c(out), expected[i], i);

		json_tree_unref(&jtree);
	}

	ret = json_istream_finish(&jinput, &error);
	test_assert(ret > 0);

	test_end();
}

/* Same as test_json_tree_stream_limit_interleaved(), but with a file-backed
   input stream. i_stream_file_seek() discards the stream buffer on every
   seek, so this catches the parser resuming on stale begin/cur/end pointers
   after a lazy range stream seeked and refilled the shared input. */
static void test_json_tree_stream_limit_interleaved_file(void)
{
	const char *text =
		"[\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
		 "\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\"]";
	const char *const expected[] = {
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
	};
	size_t text_len = strlen(text);
	char path[] = "/tmp/test-json-tree-io.XXXXXX";
	struct istream *input;
	struct json_istream *jinput;
	const char *error = NULL;
	unsigned int i;
	int fd, ret;

	test_begin("json tree stream limit interleaved (file stream)");

	fd = mkstemp(path);
	i_assert(fd >= 0);
	i_assert(write(fd, text, text_len) == (ssize_t)text_len);
	i_assert(lseek(fd, 0, SEEK_SET) == 0);
	i_unlink(path);

	input = i_stream_create_fd_autoclose(&fd, 1024);
	jinput = json_istream_create_array(input, NULL, 0);
	i_stream_unref(&input);

	for (i = 0; i < N_ELEMENTS(expected); i++) {
		struct json_tree *jtree = NULL;
		struct json_tree_node *root;
		struct istream *strm;
		string_t *out;

		while ((ret = json_istream_read_tree_lazy_strings(
					jinput, 4, 65536, &jtree)) == 0)
			;
		test_assert_idx(ret > 0, i);
		if (ret <= 0)
			break;

		root = json_tree_get_root(jtree);
		test_assert_idx(json_node_is_string(json_tree_node_get(root)),
				i);

		out = t_str_new(32);
		test_assert_idx(
			json_tree_node_get_str_istream(root, &strm) == 0, i);
		stream_read_all(strm, out);
		i_stream_unref(&strm);
		test_assert_strcmp_idx(str_c(out), expected[i], i);

		json_tree_unref(&jtree);
	}

	ret = json_istream_finish(&jinput, &error);
	test_assert(ret > 0);
	if (ret <= 0 && error != NULL)
		i_error("finish: %s", error);

	test_end();
}

/* Regression test: json_tree_node_get_str_istream()'s STREAM-content case
   used to return a wrapper that still shared the seekable parent's live
   buffer, so reading a *sibling* node's stream could refill that buffer and
   silently corrupt a data pointer already returned (but not yet consumed)
   by an earlier sibling stream. Needs a refillable, file-backed input with
   a buffer smaller than the strings, matching production;
   i_stream_create_from_data() (used everywhere else in this file) never
   refills and would pass this test vacuously either way. */
static void test_json_tree_stream_sibling_no_corruption(void)
{
	unsigned char abuf[300], bbuf[300];
	string_t *text = t_str_new(700);
	char path[] = "/tmp/test-json-tree-io.XXXXXX";
	struct istream *input;
	struct json_istream *jinput;
	struct json_tree *jtree = NULL;
	struct json_tree_node *root, *node_a, *node_b;
	struct istream *strm_a, *strm_b;
	const unsigned char *data_a, *data_b;
	size_t size_a, size_b;
	string_t *out_a, *out_b;
	const char *error = NULL;
	int fd, ret;

	test_begin("json tree str_istream sibling reads do not corrupt");

	memset(abuf, 'A', sizeof(abuf));
	memset(bbuf, 'B', sizeof(bbuf));
	str_append(text, "{\"a\":\"");
	str_append_data(text, abuf, sizeof(abuf));
	str_append(text, "\",\"b\":\"");
	str_append_data(text, bbuf, sizeof(bbuf));
	str_append(text, "\"}");

	fd = mkstemp(path);
	i_assert(fd >= 0);
	i_assert(write(fd, str_data(text), str_len(text)) ==
		 (ssize_t)str_len(text));
	i_assert(lseek(fd, 0, SEEK_SET) == 0);
	i_unlink(path);

	input = i_stream_create_fd_autoclose(&fd, 64);
	jinput = json_istream_create(input, 0, NULL, 0);
	i_stream_unref(&input);

	while ((ret = json_istream_read_tree_lazy_strings(
				jinput, 4, 65536, &jtree)) == 0)
		;
	test_assert(ret > 0);
	ret = json_istream_finish(&jinput, &error);
	test_assert(ret > 0);

	root = json_tree_get_root(jtree);
	node_a = json_tree_node_get_member(root, "a");
	node_b = json_tree_node_get_member(root, "b");
	test_assert(node_a != NULL && node_b != NULL);
	if (node_a != NULL && node_b != NULL) {
		test_assert(json_tree_node_get_str_istream(node_a, &strm_a) == 0);
		ret = i_stream_read_more(strm_a, &data_a, &size_a);
		test_assert(ret > 0 && size_a > 0 && data_a[0] == 'A');

		test_assert(json_tree_node_get_str_istream(node_b, &strm_b) == 0);
		ret = i_stream_read_more(strm_b, &data_b, &size_b);
		test_assert(ret > 0 && size_b > 0 && data_b[0] == 'B');

		/* Re-check the pointer A's stream returned *before* B's
		   stream was touched, without calling anything on strm_a in
		   between (a fresh read call would just re-seek and correct
		   itself) - a shared-buffer implementation has this pointer
		   silently retargeted to B's data by now. */
		test_assert(data_a[0] == 'A');

		out_a = t_str_new(320);
		stream_read_all(strm_a, out_a);
		i_stream_unref(&strm_a);
		test_assert_memcmp(out_a->data, out_a->used,
				   abuf, sizeof(abuf));

		out_b = t_str_new(320);
		stream_read_all(strm_b, out_b);
		i_stream_unref(&strm_b);
		test_assert_memcmp(out_b->data, out_b->used,
				   bbuf, sizeof(bbuf));
	}

	json_tree_unref(&jtree);
	test_end();
}

/* Regression test: the json_parser_continue() reconcile block (which
   re-seeks parser->input after a lazy range stream moved it backward) used
   to merely inspect whatever was already buffered instead of performing an
   actual read.  A number value leaves its trailing delimiter decoded but
   not yet shifted when it completes (see json_parser_do_parse_number()'s
   _NUM_DOT/_NUM_E/_NUM_EXP_NEXT cases) - if a later drain of an earlier
   element's deferred string stream then seeks parser->input backward
   (discarding the file stream's buffer), that cached delimiter can end up
   dangling: json_parser_have_data() reports data is available even though
   cur == end, and the next shift pushes cur past end. Reproduced with a
   file istream (discards its buffer on seek, unlike an in-memory stream)
   and an array with a lazy string element immediately followed by a
   number element, draining the string only after the number has been
   read - matching test_json_tree_stream_limit_interleaved_file()'s
   pattern but with a number in the mix. */
static void test_json_tree_stream_limit_interleaved_number(void)
{
	const char *text =
		"[\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
		 "\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\",123]";
	size_t text_len = strlen(text);
	char path[] = "/tmp/test-json-tree-io.XXXXXX";
	struct istream *input;
	struct json_istream *jinput;
	struct json_tree *jtree0 = NULL, *jtree1 = NULL, *jtree2 = NULL;
	struct json_tree_node *root;
	struct istream *strm;
	string_t *out;
	const char *error = NULL;
	int fd, ret;

	test_begin("json tree stream limit interleaved (string, string, number)");

	fd = mkstemp(path);
	i_assert(fd >= 0);
	i_assert(write(fd, text, text_len) == (ssize_t)text_len);
	i_assert(lseek(fd, 0, SEEK_SET) == 0);
	i_unlink(path);

	input = i_stream_create_fd_autoclose(&fd, 1024);
	jinput = json_istream_create_array(input, NULL, 0);
	i_stream_unref(&input);

	/* Element 0: lazy string, drained immediately (as in
	   test_json_tree_stream_limit_interleaved_file()) - this is what
	   causes parser->input to seek backward relative to where the
	   parser itself has already advanced to. */
	while ((ret = json_istream_read_tree_lazy_strings(
				jinput, 4, 65536, &jtree0)) == 0)
		;
	test_assert(ret > 0);
	if (jtree0 != NULL) {
		root = json_tree_get_root(jtree0);
		out = t_str_new(32);
		test_assert(json_tree_node_get_str_istream(root, &strm) == 0);
		stream_read_all(strm, out);
		i_stream_unref(&strm);
		test_assert_strcmp(str_c(out),
				   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	}

	/* Element 1: another lazy string, drained immediately too. */
	while ((ret = json_istream_read_tree_lazy_strings(
				jinput, 4, 65536, &jtree1)) == 0)
		;
	test_assert(ret > 0);
	if (jtree1 != NULL) {
		root = json_tree_get_root(jtree1);
		out = t_str_new(32);
		test_assert(json_tree_node_get_str_istream(root, &strm) == 0);
		stream_read_all(strm, out);
		i_stream_unref(&strm);
		test_assert_strcmp(str_c(out),
				   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
	}

	/* Element 2: a number - completing it requires peeking at (and not
	   shifting) the following ']' delimiter.  Must parse without
	   panicking despite the two preceding backward-seeking drains. */
	while ((ret = json_istream_read_tree_lazy_strings(
				jinput, 4, 65536, &jtree2)) == 0)
		;
	test_assert(ret > 0);
	if (jtree2 != NULL) {
		root = json_tree_get_root(jtree2);
		test_assert(json_node_is_number(json_tree_node_get(root)));
	}

	json_tree_unref(&jtree0);
	json_tree_unref(&jtree1);
	json_tree_unref(&jtree2);

	ret = json_istream_finish(&jinput, &error);
	test_assert(ret > 0);
	if (ret <= 0 && error != NULL)
		i_error("finish: %s", error);

	test_end();
}

/* A string exceeding the range-mode max_buffer_size must be rejected with a
   parse error, not silently fall back to a non-seekable, unreadable stream
   (see json_parser_do_parse_value() _VALUE_STRING overflow handling). */
static void test_json_tree_stream_limit_range_overflow(void)
{
	const char *text = "{\"k\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}";
	size_t text_len = strlen(text);
	struct istream *input;
	struct json_istream *jinput;
	struct json_tree *jtree = NULL;
	const char *error = NULL;
	int ret;

	test_begin("json tree stream limit range overflow");

	/* Use i_stream_create_from_data which is seekable */
	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);
	i_stream_unref(&input);

	while ((ret = json_istream_read_tree_lazy_strings(
				jinput, 4, 16, &jtree)) == 0)
		;
	test_assert(ret < 0);

	if (jtree != NULL)
		json_tree_unref(&jtree);

	ret = json_istream_finish(&jinput, &error);
	test_assert(ret < 0);
	test_assert(error != NULL);

	test_end();
}

/* Empty string with threshold=0 */
static void test_json_tree_stream_limit_empty(void)
{
	const char *text = "{\"k\":\"\"}";
	size_t text_len = strlen(text);
	struct istream *input;
	struct json_istream *jinput;
	struct json_tree *jtree = NULL;
	struct json_tree_node *root, *node;
	struct istream *strm;
	string_t *out;
	const char *error = NULL;
	int ret;

	test_begin("json tree stream limit empty string");

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);
	i_stream_unref(&input);

	while ((ret = json_istream_read_tree_lazy_strings(
				jinput, 0, 65536, &jtree)) == 0)
		;
	test_assert(ret > 0);
	ret = json_istream_finish(&jinput, &error);
	test_assert(ret > 0);

	root = json_tree_get_root(jtree);
	node = json_tree_node_get_member(root, "k");
	test_assert(node != NULL);
	if (node != NULL) {
		out = t_str_new(4);
		test_assert(json_tree_node_get_str_istream(node, &strm) == 0);
		stream_read_all(strm, out);
		i_stream_unref(&strm);
		test_assert(str_len(out) == 0);
	}

	json_tree_unref(&jtree);
	test_end();
}

/* Non-seekable input falls back to json_string_istream, output still correct */
static void test_json_tree_stream_limit_nonseekable(void)
{
	const char *text = "{\"k\":\"AABBCCDDEEFFGGHH\"}";
	size_t text_len = strlen(text);
	struct istream *input;
	struct json_istream *jinput;
	struct json_tree *jtree = NULL;
	struct json_tree_node *root, *node;
	struct istream *strm;
	string_t *out;
	const char *error = NULL;
	unsigned int pos;
	int ret;

	test_begin("json tree stream limit non-seekable input");

	/* test_istream_create_data is seekable=TRUE but we trickle it;
	   the node will be a STREAM regardless; check output is correct */
	input = test_istream_create_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL, 0);

	ret = 0;
	for (pos = 0; pos <= text_len && ret == 0; pos++) {
		test_istream_set_size(input, pos);
		ret = json_istream_read_tree_lazy_strings(
			jinput, 4, 65536, &jtree);
	}
	test_assert(ret > 0);
	ret = json_istream_finish(&jinput, &error);
	test_assert(ret > 0);
	i_stream_unref(&input);

	root = json_tree_get_root(jtree);
	node = json_tree_node_get_member(root, "k");
	test_assert(node != NULL);
	if (node != NULL) {
		out = t_str_new(32);
		test_assert(json_tree_node_get_str_istream(node, &strm) == 0);
		stream_read_all(strm, out);
		i_stream_unref(&strm);
		test_assert(strcmp(str_c(out), "AABBCCDDEEFFGGHH") == 0);
	}

	json_tree_unref(&jtree);
	test_end();
}

/* All single-char escape types via tree stream */
static void test_json_tree_stream_limit_escapes(void)
{
	/* Each escape type, threshold=1 so all strings become streams */
	static const struct { const char *json; const char *expected; } cases[] = {
		{ "{\"k\":\"\\\"\"}", "\"" },
		{ "{\"k\":\"\\\\\"}", "\\" },
		{ "{\"k\":\"\\/\"}", "/" },
		{ "{\"k\":\"\\b\"}", "\x08" },
		{ "{\"k\":\"\\f\"}", "\x0c" },
		{ "{\"k\":\"\\n\"}", "\n" },
		{ "{\"k\":\"\\r\"}", "\r" },
		{ "{\"k\":\"\\t\"}", "\t" },
	};
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(cases); i++) T_BEGIN {
		const char *text = cases[i].json;
		size_t text_len = strlen(text);
		const char *expected = cases[i].expected;
		size_t expected_len = strlen(expected);
		struct istream *input;
		struct json_istream *jinput;
		struct json_tree *jtree = NULL;
		struct json_tree_node *root, *node;
		struct istream *strm;
		string_t *out;
		const char *error = NULL;
		int ret;

		test_begin(t_strdup_printf(
			"json tree stream limit escape [%u]", i));

		input = i_stream_create_from_data(text, text_len);
		jinput = json_istream_create(input, 0, NULL, 0);
		i_stream_unref(&input);

		while ((ret = json_istream_read_tree_lazy_strings(
					jinput, 1, 65536, &jtree)) == 0)
			;
		test_assert_idx(ret > 0, i);
		ret = json_istream_finish(&jinput, &error);
		test_assert_idx(ret > 0, i);

		root = json_tree_get_root(jtree);
		node = json_tree_node_get_member(root, "k");
		test_assert_idx(node != NULL, i);
		if (node != NULL) {
			out = t_str_new(8);
			test_assert(json_tree_node_get_str_istream(node, &strm) == 0);
			stream_read_all(strm, out);
			i_stream_unref(&strm);
			test_assert_memcmp_idx(out->data, out->used,
					       expected, expected_len, i);
		}
		json_tree_unref(&jtree);
		test_end();
	} T_END;
}

/* Regression test: the nested parser that decodes an escaped lazy string on
   demand (istream-json-string.c, reached via
   json_parser_deliver_range_stream()) used to be created with only
   JSON_PARSER_FLAG_INPUT_IS_STRING_CONTENT, dropping any JSON_PARSER_FLAG_
   STRINGS_* flags the outer parser had.  An escaped NUL parsed fine into
   the tree under an outer parser configured with STRINGS_ALLOW_NUL, but
   reading it back then failed EINVAL because the nested parser re-validated
   without that flag. */
static void test_json_tree_stream_escaped_nul_allow_nul(void)
{
	const char *text = "{\"k\":\"a\\u0000b\"}";
	size_t text_len = strlen(text);
	struct istream *input;
	struct json_istream *jinput;
	struct json_tree *jtree = NULL;
	struct json_tree_node *root, *node;
	struct istream *strm;
	string_t *out;
	const char *error = NULL;
	int ret;

	test_begin("json tree stream escaped NUL with STRINGS_ALLOW_NUL");

	input = i_stream_create_from_data(text, text_len);
	jinput = json_istream_create(input, 0, NULL,
				     JSON_PARSER_FLAG_STRINGS_ALLOW_NUL);
	i_stream_unref(&input);

	while ((ret = json_istream_read_tree_lazy_strings(
				jinput, 1, 65536, &jtree)) == 0)
		;
	test_assert(ret > 0);
	ret = json_istream_finish(&jinput, &error);
	test_assert(ret > 0);

	root = json_tree_get_root(jtree);
	node = json_tree_node_get_member(root, "k");
	test_assert(node != NULL);
	if (node != NULL) {
		out = t_str_new(8);
		test_assert(json_tree_node_get_str_istream(node, &strm) == 0);
		stream_read_all(strm, out);
		i_stream_unref(&strm);
		test_assert_memcmp(out->data, out->used, "a\x00" "b", 3);
	}

	json_tree_unref(&jtree);
	test_end();
}

/* Verify that json_tree_node_get_str_istream returns fresh content on every
   call, including for escape-decoded (json_string_istream) STREAM nodes. */
static void test_json_tree_stream_limit_repeated_read(void)
{
	static const struct {
		const char *json;
		const char *expected;
	} cases[] = {
		/* plain bytes — stored as seekable i_stream_create_range */
		{ "{\"k\":\"AAAABBBB\"}", "AAAABBBB" },
		/* single-char escapes — stored as json_string_istream */
		{ "{\"k\":\"AAA\\nBBB\"}", "AAA\nBBB" },
		/* unicode escapes */
		{ "{\"k\":\"\\u0041\\u0042\\u0043\"}", "ABC" },
	};
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(cases); i++) T_BEGIN {
		const char *text = cases[i].json;
		size_t text_len = strlen(text);
		const char *expected = cases[i].expected;
		size_t expected_len = strlen(expected);
		struct istream *input;
		struct json_istream *jinput;
		struct json_tree *jtree = NULL;
		struct json_tree_node *root, *node;
		struct istream *strm;
		string_t *out;
		const char *error = NULL;
		int ret;

		test_begin(t_strdup_printf(
			"json tree str_istream repeated read [%u]", i));

		input = i_stream_create_from_data(text, text_len);
		jinput = json_istream_create(input, 0, NULL, 0);
		i_stream_unref(&input);

		while ((ret = json_istream_read_tree_lazy_strings(
					jinput, 1, 65536, &jtree)) == 0)
			;
		test_assert_idx(ret > 0, i);
		ret = json_istream_finish(&jinput, &error);
		test_assert_idx(ret > 0, i);

		root = json_tree_get_root(jtree);
		node = json_tree_node_get_member(root, "k");
		test_assert_idx(node != NULL, i);
		if (node != NULL) {
			out = t_str_new(32);
			/* First read */
			test_assert(json_tree_node_get_str_istream(node, &strm) == 0);
			stream_read_all(strm, out);
			i_stream_unref(&strm);
			test_assert_memcmp_idx(out->data, out->used,
					       expected, expected_len, i);

			/* Second read — must return same content */
			str_truncate(out, 0);
			test_assert(json_tree_node_get_str_istream(node, &strm) == 0);
			stream_read_all(strm, out);
			i_stream_unref(&strm);
			test_assert_memcmp_idx(str_data(out), str_len(out),
					       expected, expected_len, i);
		}
		json_tree_unref(&jtree);
		test_end();
	} T_END;
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
		test_json_tree_stream_limit_io,
		test_json_tree_str_istream_types,
		test_json_tree_stream_serialize_after_drain,
		test_json_tree_stream_serialize_twice,
		test_json_tree_stream_serialize_small_buffer,
		test_json_tree_str_istream_type_mismatch,
		test_json_tree_str_istream_outlives_tree,
		test_json_tree_stream_limit_multi,
		test_json_tree_stream_limit_interleaved,
		test_json_tree_stream_limit_interleaved_file,
		test_json_tree_stream_sibling_no_corruption,
		test_json_tree_stream_limit_interleaved_number,
		test_json_tree_stream_limit_range_overflow,
		test_json_tree_stream_limit_empty,
		test_json_tree_stream_limit_nonseekable,
		test_json_tree_stream_limit_escapes,
		test_json_tree_stream_escaped_nul_allow_nul,
		test_json_tree_stream_limit_repeated_read,
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
