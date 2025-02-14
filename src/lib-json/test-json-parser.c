/* Copyright (c) 2017-2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "istream-base64.h"
#include "test-common.h"

#include "json-parser.h"

#include <unistd.h>

static bool debug = FALSE;

/*
 * Test: valid json
 */

struct json_valid_parse_test {
	const char *input;
	struct json_limits limits;
	enum json_parser_flags flags;
};

static const struct json_valid_parse_test
valid_parse_tests[] = {
	/* Test cases from https://github.com/nst/JSONTestSuite.git
	   Copyright (c) 2016 Nicolas Seriot
	   MIT License (see COPYING.MIT)
	 */
	{
		// y_array_arraysWithSpaces.json
		.input = "[[]   ]",
	},
	{
		// y_array_empty.json
		.input = "[]",
	},
	{
		// y_array_empty-string.json
		.input = "[\"\"]",
	},
	{
		// y_array_ending_with_newline.json
		.input = "[\"a\"]",
	},
	{
		// y_array_false.json
		.input = "[false]",
	},
	{
		// y_array_heterogeneous.json
		.input = "[null, 1, \"1\", {}]",
	},
	{
		// y_array_null.json
		.input = "[null]",
	},
	{
		// y_array_with_1_and_newline.json
		.input = "[1\n"
			"]",
	},
	{
		// y_array_with_leading_space.json
		.input = " [1]",
	},
	{
		// y_array_with_several_null.json
		.input = "[1,null,null,null,2]",
	},
	{
		// y_array_with_trailing_space.json
		.input = "[2] ",
	},
	{
		// y_number_0e+1.json
		.input = "[0e+1]",
	},
	{
		// y_number_0e1.json
		.input = "[0e1]",
	},
	{
		// y_number_after_space.json
		.input = "[ 4]",
	},
	{
		// y_number_double_close_to_zero.json
		.input = "[-0.000000000000000000000000000000000000"
			 "000000000000000000000000000000000000000001]\n",
	},
	{
		// y_number_int_with_exp.json
		.input = "[20e1]",
	},
	{
		// y_number.json
		.input = "[123e65]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// y_number_minus_zero.json
		.input = "[-0]",
	},
	{
		// y_number_negative_int.json
		.input = "[-123]",
	},
	{
		// y_number_negative_one.json
		.input = "[-1]",
	},
	{
		// y_number_negative_zero.json
		.input = "[-0]",
	},
	{
		// y_number_real_capital_e.json
		.input = "[1E22]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// y_number_real_capital_e_neg_exp.json
		.input = "[1E-2]",
	},
	{
		// y_number_real_capital_e_pos_exp.json
		.input = "[1E+2]",
	},
	{
		// y_number_real_exponent.json
		.input = "[123e45]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// y_number_real_fraction_exponent.json
		.input = "[123.456e78]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// y_number_real_neg_exp.json
		.input = "[1e-2]",
	},
	{
		// y_number_real_pos_exponent.json
		.input = "[1e+2]",
	},
	{
		// y_number_simple_int.json
		.input = "[123]",
	},
	{
		// y_number_simple_real.json
		.input = "[123.456789]",
	},
	{
		// y_object_basic.json
		.input = "{\"asd\":\"sdf\"}",
	},
	{
		// y_object_duplicated_key_and_value.json
		.input = "{\"a\":\"b\",\"a\":\"b\"}",
	},
	{
		// y_object_duplicated_key.json
		.input = "{\"a\":\"b\",\"a\":\"c\"}",
	},
	{
		// y_object_empty.json
		.input = "{}",
	},
	{
		// y_object_empty_key.json
		.input = "{\"\":0}",
	},
	{
		// y_object_extreme_numbers.json
		.input = "{ \"min\": -1.0e+28, \"max\": 1.0e+28 }",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// y_object.json
		.input = "{\"asd\":\"sdf\", \"dfg\":\"fgh\"}",
	},
	{
		// y_object_long_strings.json
		.input = "{\"x\":[{\"id\": "
			 "\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}], "
			 "\"id\": "
			 "\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\"}",
	},
	{
		// y_object_simple.json
		.input = "{\"a\":[]}",
	},
	{
		// y_object_string_unicode.json
		.input = "{\"title\":"
			 "\"\\u041f\\u043e\\u043b\\u0442\\u043e\\u0440\\u0430 "
			 "\\u0417\\u0435\\u043c\\u043b\\u0435\\u043a\\u043e"
			 "\\u043f\\u0430\" }",
	},
	{
		// y_object_with_newlines.json
		.input = "{\n"
			 "\"a\": \"b\"\n"
			 "}",
	},
	{
		// y_string_1_2_3_bytes_UTF-8_sequences.json
		.input = "[\"\\u0060\\u012a\\u12AB\"]",
	},
	{
		// y_string_accepted_surrogate_pair.json
		.input = "[\"\\uD801\\udc37\"]",
	},
	{
		// y_string_accepted_surrogate_pairs.json
		.input = "[\"\\ud83d\\ude39\\ud83d\\udc8d\"]",
	},
	{
		// y_string_allowed_escapes.json,
		.input = "[\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"]",
	},
	{
		// y_string_backslash_and_u_escaped_zero.json
		.input = "[\"\\\\u0000\"]",
	},
	{
		// y_string_backslash_doublequotes.json
		.input = "[\"\\\"\"]",
	},
	{
		// y_string_comments.json
		.input = "[\"a/*b*/c/*d//e\"]",
	},
	{
		// y_string_double_escape_a.json
		.input = "[\"\\\\a\"]",
	},
	{
		// y_string_double_escape_n.json
		.input = "[\"\\\\n\"]",
	},
	{
		// y_string_escaped_control_character.json
		.input = "[\"\\u0012\"]",
	},
	{
		// y_string_escaped_noncharacter.json
		.input = "[\"\\uFFFF\"]",
	},
	{
		// y_string_in_array.json
		.input = "[\"asd\"]",
	},
	{
		// y_string_in_array_with_leading_space.json
		.input = "[ \"asd\"]",
	},
	{
		// y_string_last_surrogates_1_and_2.json
		.input = "[\"\\uDBFF\\uDFFF\"]",
	},
	{
		// y_string_nbsp_uescaped.json
		.input = "[\"new\\u00A0line\"]",
	},
	{
		// y_string_nonCharacterInUTF-8_U+10FFFF.json
		.input = "[\"\xf4\x8f\xbf\xbf\"]",
	},
	{
		// y_string_nonCharacterInUTF-8_U+1FFFF.json
		.input = "[\"\xf0\x9b\xbf\xbf\"]",
	},
	{
		// y_string_nonCharacterInUTF-8_U+FFFF.json
		.input = "[\"\xef\xbf\xbf\"]",
	},
	{
		// y_string_null_escape.json
		.input = "[\"\\u0000\"]",
		.flags = JSON_PARSER_FLAG_STRINGS_ALLOW_NUL,
	},
	{
		// y_string_one-byte-utf-8.json
		.input = "[\"\\u002c\"]",
	},
	{
		// y_string_pi.json
		.input = "[\"\xcf\x80\"]",
	},
	{
		// y_string_simple_ascii.json
		.input = "[\"asd \"]",
	},
	{
		// y_string_space.json
		.input = "\" \"",
	},
	{
		// y_string_surrogates_U+1D11E_MUSICAL_SYMBOL_G_CLEF.json
		.input = "[\"\\uD834\\uDd1e\"]",
	},
	{
		// y_string_three-byte-utf-8.json
		.input = "[\"\\u0821\"]",
	},
	{
		// y_string_two-byte-utf-8.json
		.input = "[\"\\u0123\"]",
	},
	{
		// y_string_u+2028_line_sep.json
		.input = "[\"\xe2\x80\xa8\"]",
	},
	{
		// y_string_u+2029_par_sep.json
		.input = "[\"\xe2\x80\xa9\"]",
	},
	{
		// y_string_uescaped_newline.json
		.input = "[\"new\\u000Aline\"]",
	},
	{
		// y_string_uEscape.json
		.input = "[\"\\u0061\\u30af\\u30EA\\u30b9\"]",
	},
	{
		// y_string_unescaped_char_delete.json
		.input = "[\"\x7f\"]",
	},
	{
		// y_string_unicode_2.json
		.input = "[\"\xe2\x8d\x82\xe3\x88\xb4\xe2\x8d\x82\"]",
	},
	{
		// y_string_unicodeEscapedBackslash.json
		.input = "[\"\\u005C\"]",
	},
	{
		// y_string_unicode_escaped_double_quote.json
		.input = "[\"\\u0022\"]",
	},
	{
		// y_string_unicode.json
		.input = "[\"\\uA66D\"]",
	},
	{
		// y_string_unicode_U+10FFFE_nonchar.json
		.input = "[\"\\uDBFF\\uDFFE\"]",
	},
	{
		// y_string_unicode_U+1FFFE_nonchar.json
		.input = "[\"\\uD83F\\uDFFE\"]",
	},
	{
		// y_string_unicode_U+200B_ZERO_WIDTH_SPACE.json
		.input = "[\"\\u200B\"]",
	},
	{
		// y_string_unicode_U+2064_invisible_plus.json
		.input = "[\"\\u2064\"]",
	},
	{
		// y_string_unicode_U+FDD0_nonchar.json
		.input = "[\"\\uFDD0\"]",
	},
	{
		// y_string_unicode_U+FFFE_nonchar.json
		.input = "[\"\\uFFFE\"]",
	},
	{
		// y_string_utf8.json
		.input = "[\"\xe2\x82\xac\xf0\x9d\x84\x9e\"]",
	},
	{
		// y_string_with_del_character.json
		.input = "[\"a\x7f""a\"]",
	},
	{
		// y_structure_lonely_false.json
		.input = "false",
	},
	{
		// y_structure_lonely_int.json
		.input = "42",
	},
	{
		// y_structure_lonely_negative_real.json
		.input = "-0.1",
	},
	{
		// y_structure_lonely_null.json
		.input = "null",
	},
	{
		// y_structure_lonely_string.json
		.input = "\"asd\"",
	},
	{
		// y_structure_lonely_true.json
		.input = "true",
	},
	{
		// y_structure_string_empty.json
		.input = "\"\"",
	},
	{
		// y_structure_trailing_newline.json
		.input = "[\"a\"]\n",
	},
	{
		// y_structure_true_in_array.json
		.input = "[true]",
	},
	{
		// y_structure_whitespace_array.json
		.input = " [] ",
	},
	{
		// i_number_double_huge_neg_exp.json
		.input = "[123.456e-789]",
	},
	{
		// i_number_huge_exp.json
		.input = "[0.4e0066999999999999999999999999999999999"
			 "99999999999999999999999999999999999999999999999"
			 "99999999999999999999999999999999999969999999006]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// i_number_neg_int_huge_exp.json
		.input = "[-1e+9999]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// i_number_pos_double_huge_exp.json
		.input = "[1.5e+9999]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// i_number_real_neg_overflow.json
		.input = "[-123123e100000]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// i_number_real_pos_overflow.json
		.input = "[123123e100000]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// i_number_real_underflow.json
		.input = "[123e-10000000]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// i_number_too_big_neg_int.json
		.input = "[-123123123123123123123123123123]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING
	},
	{
		// i_number_too_big_pos_int.json
		.input = "[100000000000000000000]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// i_number_very_big_negative_int.json
		.input = "[-237462374673276894279832749832423479823246327846]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// i_structure_500_nested_arrays.json
		.input =
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
		.limits = { .max_nesting = 500 },
	},
	/* From json.org */
	{
		.input = "[\n"
			"    \"JSON Test Pattern pass1\",\n"
			"    {\"object with 1 member\":[\"array with 1 element\"]},\n"
			"    {},\n"
			"    [],\n"
			"    -42,\n"
			"    true,\n"
			"    false,\n"
			"    null,\n"
			"    {\n"
			"        \"integer\": 1234567890,\n"
			"        \"real\": -9876.543210,\n"
			"        \"e\": 0.123456789e-12,\n"
			"        \"E\": 1.234567890E+34,\n"
			"        \"\":  23456789012E66,\n"
			"        \"zero\": 0,\n"
			"        \"one\": 1,\n"
			"        \"space\": \" \",\n"
			"        \"quote\": \"\\\"\",\n"
			"        \"backslash\": \"\\\\\",\n"
			"        \"controls\": \"\\b\\f\\n\\r\\t\",\n"
			"        \"slash\": \"/ & \\/\",\n"
			"        \"alpha\": \"abcdefghijklmnopqrstuvwyz\",\n"
			"        \"ALPHA\": \"ABCDEFGHIJKLMNOPQRSTUVWYZ\",\n"
			"        \"digit\": \"0123456789\",\n"
			"        \"0123456789\": \"digit\",\n"
			"        \"special\": \"`1~!@#$%^&*()_+-={':[,]}|;.</>?\",\n"
			"        \"hex\": \"\\u0123\\u4567\\u89AB\\uCDEF\\uabcd\\uef4A\",\n"
			"        \"true\": true,\n"
			"        \"false\": false,\n"
			"        \"null\": null,\n"
			"        \"array\":[  ],\n"
			"        \"object\":{  },\n"
			"        \"address\": \"50 St. James Street\",\n"
			"        \"url\": \"http://www.JSON.org/\",\n"
			"        \"comment\": \"// /* <!-- --\",\n"
			"        \"# -- --> */\": \" \",\n"
			"        \" s p a c e d \" :[1,2 , 3\n"
			"\n"
			",\n"
			"\n"
			"4 , 5        ,          6           ,7        ],"
				"\"compact\":[1,2,3,4,5,6,7],\n"
			"        \"jsontext\": \"{\\\"object with 1 member\\\":"
				"[\\\"array with 1 element\\\"]}\",\n"
			"        \"quotes\": \"&#34; \\u0022 %22 0x22 034 &#x22;\",\n"
			"        \"\\/\\\\\\\"\\uCAFE\\uBABE\\uAB98\\uFCDE\\ubcda\\uef4A"
				"\\b\\f\\n\\r\\t`1~!@#$%^&*()_+-=[]{}|;:',./<>?\"\n"
			": \"A key can be any string\"\n"
			"    },\n"
			"    0.5 ,98.6\n"
			",\n"
			"99.44\n"
			",\n"
			"\n"
			"1066,\n"
			"1e1,\n"
			"0.1e1,\n"
			"1e-1,\n"
			"1e00,2e+00,2e-00\n"
			",\"rosebud\"]",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		.input =
			"[[[[[[[[[[[[[[[[[[[\"Not too deep\"]]]]]]]]]]]]]]]]]]]",
	},
	{
		.input =
			"{\n"
			"    \"JSON Test Pattern pass3\": {\n"
			"        \"The outermost value\": \"must be an object or array.\",\n"
			"        \"In this test\": \"It is an object.\"\n"
			"    }\n"
			"}\n",
	},
	/* Test cases from Jansson project (http://www.digip.org/jansson/)
	   Copyright (c) 2009-2020 Petri Lehtinen
	   MIT License (see COPYING.MIT)
	 */
	{
		// valid/utf-surrogate-four-byte-encoding/input
		.input = "[\"\\uD834\\uDD1E surrogate, four-byte UTF-8\"]\n",
	},
	{
		// valid/real-subnormal-number/input
		.input = "[1.8011670033376514e-308]\n",
	},
	{
		// valid/empty-object-in-array/input
		.input = "[{}]\n",
	},
	{
		// valid/one-byte-utf-8/input
		.input = "[\"\\u002c one-byte UTF-8\"]\n",
	},
	{
		// valid/two-byte-utf-8/input
		.input = "[\"\\u0123 two-byte UTF-8\"]\n",
	},
	{
		// valid/real-positive-exponent/input
		.input = "[1e+2]\n",
	},
	{
		// valid/negative-zero/input
		.input = "[-0]\n",
	},
	{
		// valid/simple-int-1/input
		.input = "[1]\n",
	},
	{
		// valid/escaped-utf-control-char/input
		.input = "[\"\\u0012 escaped control character\"]\n",
	},
	{
		// valid/three-byte-utf-8/input
		.input = "[\"\\u0821 three-byte UTF-8\"]\n",
	},
	{
		// valid/empty-object/input
		.input = "{}\n",
	},
	{
		// valid/empty-string/input
		.input = "[\"\"]\n",
	},
	{
		// valid/real-exponent/input
		.input = "[123e45]\n",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// valid/string-escapes/input
		.input = "[\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"]\n",
	},
	{
		// valid/simple-ascii-string/input
		.input = "[\"abcdefghijklmnopqrstuvwxyz1234567890 \"]\n",
	},
	{
		// valid/real-negative-exponent/input
		.input = "[1e-2]\n",
	},
	{
		// valid/real-underflow/input
		.input = "[123e-10000000]\n",
	},
	{
		// valid/null/input
		.input = "[null]\n",
	},
	{
		// valid/real-fraction-exponent/input
		.input = "[123.456e78]\n",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// valid/true/input
		.input = "[true]\n",
	},
	{
		// valid/simple-object/input
		.input = "{\"a\":[]}\n",
	},
	{
		// valid/real-capital-e-negative-exponent/input
		.input = "[1E-2]\n",
	},
	{
		// valid/empty-array/input
		.input = "[]\n",
	},
	{
		// valid/negative-one/input
		.input = "[-1]\n",
	},
	{
		// valid/short-string/input
		.input = "[\"a\"]\n",
	},
	{
		// valid/simple-int-123/input
		.input = "[123]\n",
	},
	{
		// valid/false/input
		.input = "[false]\n",
	},
	{
		// valid/simple-int-0/input
		.input = "[0]\n",
	},
	{
		// valid/real-capital-e/input
		.input = "[1E22]\n",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
	},
	{
		// valid/complex-array/input
		.input = "[1,2,3,4,\n"
			"\"a\", \"b\", \"c\",\n"
			"{\"foo\": \"bar\", \"core\": \"dump\"},\n"
			"true, false, true, true, null, false\n"
			"]\n",
	},
	{
		// valid/real-capital-e-positive-exponent/input
		.input = "[1E+2]\n",
	},
	{
		// valid/negative-int/input
		.input = "[-123]\n",
	},
	{
		// valid/utf-8-string/input
		.input = "[\"\xe2\x82\xac\xc3\xbe\xc4\xb1\xc5\x93\xc9"
			"\x99\xc3\x9f\xc3\xb0 some utf-8 \xc4\xb8\xca\x92"
			"\xc3\x97\xc5\x8b\xc2\xb5\xc3\xa5\xc3\xa4\xc3\xb6"
			"\xf0\x9d\x84\x9e\"]\n",
	},
	{
		// valid/simple-real/input
		.input = "[123.456789]\n",
	/* Limits */
	},
	{
		.input =
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
	},
	{
		.input =
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
		.limits = { .max_nesting = 105 },
	},
	{
		.input =
			"[1,2,3,4,5,6,7,8,9,0,\n"
			" 1,2,3,4,5,6,7,8,9,0,\n"
			" 1,2,3,4,5,6,7,8,9,0,\n"
			" 1,2,3,4,5,6,7,8,9,0,\n"
			" 1,2,3,4,5,6,7,8,9,0]\n",
		.limits = { .max_list_items = 50 },
	},
	{
		.input =
			"\"123456789012345678901234567890"
			"123456789012345678901234567890"
			"123456789012345678901234567890\"",
		.limits = { .max_string_size = 90 },
	},
	{
		.input =
			"123456789012345678901234567890"
			"123456789012345678901234567890"
			"123456789012345678901234567890",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
		.limits = { .max_string_size = 90 },
	},
	{
		.input =
			"{\"123456789012345678901234567890"
			"123456789012345678901234567890"
			"123456789012345678901234567890\": 90}",
		.limits = { .max_name_size = 90 },
	},
	/* Problems found by fuzzer */
	{
		.input = "0e11111111111111110",
		.flags = JSON_PARSER_FLAG_STRICT,
	},
};

static const unsigned int valid_parse_test_count =
	N_ELEMENTS(valid_parse_tests);

static void test_json_parse_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_parse_test_count; i++) T_BEGIN {
		const struct json_valid_parse_test *test;
		struct istream *input;
		struct json_parser *parser;
		const char *text, *error = NULL;
		unsigned int pos, text_len;
		int ret = 0;

		test = &valid_parse_tests[i];

		text = test->input;
		text_len = strlen(text);
		input = test_istream_create_data(text, text_len);

		test_begin(t_strdup_printf("json text valid [%d]", i));

		parser = json_parser_init(input,
			&test->limits, test->flags, NULL, NULL);

		for (pos = 0; pos <= text_len && ret == 0; pos++) {
			test_istream_set_size(input, pos);
			ret = json_parse_more(parser, &error);
			if (ret < 0) {
				if (debug)
					i_debug("DATA: `%s'", text);
				break;
			}
		}
		test_out_reason_quiet("parse success (trickle)",
				      ret > 0, error);

		json_parser_deinit(&parser);

		i_stream_seek(input, 0);
		parser = json_parser_init(input,
			&test->limits, test->flags, NULL, NULL);

		test_istream_set_size(input, text_len);
		ret = json_parse_more(parser, &error);
		if (ret < 0) {
			if (debug)
				i_debug("DATA: `%s'", text);
		}
		test_out_reason_quiet("parse success (buffered)",
				      ret > 0, error);
		json_parser_deinit(&parser);

		test_end();

		i_stream_unref(&input);

	} T_END;
}

/*
 * Test: invalid json
 */

struct json_invalid_parse_test {
	const char *input;
	size_t input_len;
	struct json_limits limits;
	enum json_parser_flags flags;
	bool base64;
};

static const struct json_invalid_parse_test
invalid_parse_tests[] = {
	/* Test cases from https://github.com/nst/JSONTestSuite.git
	   Copyright (c) 2016 Nicolas Seriot
	   MIT License (see COPYING.MIT)
	 */
	{
		// n_array_1_true_without_comma.json
		.input = "[1 true]",
	},
	{
		// n_array_a_invalid_utf8.json
		.input = "[a\xe5]",
	},
	{
		// n_array_colon_instead_of_comma.json
		.input = "[\"\": 1]",
	},
	{
		// n_array_comma_after_close.json
		.input = "[\"\"],",
	},
	{
		// n_array_comma_and_number.json
		.input = "[,1]",
	},
	{
		// n_array_double_comma.json
		.input = "[1,,2]",
	},
	{
		// n_array_double_extra_comma.json
		.input = "[\"x\",,]",
	},
	{
		// n_array_extra_close.json
		.input = "[\"x\"]]",
	},
	{
		// n_array_extra_comma.json
		.input = "[\"\",]",
	},
	{
		// n_array_incomplete_invalid_value.json
		.input = "[x",
	},
	{
		// n_array_incomplete.json
		.input = "[\"x\"",
	},
	{
		// n_array_inner_array_no_comma.json
		.input = "[3[4]]",
	},
	{
		// n_array_invalid_utf8.json
		.input = "[\xff]",
	},
	{
		// n_array_items_separated_by_semicolon.json
		.input = "[1:2]",
	},
	{
		// n_array_just_comma.json
		.input = "[,]",
	},
	{
		// n_array_just_minus.json
		.input = "[-]",
	},
	{
		// n_array_missing_value.json
		.input = "[   , \"\"]",
	},
	{
		// n_array_newlines_unclosed.json
		.input = "[\"a\",\n"
			 "4\n"
			 ",1,",
	},
	{
		// n_array_number_and_comma.json
		.input = "[1,]",
	},
	{
		// n_array_number_and_several_commas.json
		.input = "[1,,]",
	},
	{
		// n_array_spaces_vertical_tab_formfeed.json
		.input = "[\"\va\"\\f]",
	},
	{
		// n_array_star_inside.json
		.input = "[*]",
	},
	{
		// n_array_unclosed.json
		.input = "[\"\"",
	},
	{
		// n_array_unclosed_trailing_comma.json
		.input = "[1,",
	},
	{
		// n_array_unclosed_with_new_lines.json
		.input = "[1,\n"
			 "1\n"
			 ",1",
	},
	{
		// n_array_unclosed_with_object_inside.json
		.input = "[{}",
	},
	{
		// n_incomplete_false.json
		.input = "[fals]",
	},
	{
		// n_incomplete_null.json
		.input = "[nul]",
	},
	{
		// n_incomplete_true.json
		.input = "[tru]",
	},
	{
		// n_multidigit_number_then_00.json
		.input = "123\x00",
		.input_len = 4,
	},
	{
		// n_number_0.1.2.json
		.input = "[0.1.2]",
	},
	{
		// n_number_-01.json
		.input = "[-01]",
	},
	{
		// n_number_0.3e.json
		.input = "[0.3e]",
	},
	{
		// n_number_0.3e+.json
		.input = "[0.3e+]",
	},
	{
		// n_number_0_capital_E.json
		.input = "[0E]",
	},
	{
		// n_number_0_capital_E+.json
		.input = "[0E+]",
	},
	{
		// n_number_0.e1.json
		.input = "[0.e1]",
	},
	{
		// n_number_0e.json
		.input = "[0e]",
	},
	{
		// n_number_0e+.json
		.input = "[0e+]",
	},
	{
		// n_number_1_000.json
		.input = "[1 000.0]",
	},
	{
		// n_number_1.0e-.json
		.input = "[1.0e-]",
	},
	{
		// n_number_1.0e.json
		.input = "[1.0e]",
	},
	{
		// n_number_1.0e+.json
		.input = "[1.0e+]",
	},
	{
		// n_number_-1.0..json
		.input = "[-1.0.]",
	},
	{
		// n_number_1eE2.json
		.input = "[1eE2]",
	},
	{
		// n_number_.-1.json
		.input = "[.-1]",
	},
	{
		// n_number_+1.json
		.input = "[+1]",
	},
	{
		// n_number_.2e-3.json
		.input = "[.2e-3]",
	},
	{
		// n_number_2.e-3.json
		.input = "[2.e-3]",
	},
	{
		// n_number_2.e+3.json
		.input = "[2.e+3]",
	},
	{
		// n_number_2.e3.json
		.input = "[2.e3]",
	},
	{
		// n_number_-2..json
		.input = "[-2.]",
	},
	{
		// n_number_9.e+.json
		.input = "[9.e+]",
	},
	{
		// n_number_expression.json
		.input = "[1+2]",
	},
	{
		// n_number_hex_1_digit.json
		.input = "[0x1]",
	},
	{
		// n_number_hex_2_digits.json
		.input = "[0x42]",
	},
	{
		// n_number_infinity.json
		.input = "[Infinity]",
	},
	{
		// n_number_+Inf.json
		.input = "[+Inf]",
	},
	{
		// n_number_Inf.json
		.input = "[Inf]",
	},
	{
		// n_number_invalid+-.json
		.input = "[0e+-1]",
	},
	{
		// n_number_invalid-negative-real.json
		.input = "[-123.123foo]",
	},
	{
		// n_number_invalid-utf-8-in-bigger-int.json
		.input = "[123\xe5]",
	},
	{
		// n_number_invalid-utf-8-in-exponent.json
		.input = "[1e1\xe5]",
	},
	{
		// n_number_invalid-utf-8-in-int.json
		.input = "[0\xe5]\n",
	},
	{
		// n_number_++.json
		.input = "[++1234]",
	},
	{
		// n_number_minus_infinity.json
		.input = "[-Infinity]",
	},
	{
		// n_number_minus_sign_with_trailing_garbage.json
		.input = "[-foo]",
	},
	{
		// n_number_minus_space_1.json
		.input = "[- 1]",
	},
	{
		// n_number_-NaN.json
		.input = "[-NaN]",
	},
	{
		// n_number_NaN.json
		.input = "[NaN]",
	},
	{
		// n_number_neg_int_starting_with_zero.json
		.input = "[-012]",
	},
	{
		// n_number_neg_real_without_int_part.json
		.input = "[-.123]",
	},
	{
		// n_number_neg_with_garbage_at_end.json
		.input = "[-1x]",
	},
	{
		// n_number_real_garbage_after_e.json
		.input = "[1ea]",
	},
	{
		// n_number_real_with_invalid_utf8_after_e.json
		.input = "[1e\xe5]",
	},
	{
		// n_number_real_without_fractional_part.json
		.input = "[1.]",
	},
	{
		// n_number_starting_with_dot.json
		.input = "[.123]",
	},
	{
		// n_number_U+FF11_fullwidth_digit_one.json
		.input = "[\xef\xbc\x91]",
	},
	{
		// n_number_with_alpha_char.json
		.input = "[1.8011670033376514H-308]",
	},
	{
		// n_number_with_alpha.json
		.input = "[1.2a-3]",
	},
	{
		// n_number_with_leading_zero.json
		.input = "[012]",
	},
	{
		// n_object_bad_value.json
		.input = "[\"x\", truth]",
	},
	{
		// n_object_bracket_key.json
		.input = "{[: \"x\"}\n",
	},
	{
		// n_object_comma_instead_of_colon.json
		.input = "{\"x\", null}",
	},
	{
		// n_object_double_colon.json
		.input = "{\"x\"::\"b\"}",
	},
	{
		// n_object_emoji.json
		.input = "{\xf0\x9f\x87\xa8\xf0\x9f\x87\xad}",
	},
	{
		// n_object_garbage_at_end.json
		.input = "{\"a\":\"a\" 123}",
	},
	{
		// n_object_key_with_single_quotes.json
		.input = "{key: 'value'}",
	},
	{
		// n_object_missing_colon.json
		.input = "{\"a\" b}",
	},
	{
		// n_object_missing_key.json
		.input = "{:\"b\"}",
	},
	{
		// n_object_missing_semicolon.json
		.input = "{\"a\" \"b\"}",
	},
	{
		// n_object_missing_value.json
		.input = "{\"a\":",
	},
	{
		// n_object_no-colon.json
		.input = "{\"a\"",
	},
	{
		// n_object_non_string_key_but_huge_number_instead.json
		.input = "{9999E9999:1}",
	},
	{
		// n_object_non_string_key.json
		.input = "{1:1}",
	},
	{
		// n_object_pi_in_key_and_trailing_comma.json
		.input = "{\"\xb9\":\"0\",}",
	},
	{
		// n_object_repeated_null_null.json
		.input = "{null:null,null:null}",
	},
	{
		// n_object_several_trailing_commas.json
		.input = "{\"id\":0,,,,,}",
	},
	{
		// n_object_single_quote.json
		.input = "{'a':0}",
	},
	{
		// n_object_trailing_comma.json
		.input = "{\"id\":0,}",
	},
	{
		// n_object_trailing_comment.json
		.input = "{\"a\":\"b\"}/**/",
	},
	{
		// n_object_trailing_comment_open.json
		.input = "{\"a\":\"b\"}/**//",
	},
	{
		// n_object_trailing_comment_slash_open_incomplete.json
		.input = "{\"a\":\"b\"}/",
	},
	{
		// n_object_trailing_comment_slash_open.json
		.input = "{\"a\":\"b\"}//",
	},
	{
		// n_object_two_commas_in_a_row.json
		.input = "{\"a\":\"b\",,\"c\":\"d\"}",
	},
	{
		// n_object_unquoted_key.json
		.input = "{a: \"b\"}",
	},
	{
		// n_object_unterminated-value.json
		.input = "{\"a\":\"a",
	},
	{
		// n_object_with_single_string.json
		.input = "{ \"foo\" : \"bar\", \"a\" }",
	},
	{
		// n_object_with_trailing_garbage.json
		.input = "{\"a\":\"b\"}#",
	},
	{
		// n_single_space.json
		.input = " ",
	},
	{
		// n_string_1_surrogate_then_escape.json
		.input = "[\"\\uD800\\\"]",
	},
	{
		// n_string_1_surrogate_then_escape_u1.json
		.input = "[\"\\uD800\\u1\"]",
	},
	{
		// n_string_1_surrogate_then_escape_u1x.json
		.input = "[\"\\uD800\\u1x\"]",
	},
	{
		// n_string_1_surrogate_then_escape_u.json
		.input = "[\"\\uD800\\u\"]",
	},
	{
		// n_string_accentuated_char_no_quotes.json
		.input = "[\xc3\xa9]",
	},
	{
		// n_string_backslash_00.json
		.input = "[\"\\\x00\"]",
	},
	{
		// n_string_escaped_backslash_bad.json
		.input = "[\"\\\\\\\"]",
	},
	{
		// n_string_escaped_ctrl_char_tab.json
		.input = "[\"\\\t\"]",
	},
	{
		// n_string_escaped_emoji.json
		.input = "[\"\\\xf0\x9f\x8c\x80\"]",
	},
	{
		// n_string_escape_x.json
		.input = "[\"\\x00\"]",
	},
	{
		// n_string_incomplete_escaped_character.json
		.input = "[\"\\u00A\"]",
	},
	{
		// n_string_incomplete_escape.json
		.input = "[\"\\\"]",
	},
	{
		// n_string_incomplete_surrogate_escape_invalid.json
		.input = "[\"\\uD800\\uD800\\x\"]",
	},
	{
		// n_string_incomplete_surrogate.json
		.input = "[\"\\uD834\\uDd\"]",
	},
	{
		// n_string_invalid_backslash_esc.json
		.input = "[\"\\a\"]",
	},
	{
		// n_string_invalid_unicode_escape.json
		.input = "[\"\\uqqqq\"]",
	},
	{
		// n_string_invalid_utf8_after_escape.json
		.input = "[\"\\\xe5\"]",
	},
	{
		// n_string_invalid-utf-8-in-escape.json
		.input = "[\"\\u\xe5\"]",
	},
	{
		// n_string_leading_uescaped_thinspace.json
		.input = "[\\u0020\"asd\"]",
	},
	{
		// n_string_no_quotes_with_bad_escape.json
		.input = "[\\n]",
	},
	{
		// n_string_single_doublequote.json
		.input = "\"",
	},
	{
		// n_string_single_quote.json
		.input = "['single quote']",
	},
	{
		// n_string_single_string_no_double_quotes.json
		.input = "abc",
	},
	{
		// n_string_start_escape_unclosed.json
		.input = "[\"\\",
	},
	{
		// n_string_unescaped_ctrl_char.json
		.input = "[\"a\x00a\"]",
	},
	{
		// n_string_unescaped_newline.json
		.input = "[\"new\n"
			 "line\"]",
	},
	{
		// n_string_unescaped_tab.json
		.input = "[\"\t\"]",
	},
	{
		// n_string_unicode_CapitalU.json
		.input = "\"\\UA66D\"",
	},
	{
		// n_string_with_trailing_garbage.json
		.input = "\"\"x",
	},
	{
		// n_structure_angle_bracket_..json
		.input = "<.>",
	},
	{
		// n_structure_angle_bracket_null.json
		.input = "[<null>]",
	},
	{
		// n_structure_array_trailing_garbage.json
		.input = "[1]x",
	},
	{
		// n_structure_array_with_extra_array_close.json
		.input = "[1]]",
	},
	{
		// n_structure_array_with_unclosed_string.json
		.input = "[\"asd]",
	},
	{
		// n_structure_ascii-unicode-identifier.json
		.input = "a\xc3\xa5",
	},
	{
		// n_structure_capitalized_True.json
		.input = "[True]",
	},
	{
		// n_structure_close_unopened_array.json
		.input = "1]",
	},
	{
		// n_structure_comma_instead_of_closing_brace.json
		.input = "{\"x\": true,",
	},
	{
		// n_structure_double_array.json
		.input = "[][]",
	},
	{
		// n_structure_end_array.json
		.input = "]",
	},
	{
		// n_structure_incomplete_UTF8_BOM.json
		.input = "\xef\xbb{}",
	},
	{
		// n_structure_lone-invalid-utf-8.json
		.input = "\xe5",
	},
	{
		// n_structure_lone-open-bracket.json
		.input = "[",
	},
	{
		// n_structure_no_data.json
		.input = "",
	},
	{
		// n_structure_null-byte-outside-string.json
		.input = "[\x00]",
	},
	{
		// n_structure_number_with_trailing_garbage.json
		.input = "2@",
	},
	{
		// n_structure_object_followed_by_closing_object.json
		.input = "{}}",
	},
	{
		// n_structure_object_unclosed_no_value.json
		.input = "{\"\":",
	},
	{
		// n_structure_object_with_comment.json
		.input = "{\"a\":/*comment*/\"b\"}",
	},
	{
		// n_structure_object_with_trailing_garbage.json
		.input = "{\"a\": true} \"x\"",
	},
	{
		// n_structure_open_array_apostrophe.json
		.input = "['",
	},
	{
		// n_structure_open_array_comma.json
		.input = "[,",
	},
	{
		// n_structure_open_array_open_object.json
		.input = "[{",
	},
	{
		// n_structure_open_array_open_string.json
		.input = "[\"a",
	},
	{
		// n_structure_open_array_string.json
		.input = "[\"a\"",
	},
	{
		// n_structure_open_object_close_array.json
		.input = "{]",
	},
	{
		// n_structure_open_object_comma.json
		.input = "{,",
	},
	{
		// n_structure_open_object.json
		.input = "{",
	},
	{
		// n_structure_open_object_open_array.json
		.input = "{[",
	},
	{
		// n_structure_open_object_open_string.json
		.input = "{\"a",
	},
	{
		// n_structure_open_object_string_with_apostrophes.json
		.input = "{'a'",
	},
	{
		// n_structure_open_open.json
		.input = "[\"\\{[\"\\{[\"\\{[\"\\{",
	},
	{
		// n_structure_single_eacute.json
		.input = "\xe9",
	},
	{
		// n_structure_single_star.json
		.input = "*",
	},
	{
		// n_structure_trailing_#.json
		.input = "{\"a\":\"b\"}#{}",
	},
	{
		// n_structure_U+2060_word_joined.json
		.input = "[\xe2\x81\xa0]",
	},
	{
		// n_structure_uescaped_LF_before_string.json
		.input = "[\\u000A\"\"]",
	},
	{
		// n_structure_unclosed_array.json
		.input = "[1",
	},
	{
		// n_structure_unclosed_array_partial_null.json
		.input = "[ false, nul",
	},
	{
		// n_structure_unclosed_array_unfinished_false.json
		.input = "[ true, fals",
	},
	{
		// n_structure_unclosed_array_unfinished_true.json
		.input = "[ false, tru",
	},
	{
		// n_structure_unclosed_object.json
		.input = "{\"asd\":\"asd\"",
	},
	{
		// n_structure_unicode-identifier.json
		.input = "\xc3\xa5",
	},
	{
		// n_structure_UTF8_BOM_no_data.json
		.input = "\xef\xbb\xbf",
	},
	{
		// n_structure_whitespace_formfeed.json
		.input = "[\f]",
	},
	{
		// n_structure_whitespace_U+2060_word_joiner.json
		.input = "[\xe2\x81\xa0]",
	},
	{
		// i_number_huge_exp.json
		.input = "[0.4e0066999999999999999999999999999999999"
			 "99999999999999999999999999999999999999999999999"
			 "99999999999999999999999999999999999969999999006]",
	},
	{
		// i_number_neg_int_huge_exp.json
		.input = "[-1e+9999]",
	},
	{
		// i_number_pos_double_huge_exp.json
		.input = "[1.5e+9999]",
	},
	{
		// i_number_real_neg_overflow.json
		.input = "[-123123e100000]",
	},
	{
		// i_number_real_pos_overflow.json
		.input = "[123123e100000]",
#if 0 // FIXME: check once float is implemented
	},
	{
		// i_number_real_underflow.json
		.input = "[123e-10000000]",
#endif
	},
	{
		// i_number_too_big_neg_int.json
		.input = "[-123123123123123123123123123123]",
	},
	{
		// i_number_too_big_pos_int.json
		.input = "[100000000000000000000]",
	},
	{
		// i_number_very_big_negative_int.json
		.input = "[-237462374673276894279832749832423479823246327846]",
	},
	{
		// i_object_key_lone_2nd_surrogate.json
		.input = "{\"\\uDFAA\":0}",
	},
	{
		// i_string_1st_surrogate_but_2nd_missing.json
		.input = "[\"\\uDADA\"]",
	},
	{
		// i_string_1st_valid_surrogate_2nd_invalid.json
		.input = "[\"\\uD888\\u1234\"]",
	},
	{
		// i_string_incomplete_surrogate_and_escape_valid.json
		.input = "[\"\\uD800\\n\"]",
	},
	{
		// i_string_incomplete_surrogate_pair.json
		.input = "[\"\\uDd1ea\"]",
	},
	{
		// i_string_incomplete_surrogates_escape_valid.json
		.input = "[\"\\uD800\\uD800\\n\"]",
	},
	{
		// i_string_invalid_lonely_surrogate.json
		.input = "[\"\\ud800\"]",
	},
	{
		// i_string_invalid_surrogate.json
		.input = "[\"\\ud800abc\"]",
	},
	{
		// i_string_invalid_utf-8.json
		.input = "[\"\xff\"]",
	},
	{
		// i_string_inverted_surrogates_U+1D11E.json
		.input = "[\"\\uDd1e\\uD834\"]",
	},
	{
		// i_string_iso_latin_1.json
		.input = "[\"\xe9\"]",
	},
	{
		// i_string_lone_second_surrogate.json
		.input = "[\"\\uDFAA\"]",
	},
	{
		// i_string_lone_utf8_continuation_byte.json
		.input = "[\"\x81\"]",
	},
	{
		// i_string_not_in_unicode_range.json
		.input = "[\"\xf4\xbf\xbf\xbf\"]",
	},
	{
		// i_string_overlong_sequence_2_bytes.json
		.input = "[\"\xc0\xaf\"]",
	},
	{
		// i_string_overlong_sequence_6_bytes.json
		.input = "[\"\xfc\x83\xbf\xbf\xbf\xbf\"]",
	},
	{
		// i_string_overlong_sequence_6_bytes_null.json
		.input = "[\"\xfc\x80\x80\x80\x80\x80\"]",
	},
	{
		// i_string_truncated-utf-8.json
		.input = "[\"\xe0\xff\"]",
	},
	{
		// i_string_utf16BE_no_BOM.json
		.input = "\x00[\x00\"\x00\xe9\x00\"\x00]",
		.input_len = 10
	},
	{
		// i_string_utf16LE_no_BOM.json
		.input = "[\x00\"\x00\xe9\x00\"\x00]\x00",
		.input_len = 10
	},
	{
		// i_string_UTF-16LE_with_BOM.json
		.input = "\xff\xfe[\x00\"\x00\xe9\x00\"\x00]\x00",
		.input_len = 12
	},
	{
		// i_string_UTF-8_invalid_sequence.json
		.input = "[\"\xe6\x97\xa5\xd1\x88\xfa\"]",
	},
	{
		// i_string_UTF8_surrogate_U+D800.json
		.input = "[\"\xed\xa0\x80\"]",
	},
	{
		// i_structure_UTF-8_BOM_empty_object.json
		.input = "\xef\xbb\xbf{}",
	},
	/* From json.org */
	{
		.input = "[\"Unclosed array\"",
	},
	{
		.input = "{unquoted_key: \"keys must be quoted\"}",
	},
	{
		.input = "[\"extra comma\",]",
	},
	{
		.input = "[\"double extra comma\",,]",
	},
	{
		.input = "[   , \"<-- missing value\"]",
	},
	{
		.input = "[\"Comma after the close\"],",
	},
	{
		.input = "[\"Extra close\"]]",
	},
	{
		.input = "{\"Extra comma\": true,}",
	},
	{
		.input = "{\"Extra value after close\": true} \"misplaced quoted value\"",
	},
	{
		.input = "{\"Illegal expression\": 1 + 2}",
	},
	{
		.input = "{\"Illegal invocation\": alert()}",
	},
	{
		.input = "{\"Numbers cannot have leading zeroes\": 013}",
	},
	{
		.input = "{\"Numbers cannot be hex\": 0x14}",
	},
	{
		.input = "[\"Illegal backslash escape: \\x15\"]",
	},
	{
		.input = "[\\naked]",
	},
	{
		.input = "[\"Illegal backslash escape: \\017\"]",
	},
	{
		.input = "{\"Missing colon\" null}",
	},
	{
		.input = "{\"Double colon\":: null}",
	},
	{
		.input = "{\"Comma instead of colon\", null}",
	},
	{
		.input = "[\"Colon instead of comma\": false]",
	},
	{
		.input = "[\"Bad value\", truth]",
	},
	{
		.input = "['single quote']",
	},
	{
		.input = "[\"\ttab\tcharacter\tin\tstring\t\"]",
	},
	{
		.input = "[\"tab\\   character\\   in\\  string\\  \"]",
	},
	{
		.input = "[\"line\n"
			 "break\"]",
	},
	{
		.input = "[\"line\\\n"
			 "break\"]",
	},
	{
		.input = "[0e]",
	},
	{
		.input = "[0e+]",
	},
	{
		.input = "[0e+-1]",
	},
	{
		.input = "{\"Comma instead if closing brace\": true,",
	},
	{
		.input = "[\"mismatch\"}",
	},
	/* Test cases from Jansson project (http://www.digip.org/jansson/)
	   Copyright (c) 2009-2020 Petri Lehtinen
	   MIT License (see COPYING.MIT)
	 */
	{
		// invalid/ascii-unicode-identifier/input
		.input = "a\xc3\xa5\n",
	},
	{
		// invalid/brace-comma/input
		.input = "{,\n",
	},
	{
		// invalid/extra-comma-in-multiline-array/input
		.input = "[1,\n"
			"2,\n"
			"3,\n"
			"4,\n"
			"5,\n"
			"]\n",
	},
	{
		// invalid/recursion-depth/input
		.input =
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[", // ...
	},
	{
		// invalid/real-truncated-at-e/input
		.input = "[1e]\n",
	},
	{
		// invalid/object-in-unterminated-array/input
		.input = "[{}\n",
	},
	{
		// invalid/too-big-negative-integer/input
		.input = "[-123123123123123123123123123123]\n",
	},
	{
		// invalid/unterminated-string/input
		.input = "[\"a\n",
	},
	{
		// invalid/unterminated-object-and-array/input
		.input = "{[\n",
	},
	{
		// invalid/invalid-negative-integer/input
		.input = "[-123foo]\n",
	},
	{
		// invalid/minus-sign-without-number/input
		.input = "[-foo]\n",
	},
	{
		// invalid/invalid-second-surrogate/input
		.input = "[\"\\uD888\\u3210 "
			 "(first surrogate and invalid second surrogate)\"]\n",
	},
	{
		// invalid/object-unterminated-value/input
		.input = "{\"a\":\"a\n",
	},
	{
		// invalid/null-byte-outside-string/input
		.input = "[\x00\n",
	},
	{
		// invalid/extra-comma-in-array/input
		.input = "[1,]\n",
	},
	{
		// invalid/garbage-after-newline/input
		.input = "[1,2,3]\n"
			 "foo\n",
	},
	{
		// invalid/real-negative-overflow/input
		.input = "[-123123e100000]\n",
	},
	{
		// invalid/real-truncated-at-point/input
		.input = "[1.]\n",
	},
	{
		// invalid/invalid-unicode-escape/input
		.input = "[\"\\uqqqq <-- invalid unicode escape\"]\n",
	},
	{
		// invalid/object-apostrophes/input
		.input = "{'a'\n",
	},
	{
		// invalid/lone-open-brace/input
		.input = "{\n",
	},
	{
		// invalid/truncated-unicode-surrogate/input
		.input = "[\"\\uDADA (first surrogate without the second)\"]\n",
	},
	{
		// invalid/bracket-comma/input
		.input = "[,\n",
	},
	{
		// invalid/real-garbage-after-e/input
		.input = "[1ea]\n",
	},
	{
		// invalid/empty/input
		.input = "",
	},
	{
		// invalid/garbage-at-the-end/input
		.input = "[1,2,3]foo\n",
	},
	{
		// invalid/object-no-colon/input
		.input = "{\"a\"\n",
	},
	{
		// invalid/object-no-value/input
		.input = "{\"a\":\n",
	},
	{
		// invalid/integer-starting-with-zero/input
		.input = "[012]\n",
	},
	{
		// invalid/unterminated-empty-key/input
		.input = "{\"\n",
	},
	{
		// invalid/invalid-escape/input
		.input = "[\"\\a <-- invalid escape\"]\n",
	},
	{
		// invalid/lone-open-bracket/input
		.input = "[\n",
	},
	{
		// invalid/unterminated-array-and-object/input
		.input = "[{\n",
	},
	{
		// invalid/invalid-identifier/input
		.input = "[troo\n",
	},
	{
		// invalid/too-big-positive-integer/input
		.input = "[123123123123123123123123123123]\n",
	},
	{
		// invalid/unicode-identifier/input
		.input = "\xc3\xa5\n",
	},
	{
		// invalid/null-escape-in-string/input
		.input = "[\"null escape \\u0000 not allowed\"]\n",
	},
	{
		// invalid/bracket-one-comma/input
		.input = "[1,\n",
	},
	{
		// invalid/unterminated-key/input
		.input = "{\"a\n",
	},
	{
		// invalid/apostrophe/input
		.input = "['\n",
	},
	{
		// invalid/invalid-negative-real/input
		.input = "[-123.123foo]\n",
	},
	{
		// invalid/null-byte-in-string/input
		.input = "[\"null byte \x00 not allowed\"]\n",
	},
	{
		// invalid/null-byte-in-object-key/input
		.input = "{\"foo\\u0000bar\": 42}",
	},
	{
		// invalid/real-positive-overflow/input
		.input = "[123123e100000]\n",
	},
	{
		// invalid/lone-second-surrogate/input
		.input = "[\"\\uDFAA (second surrogate on it's own)\"]\n",
	},
	{
		// invalid/negative-integer-starting-with-zero/input
		.input = "[-012]\n",
	},
	{
		// invalid/tab-character-in-string/input
		.input = "[\"\t <-- tab character\"]\n",
	},
	{
		// invalid/object-garbage-at-end/input
		.input = "{\"a\":\"a\" 123}\n",
	},
	{
		// invalid/unterminated-array/input
		.input = "[\"a\"\n",
	},
	{
		// invalid-unicode/restricted-utf-8/input
		.input = "[\"\xfd\"]\n",
	},
	{
		// invalid-unicode/encoded-surrogate-half/input
		.input = "[\"\xed\xa2\xab <-- encoded surrogate half\"]\n",
	},
	{
		// invalid-unicode/overlong-3-byte-encoding/input
		.input = "[\"\xe0\x80\xa2 <-- overlong encoding\"]\n",
	},
	{
		// invalid-unicode/invalid-utf-8-in-identifier/input
		.input = "[a\xe5]\n",
	},
	{
		// invalid-unicode/lone-invalid-utf-8/input
		.input = "\xe5\n",
	},
	{
		// invalid-unicode/invalid-utf-8-in-string/input
		.input = "[\"\xe5 <-- invalid UTF-8\"]\n",
	},
	{
		// invalid-unicode/invalid-utf-8-in-real-after-e/input
		.input = "[1e\xe5]\n",
	},
	{
		// invalid-unicode/truncated-utf-8/input
		.input = "[\"\xe0\xff <-- truncated UTF-8\"]\n",
	},
	{
		// invalid-unicode/invalid-utf-8-after-backslash/input
		.input = "[\"\\\xe5\"]\n",
	},
	{
		// invalid-unicode/overlong-ascii-encoding/input
		.input = "[\"\xc1\"]\n",
	},
	{
		// invalid-unicode/invalid-utf-8-in-escape/input
		.input = "[\"\\u\xe5\"]\n",
	},
	{
		// invalid-unicode/overlong-4-byte-encoding/input
		.input = "[\"\xf0\x80\x80\xa2 <-- overlong encoding\"]\n",
	},
	{
		// invalid-unicode/invalid-utf-8-in-exponent/input
		.input = "[1e1\xe5]\n",
	},
	{
		// invalid-unicode/lone-utf-8-continuation-byte/input
		.input = "[\"\x81\"]\n",
	},
	{
		// invalid-unicode/invalid-utf-8-in-int/input
		.input = "[0\xe5]\n",
	},
	{
		// invalid-unicode/invalid-utf-8-in-array/input
		.input = "[\xe5]\n",
	},
	{
		// invalid-unicode/not-in-unicode-range/input
		.input = "[\"\xf4\xbf\xbf\xbf\"]\n",
	},
	{
		// invalid-unicode/invalid-utf-8-in-bigger-int/input
		.input = "[123\xe5]\n",
	},
	/* Original Dovecot json-parser tests */
	{
		.input = "{",
	},
	{
		.input = "{:}",
	},
	{
		.input = "{\"foo\":}",
	},
	{
		.input = "{\"foo\" []}",
	},
	{
		.input = "{\"foo\": [1}",
	},
	{
		.input = "{\"foo\": [1,]}",
	},
	{
		.input = "{\"foo\": 1,}",
	},
	{
		.input = "{\"foo\": 1.}}",
	},
	{
		.input = "{\"foo\": 1},{}",
	},
	{
		.input = "{\"foo\": \"\\ud808\"}",
	},
	{
		.input = "{\"foo\": \"\\udfff\"}",
	},
	{
		.input = "{\"foo\": \"\\uyyyy\"}",
	},
	{
		.input = "{\"a\":\"",
	},
	{
		.input = "{\"a\":nul",
	},
	{
		.input = "{\"a\":fals",
	},
	{
		.input = "{\"a\":tru",
	},
	/* Limits */
	{
		.input =
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
		.limits = { .max_nesting = 31 },
	},
	{
		.input =
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
			"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]",
		.limits = { .max_nesting = 104 },
	},
	{
		.input =
			"[1,2,3,4,5,6,7,8,9,0,\n"
			" 1,2,3,4,5,6,7,8,9,0,\n"
			" 1,2,3,4,5,6,7,8,9,0,\n"
			" 1,2,3,4,5,6,7,8,9,0,\n"
			" 1,2,3,4,5,6,7,8,9,0]\n",
		.limits = { .max_list_items = 49 },
	},
	{
		.input =
			"\"123456789012345678901234567890"
			"123456789012345678901234567890"
			"123456789012345678901234567890\"",
		.limits = { .max_string_size = 89 },
	},
	{
		.input =
			"123456789012345678901234567890"
			"123456789012345678901234567890"
			"123456789012345678901234567890",
		.flags = JSON_PARSER_FLAG_NUMBERS_AS_STRING,
		.limits = { .max_string_size = 89 },
	},
	{
		.input =
			"{\"123456789012345678901234567890"
			"123456789012345678901234567890"
			"123456789012345678901234567890\": 90}",
		.limits = { .max_name_size = 89 },
	},
	/* Additional tests */
	{
		.input = "\"\\xFF\\xFF\\xFF\"",

	},
	/* Problems found by fuzzer */
	{
		.input = "ICJ9XHU10QAAAPxlXQ==",
		.flags = JSON_PARSER_FLAG_STRICT,
		.base64 = TRUE,
	},
	{
		.input = "IiBcdTBEMNk=",
		.flags = JSON_PARSER_FLAG_STRICT,
		.base64 = TRUE,
	},
	{
		.input =
			"Ilx1ZDgzZFx1ZGUzOVswLDMuNDZFMiw1ZTUsMCwzLDVlNSwzLjIs"
			"Mjc4My42RTIsNWU1LDMuMjc4NUUwLDM2RTIsNSwzLjIsMiwyODUs"
			"MzUsMy40NiwzLjQ2RTIsNWU1LDAsMy40NjYsMCwzLjQ2RTIsMy40"
			"Miw1ZTUsMy4yLDI3ODVFMCwzLjQ4LDMuNDZFMCwzLjQ2RTIsNWU1"
			"LDMuMjg1RTAsMy40ODVFMCwzLjQ2RTIsNWU1LDAsMy40Niw1ZTYs"
			"My4wLDMuNkUyLDVlNSwzLjI3ODVFMCwzLjQ2LDAsMy41LDMuMiwy"
			"Nzg1RTAsMy40NkUyLDVlNSwyLDUzLjI3ODVFMCwzLjYsMCwzLjUs"
			"MCwzLjQsNTI1LDMuMjc4NUUwLDMuNDIsNWU1LDMuNCwzLjQ2NDZF"
			"Miw1ZTUsMy41LDIsNWU1LDMuNDIsNWU1LDMuMiwyNzg1RTAsMy40"
			"OCwzLjQ2RTAsMy40NkUyLDVlNSwzLjIsMjc4NUUwLDMuNDg1RTAs"
			"My40NkUyLDVlNSwwLDMuNDYsNWU2LDMuMCwzLjZFMiw1ZTUsMy4y"
			"Nzg1RTAsMy40NiwwLDMuNSwzLjIsMjc4NUUwLDMuNDZFMiw1ZTUs"
			"Miw1My4yNzg1RTAsMy42LDAsMy41LDAsMy40LDUyNSwzLjI3ODVF"
			"MCwzLjQ2RTIsNWU2LDVlNSwwLDMuNDY2LDAsMy40NkUxLDVlNSwz"
			"LjUsMiw1ZTUsMy40Miw1ZTUsMy4yLDI3ODVFMCwzLjQ4LDMuNDZF"
			"MCwzLjQ2RTIsNWU1LDMuMiwyNzg1RTAsMy40ODVFMCwzLjQ2RTIs"
			"NWU1LDAsMy40Niw1ZTYsMy4wLDMuNkUyLDVlNSwzLjI3ODVFMCwz"
			"LjQ2LDAsMy41LDMuMiwyNzg1RTAsMy40NkUyLDVlNSwyLDUzLjI3"
			"ODVFMCwzLjYsMCwzLjUsMCwzLjQsNTI1LDMuMjc4NUUwLDMuNDZF"
			"Miw1ZTYsMCwzLjU1NjgsMy40MCwzLjQ2RTIsNWU1LDMuNDYsMCwz"
			"LjQ2RTIsNTMuNDZFMiwyNWU1LDUzLjI3ODVFMCwzLjYsMCwzLjUs"
			"MCwzLjQsNTI1LDMuMjc4NUUwLDMuNDZFMiw1ZTYsMCwzRTIsNTU2"
			"OCwzLjIsNWU1LDMuNSwyLDVlNSwzLjQyLDVlNSwzLjIsMjc4NUUw"
			"LDMuMiwyNzg1RTAsMy40OCwzLjQ1RTAsMy4yLDI3ODVFMCw4LjQz"
			"NUU1LDVlNSwwLDMuMjUsMy40NjQsMy40NjIsNTMuMjc4NUUwLDMu"
			"NDZFMiwzNUUwMCwzLjQ2NiwwLDNlNSwzLjIsNiwwLDMuNDZFMiw1"
			"ZTUsMy41LDIsNWU1XHVkODNkXHVkY2U5XHVkODNkXHVkZTM5XHVk"
			"ODNkXHVkYzhkXHVkODNkXHVkZTM5XHVkODNkXHVkYzZlOVx1ZDgz"
			"ZFx1ZGUzOFx1ZDgzZFx1ZGMzZFx1ZDgzZFx1ZGUzOVx1ZDgzZFx1"
			"ZGM2ZTkMdWQ4M2RcdWRlMzlcdWQ4M2RcdWRjOGRcdWQ4M2RcdWRl"
			"MzlcdWQ4M2RcdWRlMzlcdWQ4M2RcdWRjNmU5XHVkODNkXHVkZTM5"
			"XHVkODNkXHVkYzhkXHVkODNkXHVkZTM5XHVkODNkXHVkYzY5XHVk"
			"ODNkJXVkZTM4XHVkODNkXHVkYzZkXHVkLDMuNDIsNWU1LDMuMiw4"
			"RTcsNTIwMy40OCwzLjQ2RTAsMy40NkUyLDVlNSwzLjIsMjc4NUUw"
			"LDMuNDg1RTAsMy40NkUyLDVlNSwwLDMuNDYsNWU2LDMuMCwzLjZF"
			"Miw1ZTUsMy4yNzg1RTAsMy40NiwwLDMuNSwzLjIsMjc4NUUwLDMu"
			"NDZFMiw1ZTUsMiw1My4yNzg1RTAsMy42LDAsMy41LDAsMy40LDUy"
			"NSwzLjI3ODVFMCwzLjQ2RTIsNWU2LDAsMzZFMiw1NTY4LDMuNDAs"
			"My40NkUyLDVlNSwzLjQ2LDAsMy40NkUyLDUzLjQ0ODVFMCwzLjQ2"
			"RTIsNWU1ODNkXHVkLDAsMy40Niw1ZTYsMy4wLDMuNkUyLDVlNSwz"
			"LjI3ODVFMCwzLjQ2LDAsMy41LDMuMiwyNzg1RTAsMy40NkUyLDVl"
			"NSwyLDUzLjI3ODVFMCwzLjYsMCwzLjUsMCwzLjQsNTI1LDMzLjQ2"
			"MiwyLDI4NSwzNSwzLjQ2RTIsNWU1LDMuNCwzLjQ2RTIsMjc4NGUz"
			"OVx1ZDgzZFx1ZGM2ZTlcdWQ4M2SuipuazMajimQ4M2RcdWRjOGRc"
			"dWQ4M2RcdWRlMzlcdWQ4M2RcdWRjNmVcdWQ4M2RcdTZFMiwyNjYs"
			"MCwzLjQ2NSwzLjQyLDVlNWRlMzhcdWQ4M2RcdWRjM2RcdWQ4M2Rc"
			"dWRjNmU5XHVkODNkXHVkZTMsMy4yLDI3ODVFMCwzLjIsMjc4NUUw"
			"LDMuNDgsMy40NUUwLDMuMiwyNzg1RTAsOC40MzVFNSw1ZTUsMCwz"
			"LjIsMy40LDMuNDYyLDUzOFwuMjc4NUV1ZDgzZFx1MCwzLjQ2RTIs"
			"MzVFMCwzLjQ2RTIsNWU1LDI1RTAsMy42RTIsNWVkNSwzLmMyMzc4"
			"ZCgy",
		.flags = JSON_PARSER_FLAG_STRICT,
		.limits = {
			.max_name_size = 1024U,
			.max_string_size = 1024U,
			.max_nesting = 10U,
			.max_list_items = JSON_DEFAULT_MAX_LIST_ITEMS,
		},
		.base64 = TRUE,
	},
};

static const unsigned int invalid_parse_test_count =
	N_ELEMENTS(invalid_parse_tests);

static void test_json_parse_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_parse_test_count; i++) T_BEGIN {
		const struct json_invalid_parse_test *test;
		struct istream *input;
		struct json_parser *parser;
		const char *text, *error = NULL;
		unsigned int pos, text_len;
		int ret = 0;

		test = &invalid_parse_tests[i];

		text = test->input;
		text_len = test->input_len;
		if (text_len == 0)
			text_len = strlen(text);
		input = test_istream_create_data(text, text_len);
		if (test->base64) {
			struct istream *inputb64 =
				i_stream_create_base64_decoder(input);
			i_stream_unref(&input);
			input = inputb64;
		}

		test_begin(t_strdup_printf("json text invalid [%d]", i));

		parser = json_parser_init(input,
			&test->limits, test->flags, NULL, NULL);

		for (pos = 0; pos <= text_len && ret == 0; pos++) {
			test_istream_set_size(input, pos);
			ret = json_parse_more(parser, &error);
			if (ret < 0)
				break;
			if (ret > 0) {
				if (debug)
					i_debug("DATA: `%s'", text);
			}
		}
		test_out_reason_quiet("parse failure (trickle)",
				      ret < 0, error);

		json_parser_deinit(&parser);

		i_stream_seek(input, 0);
		parser = json_parser_init(input,
			&test->limits, test->flags, NULL, NULL);

		test_istream_set_size(input, text_len);
		ret = json_parse_more(parser, &error);
		if (ret > 0) {
			if (debug)
				i_debug("DATA: `%s'", text);
		}
		test_out_reason_quiet("parse failure (buffered)",
				      ret < 0, error);
		json_parser_deinit(&parser);

		test_end();

		i_stream_unref(&input);
	} T_END;
}

/*
 * Test: stream parse tests
 */

struct json_stream_parse_test {
	const char *input, *output;
	struct json_limits limits;
	enum json_parser_flags flags;
};

static const struct json_stream_parse_test
stream_parse_tests[] = {
	{
		.input = "\"AABBCC\"",
		.output = "AABBCC"
	},{
		.input = "\""
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"\"",
		.output =
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
	},{
		.input = "[\""
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"\"]",
		.output =
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
	},{
		.input = "  [ \""
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"\" ]  ",
		.output =
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
			"AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
	},{
		.input = "\"foo\\\\\\\"\\b\\f\\n\\r\\t\\u0001\\uffff\"",
		.output = "foo\\\"\b\f\n\r\t\001\xEF\xBF\xBF"
	},{
		.input = "\"\\ud801\\udc37\"",
		.output = "\xf0\x90\x90\xb7"
	},{
		.input = "\"\"",
		.output = ""
	}
};

static const unsigned int stream_parse_test_count =
	N_ELEMENTS(stream_parse_tests);

static void
test_parse_stream_parse_value(void *context,
	void *parent_context ATTR_UNUSED,
	const char *name ATTR_UNUSED, enum json_type type,
	const struct json_value *value)
{
	struct istream **str_stream_r = (struct istream **)context;

	test_assert(type == JSON_TYPE_STRING);
	test_assert(value->content_type == JSON_CONTENT_TYPE_STREAM);
	*str_stream_r = value->content.stream;
	i_stream_ref(value->content.stream);
}

static struct json_parser_callbacks parse_stream_callbacks = {
	.parse_value = test_parse_stream_parse_value
};

static void test_json_parse_stream(void)
{
	static const unsigned int trickle_steps[] = {1,2,3,4,5,10,20};
	string_t *buffer;
	unsigned int i, j;

	buffer = str_new(default_pool, 256);

	for (i = 0; i < stream_parse_test_count; i++) T_BEGIN {
		const struct json_stream_parse_test *test;
		struct istream *input, *str_input;
		struct json_parser *parser;
		const char *text, *error = NULL;
		unsigned int pos, text_len;
		int ret = 0;

		test = &stream_parse_tests[i];

		text = test->input;
		text_len = strlen(text);

		input = test_istream_create_data(text, text_len);

		test_begin(t_strdup_printf("json parse stream [%u]", i));

		/* trickle tests */
		for (j = 0; j < N_ELEMENTS(trickle_steps); j++) {
			unsigned int trickle_step = trickle_steps[j];

			i_stream_seek(input, 0);
			str_input = NULL;
			str_truncate(buffer, 0);

			parser = json_parser_init(input,
				NULL, 0, &parse_stream_callbacks, &str_input);
			json_parser_enable_string_stream(parser, 0, 10);

			ret = 0;
			for (pos = 0; pos <= text_len+1000 && ret == 0; pos += trickle_step) {
				test_istream_set_size(input, pos);
				if (str_input == NULL) {
					ret = json_parse_more(parser, &error);
					if (ret < 0)
						break;
				}
				if (str_input != NULL) {
					const unsigned char *data;
					size_t size;

					while ((ret = i_stream_read_more(str_input,
									 &data, &size)) > 0) {
						buffer_append(buffer, data, size);
						i_stream_skip(str_input, size);
					}
					if (ret < 0) {
						i_assert(!i_stream_have_bytes_left(str_input));
						i_stream_skip(str_input, size);
						i_stream_unref(&str_input);
						ret = 0;
					}
				}
			}
			test_out_reason_quiet(
				t_strdup_printf("parse success "
						"(trickle, step=%u)",
						trickle_step),
				ret > 0, error);
			test_out_quiet("stream output",
				       strcmp(str_c(buffer),
					      test->output) == 0);
			json_parser_deinit(&parser);
		}

		/* buffered test */
		i_stream_seek(input, 0);
		str_truncate(buffer, 0);

		parser = json_parser_init(input,
			NULL, 0, &parse_stream_callbacks, &str_input);
		json_parser_enable_string_stream(parser, 0, 10);

		test_istream_set_size(input, text_len);
		ret = json_parse_more(parser, &error);
		test_out_reason_quiet("parse success (buffered) #1",
				      ret == 0, error);
		if (ret == 0 && str_input != NULL) {
			const unsigned char *data;
			size_t size;

			while ((ret = i_stream_read_more(str_input,
							 &data, &size)) > 0) {
				buffer_append(buffer, data, size);
				i_stream_skip(str_input, size);
			}
			i_assert (ret != 0);
			if (ret < 0) {
				i_assert(!i_stream_have_bytes_left(str_input));
				i_stream_skip(str_input, size);
				i_stream_unref(&str_input);
				ret = 0;
			}
		}
		if (ret == 0) {
			ret = json_parse_more(parser, &error);
			test_out_reason_quiet("parse success (buffered) #2",
					      ret > 0, error);
		}
		test_out_quiet("stream output",
			       strcmp(str_c(buffer), test->output) == 0);
		json_parser_deinit(&parser);

		test_end();

		i_stream_unref(&input);
	} T_END;

	str_free(&buffer);
}

/*
 * Test: stream parse error tests
 */

struct json_stream_parse_error_test {
	const char *input;
	struct json_limits limits;
	enum json_parser_flags flags;
	int stream_errno;
};

static const struct json_stream_parse_error_test
stream_parse_error_tests[] = {
	/* invalid escape */
	{
		.input = "\"foo\\?\"",
		.stream_errno = EINVAL,
	/* just a DQUOTE */
	},{
		.input = "\"",
		.stream_errno = EPIPE,
	/* unterminated string, escaped DQUOTE */
	},{
		.input = "\"\\\"",
		.stream_errno = EPIPE,
	/* unterminated string */
	},{
		.input = "\"foo",
		.stream_errno = EPIPE,
	/* high surrogate alone, unterminated string */
	},{
		.input = "\"\\ud801",
		.stream_errno = EPIPE,
	/* high surrogate alone */
	},{
		.input = "\"\\ud801\"",
		.stream_errno = EINVAL,
	/* low surrogate before high */
	},{
		.input = "\"\\udced\\udc37\"",
		.stream_errno = EINVAL,
	/* has extra 1 in middle */
	},{
		.input = "\"\\ud8011\\udc37\"",
		.stream_errno = EINVAL,
	/* has extra TAB in middle */
	},{
		.input = "\"\\ud801\\t\\udc37\"",
		.stream_errno = EINVAL,
	/* low surrogate before high with valid prefix*/
	},{
		.input = "\"hello \\udc37\"",
		.stream_errno = EINVAL,
	/* high surrogate alone with valid prefix */
	},{
		.input = "\"hello \\ud801",
		.stream_errno = EPIPE,
	/* invalid hex value */
	},{
		.input = "\"\\uabcg",
		.stream_errno = EINVAL,
	/* invalid escape */
	},{
		.input = "\"\\xFF\\xFF\\xFF\"",
		.stream_errno = EINVAL,
	}
};

static const unsigned int stream_parse_error_test_count =
	N_ELEMENTS(stream_parse_error_tests);

static void
test_parse_stream_parse_error_value(void *context,
				    void *parent_context ATTR_UNUSED,
				    const char *name ATTR_UNUSED,
				    enum json_type type,
				    const struct json_value *value)
{
	struct istream **str_stream_r = (struct istream **)context;

	test_assert(type == JSON_TYPE_STRING);
	test_assert(value->content_type == JSON_CONTENT_TYPE_STREAM);
	*str_stream_r = value->content.stream;
	i_stream_ref(value->content.stream);
}

static struct json_parser_callbacks parse_stream_error_callbacks = {
	.parse_value = test_parse_stream_parse_error_value
};

static void test_json_parse_stream_error(void)
{
	static const unsigned int trickle_steps[] = {1,2,3,4,5,10,20};
	string_t *buffer;
	unsigned int i, j;

	buffer = str_new(default_pool, 256);

	for (i = 0; i < stream_parse_error_test_count; i++) T_BEGIN {
		const struct json_stream_parse_error_test *test;
		struct istream *input, *str_input;
		struct json_parser *parser;
		const char *text, *error = NULL;
		unsigned int pos, text_len;
		int ret = 0;

		test = &stream_parse_error_tests[i];

		text = test->input;
		text_len = strlen(text);

		input = test_istream_create_data(text, text_len);

		test_begin(t_strdup_printf("json parse stream error [%u]", i));

		/* trickle tests */
		for (j = 0; j < N_ELEMENTS(trickle_steps); j++) {
			unsigned int trickle_step = trickle_steps[j];

			i_stream_seek(input, 0);
			str_input = NULL;
			str_truncate(buffer, 0);

			parser = json_parser_init(input,
				NULL, 0, &parse_stream_error_callbacks, &str_input);
			json_parser_enable_string_stream(parser, 0, 10);

			ret = 0;
			for (pos = 0; pos <= text_len+1000 && ret == 0; pos += trickle_step) {
				test_istream_set_size(input, pos);
				if (str_input == NULL) {
					ret = json_parse_more(parser, &error);
					if (ret < 0)
						break;
				}
				if (str_input != NULL) {
					const unsigned char *data;
					size_t size;

					while ((ret = i_stream_read_more(str_input,
									 &data, &size)) > 0) {
						buffer_append(buffer, data, size);
						i_stream_skip(str_input, size);
					}
					if (ret < 0) {
						test_assert(str_input->stream_errno != 0);
						test_out_quiet("stream errno",
							       str_input->stream_errno == test->stream_errno);
						i_stream_skip(str_input, size);
						i_stream_unref(&str_input);
						ret = 0;
					}
				}
			}
			test_out_reason_quiet(
				t_strdup_printf("parse failure "
						"(trickle, step=%u)",
						trickle_step),
				ret < 0, error);
			json_parser_deinit(&parser);
		}

		/* buffered test */
		i_stream_seek(input, 0);
		str_truncate(buffer, 0);

		parser = json_parser_init(input,
			NULL, 0, &parse_stream_error_callbacks, &str_input);
		json_parser_enable_string_stream(parser, 0, 10);

		test_istream_set_size(input, text_len);
		ret = json_parse_more(parser, &error);
		test_out_reason_quiet("parse failure (buffered) #1",
				      ret <= 0, error);
		if (ret == 0 && str_input != NULL) {
			const unsigned char *data;
			size_t size;

			while ((ret = i_stream_read_more(str_input,
							 &data, &size)) > 0) {
				buffer_append(buffer, data, size);
				i_stream_skip(str_input, size);
			}
			i_assert (ret != 0);
			if (ret < 0) {
				test_assert(str_input->stream_errno != 0);
				test_out_quiet("stream errno",
					       str_input->stream_errno == test->stream_errno);
				i_stream_skip(str_input, size);
				i_stream_unref(&str_input);
				ret = 0;
			}
		}
		if (ret == 0) {
			ret = json_parse_more(parser, &error);
			test_out_reason_quiet("parse failure (buffered) #2",
					      ret < 0, error);
		}
		json_parser_deinit(&parser);

		test_end();

		i_stream_unref(&input);
	} T_END;

	str_free(&buffer);
}

int main(int argc, char *argv[])
{
	int c;

	static void (*test_functions[])(void) = {
		test_json_parse_valid,
		test_json_parse_invalid,
		test_json_parse_stream,
		test_json_parse_stream_error,
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
