/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "test-common.h"

static const char *const test_settings_blobs[] =
{
/* Blob 0 */
	"bool_true", "yes",
	"bool_false", "no",
	"uint", "15",
	"uint_oct", "0700",
	"secs", "5s",
	"msecs", "5ms",
	"size", "1k",
	"port", "2205",
	"str", "test string",
	"expand_str", "test %{string}",
	"strlist", "",
	"strlist/x", "a",
	"strlist/y", "b",
	"strlist/z", "c",
};

static const char *const test_settings_invalid[] =
{
	"bool_true", "",
	"bool_false", "x",
	"uint", "",
	"uint", "15M",
	"uint_oct", "",
	"uint_oct", "1M",
	"secs", "",
	"secs", "5G",
	"msecs", "",
	"msecs", "5G",
	"size", "1s",
	"port", "",
	"port", "1s",
};

static void test_settings_parser(void)
{
	struct test_settings {
		bool bool_true;
		bool bool_false;
		unsigned int uint;
		unsigned int uint_oct;
		unsigned int secs;
		unsigned int msecs;
		uoff_t size;
		in_port_t port;
		const char *str;
		const char *expand_str;
		ARRAY_TYPE(const_string) strlist;
	} test_defaults = {
		FALSE, /* for negation test */
		TRUE,
		0,
		0,
		0,
		0,
		0,
		0,
		"",
		"",
		ARRAY_INIT,
	};
	const struct setting_define defs[] = {
		SETTING_DEFINE_STRUCT_BOOL("bool_true", bool_true, struct test_settings),
		SETTING_DEFINE_STRUCT_BOOL("bool_false", bool_false, struct test_settings),
		SETTING_DEFINE_STRUCT_UINT("uint", uint, struct test_settings),
		{ .type = SET_UINT_OCT, .key = "uint_oct",
		  offsetof(struct test_settings, uint_oct), NULL },
		SETTING_DEFINE_STRUCT_TIME("secs", secs, struct test_settings),
		SETTING_DEFINE_STRUCT_TIME_MSECS("msecs", msecs, struct test_settings),
		SETTING_DEFINE_STRUCT_SIZE("size", size, struct test_settings),
		SETTING_DEFINE_STRUCT_IN_PORT("port", port, struct test_settings),
		SETTING_DEFINE_STRUCT_STR_NOVARS("str", str, struct test_settings),
		{ .type = SET_STR, .key = "expand_str",
		  offsetof(struct test_settings, expand_str), NULL },
		{ .type = SET_STRLIST, .key = "strlist",
		  offsetof(struct test_settings, strlist), NULL },
		SETTING_DEFINE_LIST_END
	};
	const struct setting_parser_info root = {
		.name = "test",
		.defines = defs,
		.defaults = &test_defaults,

		.struct_size = sizeof(struct test_settings),
	};

	test_begin("settings_parser");

	pool_t pool = pool_alloconly_create("settings parser", 1024);
	struct setting_parser_context *ctx =
		settings_parser_init(pool, &root, 0);
	int ret = 1;
	for (unsigned int i = 0; i < N_ELEMENTS(test_settings_blobs); i += 2) {
		ret = settings_parse_keyvalue(ctx, test_settings_blobs[i],
					      test_settings_blobs[i+1]);
		test_assert_idx(ret == 1, i);
	}
	if (ret < 0)
		i_error("settings_parse_keyvalue() failed: %s",
			settings_parser_get_error(ctx));
	test_assert(settings_parser_check(ctx, pool, NULL, NULL));

	/* check what we got */
	struct test_settings *settings = settings_parser_get_set(ctx);
	test_assert(settings != NULL);

	test_assert(settings->bool_true == TRUE);
	test_assert(settings->bool_false == FALSE);
	test_assert(settings->uint == 15);
	test_assert(settings->uint_oct == 0700);
	test_assert(settings->secs == 5);
	test_assert(settings->msecs == 5);
	test_assert(settings->size == 1024);
	test_assert(settings->port == 2205);
	test_assert_strcmp(settings->str, "test string");
	test_assert_strcmp(settings->expand_str, "test %{string}");

	test_assert(array_count(&settings->strlist) == 6);
	test_assert_strcmp(t_array_const_string_join(&settings->strlist, ";"),
			   "x;a;y;b;z;c");

	/* test invalid settings */
	for (unsigned int i = 0; i < N_ELEMENTS(test_settings_invalid); i += 2) {
		test_assert_idx(settings_parse_keyvalue(ctx,
			test_settings_invalid[i],
			test_settings_invalid[i+1]) < 0, i);
	}

	settings_parser_unref(&ctx);
	pool_unref(&pool);
	test_end();
}

static void test_settings_parse_boollist_string(void)
{
	const struct {
		const char *input;
		const char *const *output;
	} tests[] = {
		{ "", (const char *const *) { NULL } },
		{ "foo", (const char *const []) { "foo", NULL } },
		{ "foo bar", (const char *const []) { "foo", "bar", NULL } },
		{ "foo bar,baz", (const char *const []) { "foo", "bar", "baz", NULL } },
		{ ", foo, ,  b\\\\sa  ", (const char *const []) { "foo", "b\\sa", NULL } },
		{ ", a\\s\\e\\_\\+, ", (const char *const []) { "a/= ,", NULL } },

		{ "\"\"", (const char *const []) { "", NULL } },
		{ "\",.\"", (const char *const []) { ",.", NULL } },
		{ "\"esc\\\\\\\\str\"", (const char *const []) { "esc\\str", NULL } },
		{ "\"quotes\\\"str\"", (const char *const []) { "quotes\"str", NULL } },
		{ "\"val1\", \"val2\" \"val3\"", (const char *const []) { "val1", "val2", "val3", NULL } },
		{ "\"a\\\\s\\\\e\\\\_\\\\+\"", (const char *const []) { "a/= ,", NULL } },
	};
	const struct {
		const char *input;
		const char *error;
	} error_tests[] = {
		{ "\"", "Missing ending '\"'" },
		{ "\"foo\\", "Value ends with '\\'" },
		{ "x\"", "'\"' in the middle of a string" },
		{ "\"v1\"x", "Expected ',' or ' ' after '\"'" },
		{ "\"v1\"\"", "Expected ',' or ' ' after '\"'" },
	};
	ARRAY_TYPE(const_string) output;
	const char *value, *error;

	test_begin("settings_parse_boollist_string()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) T_BEGIN {
		t_array_init(&output, 8);
		test_assert_idx(settings_parse_boollist_string(tests[i].input,
			pool_datastack_create(), &output, &error) == 0, i);
		test_assert_idx(array_count(&output) == str_array_length(tests[i].output), i);
		unsigned int j = 0;
		array_foreach_elem(&output, value)
			test_assert_strcmp_idx(tests[i].output[j++], value, i);
	} T_END;

	t_array_init(&output, 8);
	for (unsigned int i = 0; i < N_ELEMENTS(error_tests); i++) {
		test_assert_idx(settings_parse_boollist_string(error_tests[i].input,
			pool_datastack_create(), &output, &error) < 0, i);
		test_assert_strcmp_idx(error, error_tests[i].error, i);
	};
	test_end();
}

static void test_settings_section_escape(void)
{
	const struct {
		const char *input;
		const char *output;
	} tests[] = {
		{ "", "\\." },
		{ "foo", "foo" },
		{ "foo bar", "foo\\_bar" },
		{ " foo bar ", "\\_foo\\_bar\\_" },
		{ "=/\\ ,", "\\e\\s\\\\\\_\\+" },
	};
	test_begin("settings_escape() and settings_unescape()");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		const char *escaped = settings_section_escape(tests[i].input);
		test_assert_strcmp_idx(escaped, tests[i].output, i);
		const char *unescaped = settings_section_unescape(escaped);
		test_assert_strcmp_idx(unescaped, tests[i].input, i);
	}

	test_assert_strcmp(settings_section_unescape("\\?"), "\\?");
	test_assert_strcmp(settings_section_unescape("foo\\"), "foo\\");
	test_assert_strcmp(settings_section_unescape("foo\\.bar"), "foobar");
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_settings_parser,
		test_settings_parse_boollist_string,
		test_settings_section_escape,
		NULL
	};
	return test_run(test_functions);
}
