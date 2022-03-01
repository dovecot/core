/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "istream.h"
#include "test-common.h"

static const char *test_settings_blobs[] =
{
/* Blob 0 */
	"bool_true=yes\n"
	"bool_false=no\n"
	"uint=15\n"
	"uint_oct=0700\n"
	"secs=5s\n"
	"msecs=5ms\n"
	"size=1k\n"
	"port=2205\n"
	"str=test string\n"
	"expand_str=test %{string}\n"
	"strlist=\n"
	"strlist/x=a\n"
	"strlist/y=b\n"
	"strlist/z=c\n"
	"\n",
};


static void test_settings_get_time(void)
{
	static const struct {
		const char *input;
		unsigned int output;
	} tests[] = {
		{ "0", 0 },

		{ "59s", 59 },
		{ "59 s", 59 },
		{ "59se", 59 },
		{ "59sec", 59 },
		{ "59secs", 59 },
		{ "59seco", 59 },
		{ "59secon", 59 },
		{ "59second", 59 },
		{ "59seconds", 59 },
		{ "123456   seconds", 123456 },

		{ "123m", 123*60 },
		{ "123 m", 123*60 },
		{ "123 mi", 123*60 },
		{ "123 min", 123*60 },
		{ "123 mins", 123*60 },
		{ "123 minu", 123*60 },
		{ "123 minut", 123*60 },
		{ "123 minute", 123*60 },
		{ "123 minutes", 123*60 },

		{ "123h", 123*60*60 },
		{ "123 h", 123*60*60 },
		{ "123 ho", 123*60*60 },
		{ "123 hou", 123*60*60 },
		{ "123 hour", 123*60*60 },
		{ "123 hours", 123*60*60 },

		{ "12d", 12*60*60*24 },
		{ "12 d", 12*60*60*24 },
		{ "12 da", 12*60*60*24 },
		{ "12 day", 12*60*60*24 },
		{ "12 days", 12*60*60*24 },

		{ "3w", 3*60*60*24*7 },
		{ "3 w", 3*60*60*24*7 },
		{ "3 we", 3*60*60*24*7 },
		{ "3 wee", 3*60*60*24*7 },
		{ "3 week", 3*60*60*24*7 },
		{ "3 weeks", 3*60*60*24*7 },

		{ "1000ms", 1 },
		{ "50000ms", 50 },
	};
	struct {
		const char *input;
		unsigned int output;
	} msecs_tests[] = {
		{ "0ms", 0 },
		{ "1ms", 1 },
		{ "123456ms", 123456 },
		{ "123456 ms", 123456 },
		{ "123456mse", 123456 },
		{ "123456msec", 123456 },
		{ "123456msecs", 123456 },
		{ "123456mseco", 123456 },
		{ "123456msecon", 123456 },
		{ "123456msecond", 123456 },
		{ "123456mseconds", 123456 },
		{ "123456mil", 123456 },
		{ "123456mill", 123456 },
		{ "123456milli", 123456 },
		{ "123456millis", 123456 },
		{ "123456millisec", 123456 },
		{ "123456millisecs", 123456 },
		{ "123456milliseco", 123456 },
		{ "123456millisecon", 123456 },
		{ "123456millisecond", 123456 },
		{ "123456milliseconds", 123456 },
		{ "4294967295 ms", 4294967295 },
	};
	const char *secs_errors[] = {
		"-1",
		"1",
		/* wrong spellings: */
		"1ss",
		"1secss",
		"1secondss",
		"1ma",
		"1minsa",
		"1hu",
		"1hoursa",
		"1dd",
		"1days?",
		"1wa",
		"1weeksb",

		/* milliseconds: */
		"1ms",
		"999ms",
		"1001ms",
		/* overflows: */
		"7102 w",
		"4294967296 s",
	};
	const char *msecs_errors[] = {
		"-1",
		"1",
		/* wrong spellings: */
		"1mis",
		"1mss",
		/* overflows: */
		"8 w",
		"4294967296 ms",
	};
	unsigned int i, secs, msecs;
	const char *error;

	test_begin("settings_get_time()");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(settings_get_time(tests[i].input, &secs, &error) == 0, i);
		test_assert_idx(secs == tests[i].output, i);

		test_assert_idx(settings_get_time_msecs(tests[i].input, &msecs, &error) == 0, i);
		test_assert_idx(msecs == tests[i].output*1000, i);
	}
	for (i = 0; i < N_ELEMENTS(msecs_tests); i++) {
		test_assert_idx(settings_get_time_msecs(msecs_tests[i].input, &msecs, &error) == 0, i);
		test_assert_idx(msecs == msecs_tests[i].output, i);
	}
	for (i = 0; i < N_ELEMENTS(secs_errors); i++)
		test_assert_idx(settings_get_time(secs_errors[i], &secs, &error) < 0, i);
	for (i = 0; i < N_ELEMENTS(msecs_errors); i++)
		test_assert_idx(settings_get_time_msecs(msecs_errors[i], &msecs, &error) < 0, i);
	test_end();
}

static void test_settings_get_size(void)
{
	test_begin("settings_get_size()");

	static const struct {
		const char *input;
		uoff_t output;
	} tests[] = {
		{ "0", 0 },
		{ "0000", 0 },
		{ "1b", 1 },
		{ "1B", 1 },
		{ "1 b", 1 },
		{ "1k", 1024 },
		{ "1K", 1024 },
		{ "1 k", 1024 },
		{ "1m", 1024*1024 },
		{ "1M", 1024*1024 },
		{ "1 m", 1024*1024 },
		{ "1g", 1024*1024*1024ULL },
		{ "1G", 1024*1024*1024ULL },
		{ "1 g", 1024*1024*1024ULL },
		{ "1t", 1024*1024*1024*1024ULL },
		{ "1T", 1024*1024*1024*1024ULL },
		{ "1 t", 1024*1024*1024*1024ULL },
	};

	const char *size_errors[] = {
		"-1",
		"one",
		"",
		"340282366920938463463374607431768211456",
		"2^32",
		"2**32",
		"1e10",
		"1 byte",
	};

	size_t i;
	uoff_t size;
	const char *error;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		error = NULL;
		test_assert_idx(settings_get_size(tests[i].input, &size, &error) == 0, i);
		test_assert_idx(size == tests[i].output, i);
		test_assert(error == NULL);
	}
	for (i = 0; i < N_ELEMENTS(size_errors); i++) {
		error = NULL;
		test_assert_idx(settings_get_size(size_errors[i], &size, &error) < 0, i);
		test_assert(error != NULL);
	};

	test_end();
}

static void test_settings_parser_get(void)
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
		SETTING_DEFINE_STRUCT_STR("str", str, struct test_settings),
		{ .type = SET_STR_VARS, .key = "expand_str",
		  offsetof(struct test_settings, expand_str), NULL },
		{ .type = SET_STRLIST, .key = "strlist",
		  offsetof(struct test_settings, strlist), NULL },
		SETTING_DEFINE_LIST_END
	};
	const struct setting_parser_info root = {
		.module_name = "test",
		.defines = defs,
		.defaults = &test_defaults,

		.type_offset = SIZE_MAX,
		.struct_size = sizeof(struct test_settings),

		.parent_offset = SIZE_MAX,
	};

	test_begin("settings_parser_get");

	pool_t pool = pool_alloconly_create("settings parser", 1024);
	struct setting_parser_context *ctx =
		settings_parser_init(pool, &root, 0);
	struct istream *is = test_istream_create(test_settings_blobs[0]);
	const char *error = NULL;
	int ret;
	while((ret = settings_parse_stream_read(ctx, is)) > 0);
	test_assert(ret == 0);
	if (ret < 0)
		i_error("settings_parse_stream failed: %s",
			settings_parser_get_error(ctx));
	i_stream_unref(&is);
	test_assert(settings_parser_check(ctx, pool, NULL));

	/* check what we got */
	struct test_settings *settings = settings_parser_get(ctx);
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
	test_assert_strcmp(settings->expand_str, "0test %{string}");

	test_assert(array_count(&settings->strlist) == 6);
	test_assert_strcmp(t_array_const_string_join(&settings->strlist, ";"),
			   "x;a;y;b;z;c");

	const struct var_expand_table table[] = {
		{'\0', "value", "string"},
		{'\0', NULL, NULL}
	};

	/* expand settings */
	test_assert(settings_var_expand(&root, settings, pool, table, &error) == 1 &&
		    error == NULL);

	/* check that the setting got expanded */
	test_assert_strcmp(settings->expand_str, "test value");

	settings_parser_deinit(&ctx);
	pool_unref(&pool);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_settings_get_time,
		test_settings_get_size,
		test_settings_parser_get,
		NULL
	};
	return test_run(test_functions);
}
