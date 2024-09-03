/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "settings.h"
#include "settings-legacy.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"

/*
 * settings_read_nosection()
 */

#define TEST_SETTING_FILE ".test_settings.conf"

static const char *config_contents =
"# this is a comment\n"
"str = value\n"
"str2 = some other value # and this should be ignored\n"
"str3 = $ENV:test\n"
"str4 = $ENV:test %{second}\n"
"str5 = Hello $ENV:test\n"
"str6 = foo$ENV:test bar\n"
"str7 = \"this is $ENV:test string literal\"\n"
"str8 = \\$ENV:test escaped\n"
"str9 = $ENV:FOO$ENV:FOO bar\n"
"str10 = \\$escape \\escape \\\"escape\\\"\n"
"str11 = 'this is $ENV:test string literal'\n"
"str12 = $ENV:test $ENV:test\n"
"b_true = yes\n"
"b_false = no\n"
"number = 1234\n";

struct test_settings {
	const char *str;
	const char *str2;
	const char *str3;
	const char *str4;
	const char *str5;
	const char *str6;
	const char *str7;
	const char *str8;
	const char *str9;
	const char *str10;
	const char *str11;
	const char *str12;

	bool b_true;
	bool b_false;
	unsigned int number;
};

#undef DEF_STR
#undef DEF_BOOL
#undef DEF_INT

#define DEF_STR(name) DEF_STRUCT_STR(name, test_settings)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, test_settings)
#define DEF_INT(name) DEF_STRUCT_INT(name, test_settings)

static struct setting_def setting_defs[] = {
	DEF_STR(str),
	DEF_STR(str2),
	DEF_STR(str3),
	DEF_STR(str4),
	DEF_STR(str5),
	DEF_STR(str6),
	DEF_STR(str7),
	DEF_STR(str8),
	DEF_STR(str9),
	DEF_STR(str10),
	DEF_STR(str11),
	DEF_STR(str12),
	DEF_BOOL(b_true),
	DEF_BOOL(b_false),
	DEF_INT(number),
	{ 0, NULL, 0 }
};

static struct test_settings default_settings = {
	.str   = "",
	.str2  = "",
	.str3  = "",
	.str4  = "",
	.str5  = "",
	.str6  = "",
	.str7  = "",
	.str8  = "",
	.str9  = "",
	.str10 = "",
	.str11 = "",
	.str12 = "",

	.b_true = FALSE,
	.b_false = TRUE,
	.number = 0,
};

struct test_settings_context {
	pool_t pool;
	struct test_settings set;
};

static const char *parse_setting(const char *key, const char *value,
				 struct test_settings_context *ctx)
{
	return parse_setting_from_defs(ctx->pool, setting_defs,
				       &ctx->set, key, value);
}

static void test_settings_read_nosection(void)
{
	test_begin("settings_read_nosection");

	const char *error = NULL;
	/* write a simple config file */
	struct ostream *os = o_stream_create_file(TEST_SETTING_FILE, 0, 0600, 0);
	o_stream_nsend_str(os, config_contents);
	test_assert(o_stream_finish(os) == 1);
	o_stream_unref(&os);

	putenv("test=first");
	putenv("FOO$ENV:FOO=works");
	/* try parse it */
	pool_t pool = pool_alloconly_create("test settings", 1024);
	struct test_settings_context *ctx =
		p_new(pool, struct test_settings_context, 1);
	ctx->pool = pool;
	ctx->set = default_settings;

	test_assert(settings_read_nosection(TEST_SETTING_FILE, parse_setting,
					    ctx, &error));
	test_assert(error == NULL);
	if (error != NULL)
		i_error("%s", error);

	/* see what we got */
	test_assert_strcmp(ctx->set.str, "value");
	test_assert_strcmp(ctx->set.str2, "some other value");
	test_assert_strcmp(ctx->set.str3, "first");
	test_assert_strcmp(ctx->set.str4, "first %{second}");
	test_assert_strcmp(ctx->set.str5, "Hello first");
	test_assert_strcmp(ctx->set.str6, "foo$ENV:test bar");
	test_assert_strcmp(ctx->set.str7, "this is $ENV:test string literal");
	test_assert_strcmp(ctx->set.str8, "\\$ENV:test escaped");
	test_assert_strcmp(ctx->set.str9, "works bar");
	test_assert_strcmp(ctx->set.str10, "\\$escape \\escape \\\"escape\\\"");
	test_assert_strcmp(ctx->set.str11, "this is $ENV:test string literal");
	test_assert_strcmp(ctx->set.str12, "first first");

	test_assert(ctx->set.b_true == TRUE);
	test_assert(ctx->set.b_false == FALSE);
	test_assert(ctx->set.number == 1234);

	pool_unref(&pool);

	i_unlink_if_exists(TEST_SETTING_FILE);
	test_end();
}

/*
 * settings_get()
 */

struct test2_fruit_settings {
	pool_t pool;

	const char *name;
	bool eat;
	unsigned int preference;
};

struct test2_settings {
	pool_t pool;

	const char *title;
	ARRAY_TYPE(const_string) fruits;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("test2_fruit_"#name, name, \
				     struct test2_fruit_settings)

static const struct setting_define test2_fruit_setting_defines[] = {
	DEF(STR, name),
	DEF(BOOL, eat),
	DEF(UINT, preference),
	SETTING_DEFINE_LIST_END
};

static struct test2_fruit_settings test2_fruit_default_settings = {
	.name = "",
	.eat = FALSE,
	.preference = UINT_MAX,
};

static const struct setting_parser_info test2_fruit_setting_parser_info = {
	.name = "test2_fruit",

	.defines = test2_fruit_setting_defines,
	.defaults = &test2_fruit_default_settings,

	.struct_size = sizeof(struct test2_fruit_settings),
	.pool_offset1 = 1 + offsetof(struct test2_fruit_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("test2_"#name, name, struct test2_settings)

static struct setting_define test2_setting_defines[] = {
	DEF(STR, title),

	{ .type = SET_FILTER_ARRAY, .key = "test2_fruit",
	   .offset = offsetof(struct test2_settings, fruits),
	   .filter_array_field_name = "test2_fruit_name" },
	SETTING_DEFINE_LIST_END
};

static struct test2_settings test2_default_settings = {
	.title = "",
	.fruits = ARRAY_INIT,
};

static const struct setting_parser_info test2_setting_parser_info = {
	.name = "test2",

	.defines = test2_setting_defines,
	.defaults = &test2_default_settings,

	.struct_size = sizeof(struct test2_settings),
	.pool_offset1 = 1 + offsetof(struct test2_settings, pool),
};

static void test_settings_get_scenario(
	const char *scenario_name,
	const struct setting_filter_array_order *order, const char *result[])
{
	static const char *const settings[] = {
		"test2_title=Fruit Preferences",
		"test2_fruit+=Orange",
		"test2_fruit/Orange/name=Orange", // FIXME: why is this not applied implicitly?
		"test2_fruit/Orange/eat=no",
		"test2_fruit/Orange/preference=1",
		"test2_fruit+=Apple",
		"test2_fruit/Apple/name=Apple",
		"test2_fruit/Apple/eat=yes",
		"test2_fruit/Apple/preference=2",
		"test2_fruit+=Grapefruit",
		"test2_fruit/Grapefruit/name=Grapefruit",
		"test2_fruit/Grapefruit/eat=no",
		"test2_fruit/Grapefruit/preference=0",
		"test2_fruit+=Mulberry",
		"test2_fruit/Mulberry/name=Mulberry",
		"test2_fruit/Mulberry/eat=yes",
		"test2_fruit/Mulberry/preference=6",
		"test2_fruit+=Lemon",
		"test2_fruit/Lemon/name=Lemon",
		"test2_fruit/Lemon/eat=yes",
		"test2_fruit/Lemon/preference=4",
		"test2_fruit+=Fig",
		"test2_fruit/Fig/name=Fig",
		"test2_fruit/Fig/eat=no",
		"test2_fruit/Fig/preference=5",
		"test2_fruit+=PineApple",
		"test2_fruit/PineApple/name=PineApple",
		"test2_fruit/PineApple/eat=yes",
		"test2_fruit/PineApple/preference=3",
		NULL
	};
	const char *error = NULL;
	pool_t pool;
	static struct test2_settings *set;
	static struct settings_root *set_root;
	int ret;

	/* Modified like this only for testing; normally this is all const */
	test2_setting_defines[1].filter_array_order = order;

	test_begin(t_strdup_printf("settings_get - %s", scenario_name));

	pool = pool_alloconly_create(MEMPOOL_GROWING"test2 pool", 2048);

	set_root = settings_root_init();
	for (unsigned int i = 0; settings[i] != NULL; i++) {
		const char *key, *value;
		t_split_key_value_eq(settings[i], &key, &value);
		settings_root_override(set_root, key, value,
				       SETTINGS_OVERRIDE_TYPE_CODE);
	}
	struct event *event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);

	ret = settings_get(event, &test2_setting_parser_info,
			   (order != NULL ?
			    SETTINGS_GET_FLAG_SORT_FILTER_ARRAYS : 0),
			   &set, &error);
	test_assert(ret == 0);
	test_assert(error == NULL);
	if (error != NULL)
		i_error("%s", error);
	if (ret == 0) {
		test_assert(array_is_created(&set->fruits));
		test_assert_strcmp(set->title, "Fruit Preferences");
	}
	if (ret == 0 && array_is_created(&set->fruits)) {
		unsigned int count, i;
		const char *const *fruits = array_get(&set->fruits, &count);
		for (i = 0; i < count; i++) {
			struct test2_fruit_settings *fruit_set;
			ret = settings_get_filter(
				event, "test2_fruit", fruits[i],
				&test2_fruit_setting_parser_info, 0,
				&fruit_set, &error);
			test_assert(ret == 0);
			test_assert(error == NULL);

			test_assert_strcmp(fruit_set->name, result[i]);

			settings_free(fruit_set);
		}
	}

	settings_free(set);
	settings_root_deinit(&set_root);
	pool_unref(&pool);
	event_unref(&event);

	test_end();
}

static void test_settings_get(void)
{
	static const struct setting_filter_array_order order_by_preference = {
		.info = &test2_fruit_setting_parser_info,
		.field_name = "test2_fruit_preference",
	};
	static struct setting_filter_array_order order_by_name = {
		.info = &test2_fruit_setting_parser_info,
		.field_name = "test2_fruit_name",
	};
	static const struct setting_filter_array_order
		order_by_preference_reverse = {
		.info = &test2_fruit_setting_parser_info,
		.field_name = "test2_fruit_preference",
		.reverse = TRUE,
	};
	static struct setting_filter_array_order order_by_name_reverse = {
		.info = &test2_fruit_setting_parser_info,
		.field_name = "test2_fruit_name",
		.reverse = TRUE,
	};
	static const char *result_unsorted[] = {
		"Orange",
		"Apple",
		"Grapefruit",
		"Mulberry",
		"Lemon",
		"Fig",
		"PineApple",
	};
	static const char *result_sorted_preference[] = {
		"Grapefruit",
		"Orange",
		"Apple",
		"PineApple",
		"Lemon",
		"Fig",
		"Mulberry",
	};
	static const char *result_sorted_name[] = {
		"Apple",
		"Fig",
		"Grapefruit",
		"Lemon",
		"Mulberry",
		"Orange",
		"PineApple",
	};
	static const char *result_sorted_preference_reverse[] = {
		"Mulberry",
		"Fig",
		"Lemon",
		"PineApple",
		"Apple",
		"Orange",
		"Grapefruit",
	};
	static const char *result_sorted_name_reverse[] = {
		"PineApple",
		"Orange",
		"Mulberry",
		"Lemon",
		"Grapefruit",
		"Fig",
		"Apple",
	};

	test_settings_get_scenario("not sorted", NULL, result_unsorted);
	test_settings_get_scenario("sort by preference", &order_by_preference,
				   result_sorted_preference);
	test_settings_get_scenario("sort by name", &order_by_name,
				   result_sorted_name);
	test_settings_get_scenario("sort by preference (reverse)",
				   &order_by_preference_reverse,
				   result_sorted_preference_reverse);
	test_settings_get_scenario("sort by name (reverse)",
				   &order_by_name_reverse,
				   result_sorted_name_reverse);
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_settings_read_nosection,
		test_settings_get,
		NULL
	};
	return test_run(test_functions);
}
