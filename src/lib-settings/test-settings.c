/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "settings.h"
#include "test-common.h"

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
		"test2_fruit/Orange/eat=no",
		"test2_fruit/Orange/preference=1",
		"test2_fruit+=Apple",
		"test2_fruit/Apple/eat=yes",
		"test2_fruit/Apple/preference=2",
		"test2_fruit+=Grapefruit",
		"test2_fruit/Grapefruit/eat=no",
		"test2_fruit/Grapefruit/preference=0",
		"test2_fruit+=Mulberry",
		"test2_fruit/Mulberry/eat=yes",
		"test2_fruit/Mulberry/preference=6",
		"test2_fruit+=Lemon",
		"test2_fruit/Lemon/eat=yes",
		"test2_fruit/Lemon/preference=4",
		"test2_fruit+=Fig",
		"test2_fruit/Fig/eat=no",
		"test2_fruit/Fig/preference=5",
		"test2_fruit+=PineApple",
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
		test_settings_get,
		NULL
	};
	return test_run(test_functions);
}
