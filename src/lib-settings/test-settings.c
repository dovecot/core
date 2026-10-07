/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "settings.h"
#include "settings-history.h"
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
	ARRAY_TYPE(const_string) attrs;
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
	{ .type = SET_ALIAS, .key = "test2_title_alias" },

	{ .type = SET_FILTER_ARRAY, .key = "test2_fruit",
	   .offset = offsetof(struct test2_settings, fruits),
	   .filter_array_field_name = "test2_fruit_name" },
	DEF(STRLIST, attrs),
	{ .type = SET_ALIAS, .key = "test2_attrs_alias" },
	SETTING_DEFINE_LIST_END
};

static struct test2_settings test2_default_settings = {
	.title = "",
	.fruits = ARRAY_INIT,
	.attrs = ARRAY_INIT,
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
	unsigned int fruit_idx;
	if (!setting_parser_info_find_key(&test2_setting_parser_info,
					  "test2_fruit", &fruit_idx))
		i_unreached();
	test2_setting_defines[fruit_idx].filter_array_order = order;

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

static int
test_var_expand_hierarchy_key1(const char *field_name ATTR_UNUSED,
			       const char **value_r, void *context,
			       const char **error_r ATTR_UNUSED)
{
	test_assert_strcmp(context, "context1");
	*value_r = "key1_value";
	return 0;
}

static int
test_var_expand_hierarchy_key2(const char *key ATTR_UNUSED,
			       const char **value_r, void *context,
			       const char **error_r ATTR_UNUSED)
{
	test_assert_strcmp(context, "context2");
	*value_r = "key2_value";
	return 0;
}

static void test_var_expand_hierarchy(void)
{
	test_begin("settings_get - hierarchical event");
	char *context1 = "context1";
	char *context2 = "context2";
	struct var_expand_table tab1[] = {
		{ .key = "key1", .func = test_var_expand_hierarchy_key1 },
		{ .key = NULL }
	};
	struct var_expand_params params1 = {
		.table = tab1,
		.context = context1,
	};

	struct var_expand_provider prov2[] = {
		{ "key2", test_var_expand_hierarchy_key2 },
		{ NULL, NULL }
	};
	struct var_expand_params params2 = {
		.providers = prov2,
		.context = context2,
	};

	struct var_expand_params params3;
	i_zero(&params3);
	params3.tables_arr = (const struct var_expand_table *const[]) {
		tab1,
		tab1,
		NULL
	};
	params3.contexts = (void *const[]) {
		context1,
		context1,
		VAR_EXPAND_CONTEXTS_END,
	};

	struct settings_root *set_root = settings_root_init();
	settings_root_override(set_root, "test2_title", "%{key1} and %{key2:foo}",
			       SETTINGS_OVERRIDE_TYPE_DEFAULT);

	struct event *root = event_create(NULL);
	event_set_ptr(root, SETTINGS_EVENT_ROOT, set_root);
	event_set_ptr(root, SETTINGS_EVENT_VAR_EXPAND_PARAMS, &params1);

	struct event *child = event_create(root);
	event_set_ptr(child, SETTINGS_EVENT_VAR_EXPAND_PARAMS, &params2);

	struct test2_settings *set;
	const char *error;
	test_assert(settings_get(child, &test2_setting_parser_info, 0,
				 &set, &error) == 0);
	test_assert_strcmp(set->title, "key1_value and key2_value");
	settings_free(set);

	struct event *child2 = event_create(child);
	event_set_ptr(child2, SETTINGS_EVENT_VAR_EXPAND_PARAMS, &params3);

	test_assert(settings_get(child2, &test2_setting_parser_info, 0,
				 &set, &error) == 0);
	test_assert_strcmp(set->title, "key1_value and key2_value");
	settings_free(set);


	event_unref(&child2);
	event_unref(&child);
	event_unref(&root);
	settings_root_deinit(&set_root);
	test_end();
}

static void test_var_expand_strlist_key(void)
{
	test_begin("settings_get - strlist key expansion");

	char *context1 = "context1";
	struct var_expand_table tab1[] = {
		{ .key = "key1", .func = test_var_expand_hierarchy_key1 },
		{ .key = NULL }
	};
	struct var_expand_params params1 = {
		.table = tab1,
		.context = context1,
	};

	struct settings_root *set_root = settings_root_init();
	/* key with a %variable - must be expanded, but its raw form is the
	   list identity used for dedup/override */
	settings_root_override(set_root, "test2_attrs/%{key1}", "v-%{key1}",
			       SETTINGS_OVERRIDE_TYPE_DEFAULT);
	/* a second, distinct raw key that must survive alongside the first */
	settings_root_override(set_root, "test2_attrs/plain", "%{key1}",
			       SETTINGS_OVERRIDE_TYPE_DEFAULT);

	struct event *event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);
	event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_PARAMS, &params1);

	struct test2_settings *set;
	const char *error;
	test_assert(settings_get(event, &test2_setting_parser_info, 0,
				 &set, &error) == 0);

	unsigned int count;
	const char *const *attrs = array_get(&set->attrs, &count);
	/* both raw keys survived dedup (no collision on raw identity);
	   overrides are filled in reverse order */
	test_assert(count == 4);
	if (count == 4) {
		/* literal key kept, value expanded */
		test_assert_strcmp(attrs[0], "plain");
		test_assert_strcmp(attrs[1], "key1_value");
		/* key and value both expanded */
		test_assert_strcmp(attrs[2], "key1_value");
		test_assert_strcmp(attrs[3], "v-key1_value");
	}
	settings_free(set);

	event_unref(&event);
	settings_root_deinit(&set_root);
	test_end();
}

static void test_strlist_key_no_override_expand(void)
{
	test_begin("settings_get - strlist key not expanded for overrides");

	char *context1 = "context1";
	struct var_expand_table tab1[] = {
		{ .key = "key1", .func = test_var_expand_hierarchy_key1 },
		{ .key = NULL }
	};
	struct var_expand_params params1 = {
		.table = tab1,
		.context = context1,
	};

	struct settings_root *set_root = settings_root_init();
	/* -o style and userdb overrides must NOT have their keys or values
	   expanded, the same way override values are not expanded. */
	settings_root_override(set_root, "test2_attrs/%{key1}", "%{key1}",
			       SETTINGS_OVERRIDE_TYPE_CLI_PARAM);
	settings_root_override(set_root, "test2_attrs/u-%{key1}", "%{key1}",
			       SETTINGS_OVERRIDE_TYPE_USERDB);

	struct event *event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);
	event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_PARAMS, &params1);

	struct test2_settings *set;
	const char *error;
	test_assert(settings_get(event, &test2_setting_parser_info, 0,
				 &set, &error) == 0);

	unsigned int count;
	const char *const *attrs = array_get(&set->attrs, &count);
	test_assert(count == 4);
	if (count == 4) {
		/* keys and values stay literal */
		test_assert_strcmp(attrs[0], "%{key1}");    /* -o key   */
		test_assert_strcmp(attrs[1], "%{key1}");    /* -o value */
		test_assert_strcmp(attrs[2], "u-%{key1}");  /* userdb key   */
		test_assert_strcmp(attrs[3], "%{key1}");    /* userdb value */
	}
	settings_free(set);

	event_unref(&event);
	settings_root_deinit(&set_root);
	test_end();
}

struct test_empty_default_settings {
	pool_t pool;

	unsigned int num;
	unsigned int interval;
	const char *str;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("test_empty_default_"#name, name, \
				     struct test_empty_default_settings)

static const struct setting_define test_empty_default_setting_defines[] = {
	DEF(UINT, num),
	DEF(TIME, interval),
	DEF(STR, str),
	SETTING_DEFINE_LIST_END
};

static const struct test_empty_default_settings
test_empty_default_default_settings = {
	.num = 42,
	.interval = 30,
	.str = "default",
};

/* An empty built-in default for a setting that can't be empty (num, interval)
   must be treated as "no default" and inherited from the struct default,
   rather than failing to parse. An empty default for an emptyable setting
   (str) is applied normally. */
static const struct setting_keyvalue
test_empty_default_default_settings_keyvalue[] = {
	{ "test_empty_default_num", "" },
	{ "test_empty_default_interval", "" },
	{ "test_empty_default_str", "" },
	{ NULL, NULL }
};

static const struct setting_parser_info test_empty_default_setting_parser_info = {
	.name = "test_empty_default",

	.defines = test_empty_default_setting_defines,
	.defaults = &test_empty_default_default_settings,
	.default_settings = test_empty_default_default_settings_keyvalue,

	.struct_size = sizeof(struct test_empty_default_settings),
	.pool_offset1 = 1 + offsetof(struct test_empty_default_settings, pool),
};

static void test_settings_empty_default(void)
{
	test_begin("settings_get - empty built-in default means no default");

	struct settings_root *set_root = settings_root_init();
	struct event *event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);

	struct test_empty_default_settings *set;
	const char *error = NULL;
	int ret = settings_get(event, &test_empty_default_setting_parser_info,
			       0, &set, &error);
	test_assert(ret == 0);
	test_assert(error == NULL);
	if (error != NULL)
		i_error("%s", error);
	if (ret == 0) {
		/* non-emptyable settings inherit their struct defaults */
		test_assert(set->num == 42);
		test_assert(set->interval == 30);
		/* emptyable setting keeps the empty default */
		test_assert_strcmp(set->str, "");
		settings_free(set);
	}

	event_unref(&event);
	settings_root_deinit(&set_root);
	test_end();
}

struct test_path_settings {
	pool_t pool;

	const char *dir;
	const char *file;
	const char *str;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("test_path_"#name, name, \
				     struct test_path_settings)

static const struct setting_define test_path_setting_defines[] = {
	DEF(PATH_DIR, dir),
	DEF(PATH_FILE, file),
	DEF(STR, str),
	SETTING_DEFINE_LIST_END
};

static const struct test_path_settings test_path_default_settings = {
	.dir = "",
	.file = "",
	.str = "",
};

static const struct setting_parser_info test_path_setting_parser_info = {
	.name = "test_path",

	.defines = test_path_setting_defines,
	.defaults = &test_path_default_settings,

	.struct_size = sizeof(struct test_path_settings),
	.pool_offset1 = 1 + offsetof(struct test_path_settings, pool),
};

static void
test_settings_path_expand_scenario(const char *scenario_name,
				   enum settings_override_type type,
				   const char *value,
				   const char *expected_dir,
				   const char *expected_file,
				   const char *expected_str)
{
	struct var_expand_table tab[] = {
		{ .key = "home", .value = "/home/user" },
		{ .key = "key1", .value = "key1_value" },
		{ .key = NULL }
	};
	struct var_expand_params params = {
		.table = tab,
	};

	test_begin(t_strdup_printf("settings_get - path expand %s",
				   scenario_name));

	struct settings_root *set_root = settings_root_init();
	settings_root_override(set_root, "test_path_dir", value, type);
	settings_root_override(set_root, "test_path_file", value, type);
	settings_root_override(set_root, "test_path_str", value, type);

	struct event *event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);
	event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_PARAMS, &params);

	struct test_path_settings *set;
	const char *error = NULL;
	int ret = settings_get(event, &test_path_setting_parser_info, 0,
			       &set, &error);
	test_assert(ret == 0);
	test_assert(error == NULL);
	if (error != NULL)
		i_error("%s", error);
	if (ret == 0) {
		test_assert_strcmp(set->dir, expected_dir);
		test_assert_strcmp(set->file, expected_file);
		test_assert_strcmp(set->str, expected_str);
		settings_free(set);
	}

	event_unref(&event);
	settings_root_deinit(&set_root);
	test_end();
}

static void test_settings_path_expand(void)
{
	/* default settings get full %variable expansion, ~/ included */
	test_settings_path_expand_scenario("default",
		SETTINGS_OVERRIDE_TYPE_DEFAULT, "~/mail/%{key1}",
		"/home/user/mail/key1_value", "/home/user/mail/key1_value",
		"~/mail/key1_value");
	test_settings_path_expand_scenario("default trailing slash",
		SETTINGS_OVERRIDE_TYPE_DEFAULT, "~/mail/",
		"/home/user/mail", "/home/user/mail/", "~/mail/");
	test_settings_path_expand_scenario("default bare tilde",
		SETTINGS_OVERRIDE_TYPE_DEFAULT, "~",
		"/home/user", "/home/user", "~");
	test_settings_path_expand_scenario("default absolute path",
		SETTINGS_OVERRIDE_TYPE_DEFAULT, "/abs/path/",
		"/abs/path", "/abs/path/", "/abs/path/");
	/* -o and userdb overrides expand only the ~/ prefix, the rest of the
	   value stays literal */
	test_settings_path_expand_scenario("cli",
		SETTINGS_OVERRIDE_TYPE_CLI_PARAM, "~/mail/%{key1}",
		"/home/user/mail/%{key1}", "/home/user/mail/%{key1}",
		"~/mail/%{key1}");
	test_settings_path_expand_scenario("userdb",
		SETTINGS_OVERRIDE_TYPE_USERDB, "~/mail/",
		"/home/user/mail", "/home/user/mail/", "~/mail/");
	test_settings_path_expand_scenario("userdb bare tilde",
		SETTINGS_OVERRIDE_TYPE_USERDB, "~",
		"/home/user", "/home/user", "~");
}

static void test_settings_path_expand_no_home(void)
{
	/* no home variable available - using ~/ must fail */
	static const enum settings_override_type types[] = {
		SETTINGS_OVERRIDE_TYPE_DEFAULT,
		SETTINGS_OVERRIDE_TYPE_USERDB,
	};

	test_begin("settings_get - path expand without home");
	for (unsigned int i = 0; i < N_ELEMENTS(types); i++) {
		struct settings_root *set_root = settings_root_init();
		settings_root_override(set_root, "test_path_dir", "~/mail",
				       types[i]);

		struct event *event = event_create(NULL);
		event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);

		struct test_path_settings *set;
		const char *error = NULL;
		test_assert_idx(settings_get(event,
			&test_path_setting_parser_info, 0, &set, &error) < 0, i);
		test_assert_idx(error != NULL, i);

		event_unref(&event);
		settings_root_deinit(&set_root);
	}
	test_end();
}

static void test_settings_alias(void)
{
	test_begin("settings_get - alias");

	struct settings_root *set_root = settings_root_init();
	/* alias of a plain setting */
	settings_root_override(set_root, "test2_title_alias", "aliased title",
			       SETTINGS_OVERRIDE_TYPE_DEFAULT);
	/* alias of a list setting, with a list key suffix */
	settings_root_override(set_root, "test2_attrs_alias/k1", "v1",
			       SETTINGS_OVERRIDE_TYPE_DEFAULT);

	struct event *event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);

	struct test2_settings *set;
	const char *error;
	test_assert(settings_get(event, &test2_setting_parser_info, 0,
				 &set, &error) == 0);
	test_assert_strcmp(set->title, "aliased title");

	unsigned int count;
	const char *const *attrs = array_get(&set->attrs, &count);
	test_assert(count == 2);
	if (count == 2) {
		test_assert_strcmp(attrs[0], "k1");
		test_assert_strcmp(attrs[1], "v1");
	}
	settings_free(set);

	event_unref(&event);
	settings_root_deinit(&set_root);
	test_end();
}

/*
 * default_settings with settings roots without configuration
 */

struct test3_settings {
	pool_t pool;

	const char *title;
	ARRAY_TYPE(const_string) items;
};

struct test3_item_settings {
	pool_t pool;

	const char *name;
	const char *value;
};

struct test4_settings {
	pool_t pool;

	const char *value;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("test3_"#name, name, struct test3_settings)

static const struct setting_define test3_setting_defines[] = {
	DEF(STR, title),
	{ .type = SET_FILTER_ARRAY, .key = "test3_item",
	  .offset = offsetof(struct test3_settings, items),
	  .filter_array_field_name = "test3_item_name" },
	{ .type = SET_FILTER_NAME, .key = "test3_named" },
	SETTING_DEFINE_LIST_END
};

static const struct test3_settings test3_default_settings = {
	.title = "",
	.items = ARRAY_INIT,
};

static const struct setting_keyvalue test3_default_settings_keyvalue[] = {
	{ "test3_title", "title-default" },
	{ "test3_named/test3_title", "named-title-default" },
	{ "test3_item/item1/test3_item_value", "item1-default" },
	{ NULL, NULL }
};

static const struct setting_parser_info test3_setting_parser_info = {
	.name = "test3",

	.defines = test3_setting_defines,
	.defaults = &test3_default_settings,
	.default_settings = test3_default_settings_keyvalue,

	.struct_size = sizeof(struct test3_settings),
	.pool_offset1 = 1 + offsetof(struct test3_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("test3_item_"#name, name, \
				     struct test3_item_settings)

static const struct setting_define test3_item_setting_defines[] = {
	DEF(STR, name),
	DEF(STR, value),
	SETTING_DEFINE_LIST_END
};

static const struct test3_item_settings test3_item_default_settings = {
	.name = "",
	.value = "",
};

static const struct setting_parser_info test3_item_setting_parser_info = {
	.name = "test3_item",

	.defines = test3_item_setting_defines,
	.defaults = &test3_item_default_settings,

	.struct_size = sizeof(struct test3_item_settings),
	.pool_offset1 = 1 + offsetof(struct test3_item_settings, pool),
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("test4_"#name, name, struct test4_settings)

static const struct setting_define test4_setting_defines[] = {
	DEF(STR, value),
	SETTING_DEFINE_LIST_END
};

static const struct test4_settings test4_default_settings = {
	.value = "",
};

static const struct setting_keyvalue test4_default_settings_keyvalue[] = {
	{ "test4_value", "test4-default" },
	{ "test3_named/test4_value", "named-test4-default" },
	{ NULL, NULL }
};

static const struct setting_parser_info test4_setting_parser_info = {
	.name = "test4",

	.defines = test4_setting_defines,
	.defaults = &test4_default_settings,
	.default_settings = test4_default_settings_keyvalue,

	.struct_size = sizeof(struct test4_settings),
	.pool_offset1 = 1 + offsetof(struct test4_settings, pool),
};

struct test5_settings {
	pool_t pool;

	const char *title;
};

static const struct setting_define test5_setting_defines[] = {
	SETTING_DEFINE_STRUCT_STR("test3_title", title, struct test5_settings),
	SETTING_DEFINE_LIST_END
};

static const struct test5_settings test5_default_settings = {
	.title = "",
};

static const struct setting_parser_info test5_setting_parser_info = {
	.name = "test5",

	.defines = test5_setting_defines,
	.defaults = &test5_default_settings,

	.struct_size = sizeof(struct test5_settings),
	.pool_offset1 = 1 + offsetof(struct test5_settings, pool),
};

static const char *
test_defaults_get_title(struct event *event, bool named)
{
	const struct test3_settings *set;
	const char *error;

	struct event *lookup_event = event_create(event);
	if (named)
		settings_event_add_filter_name(lookup_event, "test3_named");
	if (settings_get(lookup_event, &test3_setting_parser_info, 0,
			 &set, &error) < 0) {
		i_error("%s", error);
		event_unref(&lookup_event);
		return "<error>";
	}
	event_unref(&lookup_event);
	const char *title = t_strdup(set->title);
	settings_free(set);
	return title;
}

static const char *
test_defaults_get_item_value(struct event *event, const char *item_name)
{
	const struct test3_item_settings *set;
	const char *error;
	int ret;

	ret = settings_try_get_filter(event, "test3_item", item_name,
				      &test3_item_setting_parser_info, 0,
				      &set, &error);
	if (ret < 0) {
		i_error("%s", error);
		return "<error>";
	}
	if (ret == 0)
		return "<none>";
	const char *value = t_strdup(set->value);
	settings_free(set);
	return value;
}

static const char *
test_defaults_get_test4_value(struct event *event, bool named)
{
	const struct test4_settings *set;
	const char *error;

	struct event *lookup_event = event_create(event);
	if (named)
		settings_event_add_filter_name(lookup_event, "test3_named");
	if (settings_get(lookup_event, &test4_setting_parser_info, 0,
			 &set, &error) < 0) {
		i_error("%s", error);
		event_unref(&lookup_event);
		return "<error>";
	}
	event_unref(&lookup_event);
	const char *value = t_strdup(set->value);
	settings_free(set);
	return value;
}

static void test_settings_no_config_defaults(void)
{
	test_begin("settings_get - default_settings without config");

	/* Two independent roots with instances get the same defaults */
	struct settings_root *roots[2];
	struct settings_instance *instances[2];
	struct event *events[2];
	for (unsigned int i = 0; i < N_ELEMENTS(roots); i++) {
		roots[i] = settings_root_init();
		instances[i] = settings_instance_new(roots[i]);
		events[i] = event_create(NULL);
		event_set_ptr(events[i], SETTINGS_EVENT_ROOT, roots[i]);
		event_set_ptr(events[i], SETTINGS_EVENT_INSTANCE,
			      instances[i]);
	}
	for (unsigned int j = 0; j < 2; j++) {
		for (unsigned int i = 0; i < N_ELEMENTS(roots); i++) {
			test_assert_strcmp_idx(
				test_defaults_get_title(events[i], FALSE),
				"title-default", i);
			test_assert_strcmp_idx(
				test_defaults_get_title(events[i], TRUE),
				"named-title-default", i);
			test_assert_strcmp_idx(
				test_defaults_get_item_value(events[i], "item1"),
				"item1-default", i);
			test_assert_strcmp_idx(
				test_defaults_get_item_value(events[i], "item2"),
				"<none>", i);
		}
	}

	/* Instance overrides are sorted the same way with the defaults:
	   a named filter override wins over the named default, and a plain
	   userdb override wins over the named filter default. */
	settings_override(instances[0], "test3_named/test3_title",
			  "named-title-userdb", SETTINGS_OVERRIDE_TYPE_USERDB);
	settings_override(instances[0], "test3_item/item1/test3_item_value",
			  "item1-userdb", SETTINGS_OVERRIDE_TYPE_USERDB);
	test_assert_strcmp(test_defaults_get_title(events[0], FALSE),
			   "title-default");
	test_assert_strcmp(test_defaults_get_title(events[0], TRUE),
			   "named-title-userdb");
	test_assert_strcmp(test_defaults_get_item_value(events[0], "item1"),
			   "item1-userdb");
	settings_override(instances[1], "test3_title", "title-userdb",
			  SETTINGS_OVERRIDE_TYPE_USERDB);
	test_assert_strcmp(test_defaults_get_title(events[1], FALSE),
			   "title-userdb");
	test_assert_strcmp(test_defaults_get_title(events[1], TRUE),
			   "title-userdb");

	/* A new info registered after the earlier lookups: its defaults are
	   added, and the earlier infos' defaults still work. */
	test_assert_strcmp(test_defaults_get_test4_value(events[0], FALSE),
			   "test4-default");
	test_assert_strcmp(test_defaults_get_test4_value(events[0], TRUE),
			   "named-test4-default");
	test_assert_strcmp(test_defaults_get_title(events[0], TRUE),
			   "named-title-userdb");
	test_assert_strcmp(test_defaults_get_item_value(events[1], "item1"),
			   "item1-default");

	/* The test3_item=item1 filter exists only in test3's default
	   settings, but it's found also when looking up other infos. */
	const struct test4_settings *set4;
	const char *error4;
	test_assert(settings_try_get_filter(events[1], "test3_item", "item1",
					    &test4_setting_parser_info, 0,
					    &set4, &error4) == 1);
	settings_free(set4);
	test_assert(settings_try_get_filter(events[1], "test3_item", "item2",
					    &test4_setting_parser_info, 0,
					    &set4, &error4) == 0);

	/* A new info that has the same key as an earlier info's default
	   gets the default as well. */
	const struct test5_settings *set5;
	const char *error;
	struct settings_root *root5 = settings_root_init();
	struct event *named_event = event_create(NULL);
	event_set_ptr(named_event, SETTINGS_EVENT_ROOT, root5);
	settings_event_add_filter_name(named_event, "test3_named");
	if (settings_get(named_event, &test5_setting_parser_info, 0,
			 &set5, &error) < 0)
		i_error("%s", error);
	else {
		test_assert_strcmp(set5->title, "named-title-default");
		settings_free(set5);
	}
	event_unref(&named_event);
	settings_root_deinit(&root5);

	for (unsigned int i = 0; i < N_ELEMENTS(roots); i++) {
		event_unref(&events[i]);
		settings_instance_free(&instances[i]);
		settings_root_deinit(&roots[i]);
	}
	test_end();
}

static void test_settings_no_config_2nd_defaults(void)
{
	test_begin("settings_get - default_settings without config with 2nd defaults");

	struct settings_root *root = settings_root_init();
	struct settings_instance *instance = settings_instance_new(root);
	struct event *event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, root);
	event_set_ptr(event, SETTINGS_EVENT_INSTANCE, instance);

	/* Like mail_storage_2nd_settings_reset(): reset back to the
	   defaults, which includes default_settings */
	settings_override(instance, "test3_title", "userdb-title",
			  SETTINGS_OVERRIDE_TYPE_USERDB);
	settings_override(instance, "*/test3_title", "",
			  SETTINGS_OVERRIDE_TYPE_2ND_DEFAULT);
	test_assert_strcmp(test_defaults_get_title(event, FALSE),
			   "title-default");
	test_assert_strcmp(test_defaults_get_title(event, TRUE),
			   "named-title-default");

	/* 2nd CLI parameter overrides it */
	settings_override(instance, "*/test3_title", "cli-title",
			  SETTINGS_OVERRIDE_TYPE_2ND_CLI_PARAM);
	test_assert_strcmp(test_defaults_get_title(event, FALSE),
			   "cli-title");

	event_unref(&event);
	settings_instance_free(&instance);
	settings_root_deinit(&root);
	test_end();
}

static void test_settings_history_translate_key(void)
{
	static const struct setting_history_rename test_renames[] = {
		{ "test2_old_title", "test2_title", "2.4.1" },
		{ "test2_older_title", "test2_old_title", "2.4.0" },
		{ "test_old_pass", "test_filt/test_new_pass", "2.4.0" },
	};
	test_begin("settings_history_translate_key");
	settings_history_register_renames(test_renames,
					  N_ELEMENTS(test_renames));

	/* not renamed */
	test_assert_strcmp(settings_history_translate_key("test2_title"),
			   "test2_title");
	/* simple rename */
	test_assert_strcmp(settings_history_translate_key("test2_old_title"),
			   "test2_title");
	/* chained rename */
	test_assert_strcmp(settings_history_translate_key("test2_older_title"),
			   "test2_title");
	/* filter prefixes are preserved */
	test_assert_strcmp(
		settings_history_translate_key("ns/foo/test2_old_title"),
		"ns/foo/test2_title");
	/* rename adding a filter prefix */
	test_assert_strcmp(settings_history_translate_key("test_old_pass"),
			   "test_filt/test_new_pass");
	test_assert_strcmp(
		settings_history_translate_key("ns/foo/test_old_pass"),
		"ns/foo/test_filt/test_new_pass");
	/* already inside the added filter - prefix isn't duplicated */
	test_assert_strcmp(
		settings_history_translate_key("test_filt/test_old_pass"),
		"test_filt/test_new_pass");
	test_assert_strcmp(
		settings_history_translate_key("ns/foo/test_filt/test_old_pass"),
		"ns/foo/test_filt/test_new_pass");
	test_end();
}

static void test_settings_override_rename(void)
{
	/* Uses the renames registered by
	   test_settings_history_translate_key() */
	static const struct {
		enum settings_override_type type;
		const char *expected_title;
	} tests[] = {
		/* userdb and CLI overrides may still use old names of
		   renamed settings */
		{ SETTINGS_OVERRIDE_TYPE_USERDB, "New Title" },
		{ SETTINGS_OVERRIDE_TYPE_CLI_PARAM, "New Title" },
		{ SETTINGS_OVERRIDE_TYPE_2ND_CLI_PARAM, "New Title" },
		/* code overrides must use the current names */
		{ SETTINGS_OVERRIDE_TYPE_CODE, "" },
	};
	test_begin("settings_get - renamed override key");
	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		struct settings_root *set_root = settings_root_init();
		settings_root_override(set_root, "test2_old_title",
				       "New Title", tests[i].type);

		struct event *event = event_create(NULL);
		event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);

		struct test2_settings *set;
		const char *error;
		test_assert_idx(settings_get(event,
			&test2_setting_parser_info, 0, &set, &error) == 0, i);
		test_assert_strcmp_idx(set->title, tests[i].expected_title, i);
		settings_free(set);

		event_unref(&event);
		settings_root_deinit(&set_root);
	}
	test_end();
}

static void test_settings_filter_array_append_only(void)
{
	test_begin("settings_get - filter array item without settings");

	struct settings_root *set_root = settings_root_init();
	/* Growing the overrides array while the generated default overrides
	   are being added to it must not break the lookups. */
	string_t *items = t_str_new(128);
	str_append(items, "new1 new2");
	for (unsigned int i = 0; i < 20; i++)
		str_printfa(items, " extra%u", i);
	settings_root_override(set_root, "test2_fruit+", str_c(items),
			       SETTINGS_OVERRIDE_TYPE_CODE);
	settings_root_override(set_root, "test2_fruit/new1/eat", "yes",
			       SETTINGS_OVERRIDE_TYPE_CODE);

	struct event *event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);

	struct test2_settings *set;
	const char *error;
	test_assert(settings_get(event, &test2_setting_parser_info, 0,
				 &set, &error) == 0);
	test_assert(array_count(&set->fruits) == 22);
	settings_free(set);

	struct test2_fruit_settings *fruit_set;
	test_assert(settings_try_get_filter(event, "test2_fruit", "new1",
				&test2_fruit_setting_parser_info, 0,
				&fruit_set, &error) == 1);
	test_assert_strcmp(fruit_set->name, "new1");
	test_assert(fruit_set->eat);
	settings_free(fruit_set);

	/* new2 has no settings other than the generated name */
	test_assert(settings_try_get_filter(event, "test2_fruit", "new2",
				&test2_fruit_setting_parser_info, 0,
				&fruit_set, &error) == 1);
	test_assert_strcmp(fruit_set->name, "new2");
	test_assert(!fruit_set->eat);
	settings_free(fruit_set);

	test_assert(settings_get_filter(event, "test2_fruit", "extra19",
				&test2_fruit_setting_parser_info, 0,
				&fruit_set, &error) == 0);
	test_assert_strcmp(fruit_set->name, "extra19");
	settings_free(fruit_set);

	test_assert(settings_try_get_filter(event, "test2_fruit", "unknown",
				&test2_fruit_setting_parser_info, 0,
				&fruit_set, &error) == 0);

	event_unref(&event);
	settings_root_deinit(&set_root);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_settings_get,
		test_var_expand_hierarchy,
		test_var_expand_strlist_key,
		test_strlist_key_no_override_expand,
		test_settings_empty_default,
		test_settings_path_expand,
		test_settings_path_expand_no_home,
		test_settings_no_config_defaults,
		test_settings_no_config_2nd_defaults,
		test_settings_alias,
		test_settings_history_translate_key,
		test_settings_override_rename,
		test_settings_filter_array_append_only,
		NULL
	};
	return test_run(test_functions);
}
