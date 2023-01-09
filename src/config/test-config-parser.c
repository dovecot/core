/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ostream.h"
#include "service-settings.h"
#include "settings-parser.h"
#include "config-filter.h"
#include "test-common.h"
#include "all-settings.h"
#include "config-parser.h"

#define TEST_CONFIG_FILE ".test-config"

static ARRAY_TYPE(service_settings) services = ARRAY_INIT;
ARRAY_TYPE(service_settings) *default_services = &services;

struct test_settings {
	const char *key;
	const char *key2;
	const char *key3;
	const char *key4;
	const char *key5;
	const char *pop3_deleted_flag;
	const char *env_key;
	const char *env_key2;
	const char *env_key3;
	const char *env_key4;
	const char *env_key5;
	const char *protocols;
};

static const struct setting_define test_settings_defs[] = {
	SETTING_DEFINE_STRUCT_STR("key", key, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("key2", key2, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("key3", key3, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("key4", key4, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("key5", key5, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("pop3_deleted_flag", pop3_deleted_flag, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("env_key", env_key, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("env_key2", env_key2, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("env_key3", env_key3, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("env_key4", env_key4, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("env_key5", env_key5, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("protocols", protocols, struct test_settings),
	SETTING_DEFINE_LIST_END
};

static const struct test_settings test_settings_defaults = {
	.key = "",
	.key2 = "",
	.key3 = "",
	.key4 = "",
	.key5 = "",
	.pop3_deleted_flag = "",
	.env_key = "",
	.env_key2 = "",
	.env_key3 = "",
	.env_key4 = "",
	.env_key5 = "",
	.protocols = "pop3",
};

const struct setting_parser_info test_settings_root = {
	.module_name = "test",
	.defines = test_settings_defs,
	.defaults = &test_settings_defaults,

	.type_offset = SIZE_MAX,
	.struct_size = sizeof(struct test_settings),

	.parent_offset = SIZE_MAX,
	.parent = NULL,
};

static const struct setting_parser_info *const roots[] = {
	&test_settings_root,
	NULL
};

const struct setting_parser_info *const *all_roots = roots;

static void write_config_file(const char *contents)
{
	struct ostream *os = o_stream_create_file(TEST_CONFIG_FILE, 0, 0600, 0);
	o_stream_nsend_str(os, contents);
	test_assert(o_stream_finish(os) == 1);
	o_stream_unref(&os);
}

static void test_config_parser(void)
{
	const char *error = NULL;

	test_begin("config_parse_file");

	write_config_file(
"# comment\n"
"key=value\n"
"key2 = \\$escape \\escape \\\"escape\\\"\n"
"key3 = value\n"
"key3 = $key3 nothervalue\n"
"key3 = yetanother value $key3 right here\n"
"key4 = \" $key3 \"\n"
"key5 = ' $key4 '\n"
"pop3_deleted_flag = \"$Deleted\"\n"
"env_key=$ENV:foo\n"
"env_key=$env_key $ENV:bar\n"
"env_key=$env_key \"$env_key\"\n"
"env_key2 = foo$ENV:FOO bar\n"
"env_key3 = $ENV:FOO$ENV:FOO bar\n"
"env_key4 = $ENV:foo $ENV:bar $key\n"
"env_key5 = $ENV:foo $ENV:foo\n"
"protocols = $protocols imap\n"
	);

	putenv("foo=test1");
	putenv("bar=test2");
	putenv("FOO$ENV:FOO=works");

	test_assert(config_parse_file(TEST_CONFIG_FILE, CONFIG_PARSE_FLAG_EXPAND_VALUES, &error) == 1);
	if (error != NULL)
		i_error("config_parse_file(): %s", error);

	/* get the parsed output */
	const struct test_settings *set =
		settings_parser_get(config_module_parsers[0].parser);
	test_assert_strcmp(set->key, "value");
	test_assert_strcmp(set->key2, "\\$escape \\escape \\\"escape\\\"");
	test_assert_strcmp(set->key3, "yetanother value value nothervalue right here");
	test_assert_strcmp(set->key4, " $key3 ");
	test_assert_strcmp(set->key5, " $key4 ");
	test_assert_strcmp(set->pop3_deleted_flag, "$Deleted");
	test_assert_strcmp(set->env_key, "test1 test2 \"$env_key\"");
	test_assert_strcmp(set->env_key2, "foo$ENV:FOO bar");
	test_assert_strcmp(set->env_key3, "works bar");
	test_assert_strcmp(set->env_key4, "test1 test2 value");
	test_assert_strcmp(set->env_key5, "test1 test1");
	test_assert_strcmp(set->protocols, "pop3 imap");

	/* try again unexpanded */
	test_assert(config_parse_file(TEST_CONFIG_FILE, 0, &error) == 1);
	set = settings_parser_get(config_module_parsers[0].parser);

	test_assert_strcmp(set->key, "value");
	test_assert_strcmp(set->key2, "\\$escape \\escape \\\"escape\\\"");
	test_assert_strcmp(set->key3, "yetanother value value nothervalue right here");
	test_assert_strcmp(set->key4, " $key3 ");
	test_assert_strcmp(set->key5, " $key4 ");
	test_assert_strcmp(set->pop3_deleted_flag, "$Deleted");
	test_assert_strcmp(set->env_key, "$ENV:foo $ENV:bar \"$env_key\"");
	test_assert_strcmp(set->env_key2, "foo$ENV:FOO bar");
	test_assert_strcmp(set->env_key3, "$ENV:FOO$ENV:FOO bar");
	test_assert_strcmp(set->env_key4, "$ENV:foo $ENV:bar $key");
	test_assert_strcmp(set->env_key5, "$ENV:foo $ENV:foo");
	test_assert_strcmp(set->protocols, "pop3 imap");

	config_filter_deinit(&config_filter);
	config_parser_deinit();
	i_unlink_if_exists(TEST_CONFIG_FILE);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_config_parser,
		NULL
	};
	return test_run(test_functions);
}
