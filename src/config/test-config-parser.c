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

static const struct config_service test_config_all_services[] = { { NULL, NULL } };
const struct config_service *config_all_services = test_config_all_services;

struct test_settings {
	pool_t pool;
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

const struct setting_parser_info test_settings_info = {
	.name = "test",
	.defines = test_settings_defs,
	.defaults = &test_settings_defaults,

	.struct_size = sizeof(struct test_settings),
	.pool_offset1 = 1 + offsetof(struct test_settings, pool),
};

static const struct setting_parser_info *const infos[] = {
	&test_settings_info,
	NULL
};

const struct setting_parser_info *const *all_infos = infos;

static void write_config_file(const char *contents)
{
	struct ostream *os = o_stream_create_file(TEST_CONFIG_FILE, 0, 0600, 0);
	o_stream_nsend_str(os, contents);
	test_assert(o_stream_finish(os) == 1);
	o_stream_unref(&os);
}

static void test_config_parser(void)
{
	struct config_parsed *config;
	const char *error = NULL;

	test_begin("config_parse_file");

	write_config_file(
"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
"# comment\n"
"key=value\n"
"key2 = \\$escape \\escape \\\"escape\\\"\n"
"key3 = $value\n"
"key3 = $SET:key3 nothervalue\n"
"key3 = yetanother value $SET:key3 right here\n"
"key4 = \" $SET:key3 \"\n"
"key5 = ' $SET:key4 '\n"
"pop3_deleted_flag = \"$Deleted\"\n"
"env_key=$ENV:foo\n"
"env_key=$SET:env_key $ENV:bar\n"
"env_key=$SET:env_key \"$SET:env_key\"\n"
"env_key2 = foo$ENV:FOO bar\n"
"env_key3 = $ENV:FOO$ENV:FOO bar\n"
"env_key4 = $ENV:foo $ENV:bar $SET:key\n"
"env_key5 = $ENV:foo $ENV:foo\n"
"protocols = $SET:protocols imap\n"
	);

	putenv("foo=test1");
	putenv("bar=test2");
	putenv("FOO$ENV:FOO=works");

	test_assert(config_parse_file(TEST_CONFIG_FILE,
				      CONFIG_PARSE_FLAG_EXPAND_VALUES |
				      CONFIG_PARSE_FLAG_NO_DEFAULTS,
				      NULL, &config, &error) == 1);
	if (error != NULL)
		i_error("config_parse_file(): %s", error);

	/* get the parsed output */
	pool_t pool = pool_alloconly_create("test settings", 128);
	struct config_filter_parser *global_filter =
		config_parsed_get_global_filter_parser(config);
	const struct config_module_parser *p = global_filter->module_parsers;
	struct setting_parser_context *set_parser =
		settings_parser_init(pool, p->info, 0);
	config_fill_set_parser(set_parser, p, TRUE);
	const struct test_settings *set = settings_parser_get_set(set_parser);
	test_assert_strcmp(set->key, "value");
	test_assert_strcmp(set->key2, "\\$escape \\escape \\\"escape\\\"");
	test_assert_strcmp(set->key3, "yetanother value $value nothervalue right here");
	test_assert_strcmp(set->key4, " $SET:key3 ");
	test_assert_strcmp(set->key5, " $SET:key4 ");
	test_assert_strcmp(set->pop3_deleted_flag, "$Deleted");
	test_assert_strcmp(set->env_key, "test1 test2 \"$SET:env_key\"");
	test_assert_strcmp(set->env_key2, "foo$ENV:FOO bar");
	test_assert_strcmp(set->env_key3, "works bar");
	test_assert_strcmp(set->env_key4, "test1 test2 value");
	test_assert_strcmp(set->env_key5, "test1 test1");
	test_assert_strcmp(set->protocols, "pop3 imap");
	settings_parser_unref(&set_parser);
	config_parsed_free(&config);

	/* try again unexpanded */
	test_assert(config_parse_file(TEST_CONFIG_FILE,
				      CONFIG_PARSE_FLAG_NO_DEFAULTS,
				      NULL, &config, &error) == 1);

	p_clear(pool);
	global_filter = config_parsed_get_global_filter_parser(config);
	p = global_filter->module_parsers;
	set_parser = settings_parser_init(pool, p->info, 0);
	config_fill_set_parser(set_parser, p, TRUE);
	set = settings_parser_get_set(set_parser);

	test_assert_strcmp(set->key, "value");
	test_assert_strcmp(set->key2, "\\$escape \\escape \\\"escape\\\"");
	test_assert_strcmp(set->key3, "yetanother value $value nothervalue right here");
	test_assert_strcmp(set->key4, " $SET:key3 ");
	test_assert_strcmp(set->key5, " $SET:key4 ");
	test_assert_strcmp(set->pop3_deleted_flag, "$Deleted");
	test_assert_strcmp(set->env_key, "$ENV:foo $ENV:bar \"$SET:env_key\"");
	test_assert_strcmp(set->env_key2, "foo$ENV:FOO bar");
	test_assert_strcmp(set->env_key3, "$ENV:FOO$ENV:FOO bar");
	test_assert_strcmp(set->env_key4, "$ENV:foo $ENV:bar $SET:key");
	test_assert_strcmp(set->env_key5, "$ENV:foo $ENV:foo");
	test_assert_strcmp(set->protocols, "pop3 imap");

	settings_parser_unref(&set_parser);
	config_parsed_free(&config);
	config_parser_deinit();
	i_unlink_if_exists(TEST_CONFIG_FILE);
	pool_unref(&pool);
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
