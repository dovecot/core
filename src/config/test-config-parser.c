/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "ostream.h"
#include "service-settings.h"
#include "settings-parser.h"
#include "settings-parser-http-url.h"
#include "http-url.h"
#include "config-filter.h"
#include "settings-history.h"
#include "config-request.h"
#include "test-common.h"
#include "test-dir.h"
#include "all-settings.h"
#include "config-parser.h"

#define TEST_CONFIG_FILE "config"

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
	const char *at_group_name;
	const char *key_file;
	const char *key_novars;
	ARRAY_TYPE(const_string) key_strlist;
	struct http_url key_url;
	struct http_url key_url_auth;
	const char *testfilter_new_key;
	const char *deprecated_key;
	const char *removed_key;
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
	SETTING_DEFINE_STRUCT_STR("@group_name", at_group_name, struct test_settings),
	SETTING_DEFINE_STRUCT_FILE("key_file", key_file, struct test_settings),
	SETTING_DEFINE_STRUCT_STR_NOVARS("key_novars", key_novars, struct test_settings),
	SETTING_DEFINE_STRUCT_STRLIST("key_strlist", key_strlist, struct test_settings),
	SETTING_DEFINE_STRUCT_HTTP_URL("key_url", key_url, struct test_settings),
	SETTING_DEFINE_STRUCT_HTTP_URL_AUTH("key_url_auth", key_url_auth, struct test_settings),
	{ .type = SET_FILTER_NAME, .key = "testfilter" },
	SETTING_DEFINE_STRUCT_STR("testfilter_new_key", testfilter_new_key, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("deprecated_key", deprecated_key, struct test_settings),
	SETTING_DEFINE_STRUCT_STR("removed_key", removed_key, struct test_settings),
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
	.at_group_name = "",
	.key_file = "",
	.key_novars = "",
	.key_url = HTTP_URL_INIT_EMPTY,
	.key_url_auth = HTTP_URL_INIT_EMPTY,
	.testfilter_new_key = "",
	.deprecated_key = "",
	.removed_key = "",
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

struct test_missing_plugin_settings {
	pool_t pool;
	const char *missing_plugin_key;
};

static const struct setting_define test_missing_plugin_settings_defs[] = {
	{ .type = SET_FILTER_NAME, .key = "missing_plugin" },
	SETTING_DEFINE_STRUCT_STR("missing_plugin_key", missing_plugin_key,
				  struct test_missing_plugin_settings),
	SETTING_DEFINE_LIST_END
};

static const struct test_missing_plugin_settings
test_missing_plugin_settings_defaults = {
	.missing_plugin_key = "",
};

static const struct setting_parser_info test_missing_plugin_settings_info = {
	.name = "test_missing_plugin",
	.plugin_dependency = "lib99_nonexistent_test_plugin",
	.defines = test_missing_plugin_settings_defs,
	.defaults = &test_missing_plugin_settings_defaults,

	.struct_size = sizeof(struct test_missing_plugin_settings),
	.pool_offset1 = 1 + offsetof(struct test_missing_plugin_settings, pool),
};

static void write_config_file(const char *contents)
{
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);
	struct ostream *os = o_stream_create_file(config_file, 0, 0600, 0);
	o_stream_nsend_str(os, contents);
	test_assert(o_stream_finish(os) == 1);
	o_stream_unref(&os);
}

static void test_config_parser(void)
{
	struct config_parsed *config;
	const char *error = NULL;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);

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
"\"@group_name\" = value\n"
	);

	putenv("foo=test1");
	putenv("bar=test2");
	putenv("FOO$ENV:FOO=works");

	test_assert(config_parse_file(config_file,
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
	test_assert_strcmp(set->at_group_name, "value");
	settings_parser_unref(&set_parser);
	config_parsed_free(&config);

	/* try again unexpanded */
	test_assert(config_parse_file(config_file,
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
	test_assert_strcmp(set->at_group_name, "value");

	settings_parser_unref(&set_parser);
	config_parsed_free(&config);
	config_parser_deinit();
	i_unlink_if_exists(config_file);
	pool_unref(&pool);
	test_end();
}

static void test_config_parser_heredoc(void)
{
	static const struct {
		const char *name;
		const char *input;
		/* NULL = expect config_parse_file() to fail */
		const char *output;
	} tests[] = {
		{ "basic",
		  "key = <<EOD\n"
		  "line1\n"
		  "line2\n"
		  "EOD\n",
		  "line1\nline2\n" },
		{ "custom marker",
		  "key = <<MYMARKER\n"
		  "value with EOD inside\n"
		  "MYMARKER\n",
		  "value with EOD inside\n" },
		{ "EODXXX does not terminate",
		  "key = <<EOD\n"
		  "EODXXX\n"
		  "real line\n"
		  "EOD\n",
		  "EODXXX\nreal line\n" },
		{ "missing terminator",
		  "key = <<EOD\n"
		  "line1\n",
		  NULL },
	};
	struct config_parsed *config;
	const char *error;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);
	pool_t pool;
	struct config_filter_parser *global_filter;
	const struct config_module_parser *p;
	struct setting_parser_context *set_parser;
	const struct test_settings *set;

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		test_begin(t_strdup_printf("config_parse_file - heredoc %s",
					   tests[i].name));
		write_config_file(t_strconcat(
			"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n",
			tests[i].input, NULL));
		error = NULL;
		config = NULL;
		if (tests[i].output == NULL) {
			test_assert(config_parse_file(config_file,
					CONFIG_PARSE_FLAG_EXPAND_VALUES |
					CONFIG_PARSE_FLAG_NO_DEFAULTS,
					NULL, &config, &error) < 0);
			test_assert(error != NULL);
		} else {
			test_assert(config_parse_file(config_file,
					CONFIG_PARSE_FLAG_EXPAND_VALUES |
					CONFIG_PARSE_FLAG_NO_DEFAULTS,
					NULL, &config, &error) == 1);
			if (error != NULL)
				i_error("config_parse_file(): %s", error);
			pool = pool_alloconly_create("test settings", 128);
			global_filter =
				config_parsed_get_global_filter_parser(config);
			p = global_filter->module_parsers;
			set_parser = settings_parser_init(pool, p->info, 0);
			config_fill_set_parser(set_parser, p, TRUE);
			set = settings_parser_get_set(set_parser);
			test_assert_strcmp(set->key, tests[i].output);
			settings_parser_unref(&set_parser);
			pool_unref(&pool);
		}
		if (config != NULL)
			config_parsed_free(&config);
		config_parser_deinit();
		i_unlink_if_exists(config_file);
		test_end();
	}
}

static const char *heredoc_marker_got;

static void
test_config_export_callback(const struct config_export_setting *set, void *context ATTR_UNUSED)
{
	if (strcmp(set->key, "key") == 0 && set->heredoc_marker != NULL)
		heredoc_marker_got = set->heredoc_marker;
}

static void test_config_parser_heredoc_marker_preserved(void)
{
	struct config_parsed *config;
	const char *error = NULL;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);

	test_begin("config_parse_file - heredoc marker preserved in export");
	write_config_file(
"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
"key = <<FOO\n"
"line1\n"
"FOO\n"
	);
	test_assert(config_parse_file(config_file,
				      CONFIG_PARSE_FLAG_EXPAND_VALUES |
				      CONFIG_PARSE_FLAG_NO_DEFAULTS,
				      NULL, &config, &error) == 1);
	if (error != NULL)
		i_error("config_parse_file(): %s", error);

	heredoc_marker_got = NULL;
	struct config_filter_parser *global_filter =
		config_parsed_get_global_filter_parser(config);
	struct config_export_context *ectx =
		config_export_init(CONFIG_DUMP_SCOPE_SET, 0,
				   DOVECOT_CONFIG_VERSION, "",
				   test_config_export_callback, NULL);
	config_export_set_module_parsers(ectx, global_filter->module_parsers);
	const char *exp_error;
	for (unsigned int i = 0; i < config_export_get_parser_count(ectx); i++) {
		if (config_export_parser(ectx, i, &exp_error) < 0) {
			i_error("config_export_parser: %s", exp_error);
			break;
		}
	}
	config_export_free(&ectx);
	test_assert_strcmp(heredoc_marker_got, "FOO");

	config_parsed_free(&config);
	config_parser_deinit();
	i_unlink_if_exists(config_file);
	test_end();
}

struct set_file_export_ctx {
	const char *expected_path;
	bool seen;
};

static void
test_config_set_file_export_callback(const struct config_export_setting *set,
				     struct set_file_export_ctx *ctx)
{
	if (strcmp(set->key, "key_file") != 0 || set->value_is_file_inline)
		return;
	ctx->seen = TRUE;
	/* value is "path\nfile_contents" - t_strcut must give just the path */
	test_assert_strcmp(t_strcut(set->value, '\n'), ctx->expected_path);
	test_assert(strchr(set->value, '\n') != NULL);
}

static void test_config_parser_set_file_export_value(void)
{
	struct config_parsed *config;
	const char *error = NULL;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);
	const char *data_file = test_dir_prepend("key_file_data");

	test_begin("config_parse_file - SET_FILE export value format");

	struct ostream *os = o_stream_create_file(data_file, 0, 0600, 0);
	o_stream_nsend_str(os, "file content line\n");
	test_assert(o_stream_finish(os) == 1);
	o_stream_unref(&os);

	write_config_file(t_strdup_printf(
		"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
		"key_file = %s\n", data_file));

	test_assert(config_parse_file(config_file,
				      CONFIG_PARSE_FLAG_EXPAND_VALUES |
				      CONFIG_PARSE_FLAG_NO_DEFAULTS,
				      NULL, &config, &error) == 1);
	if (error != NULL)
		i_error("config_parse_file(): %s", error);

	struct set_file_export_ctx export_ctx = { .expected_path = data_file };
	struct config_filter_parser *global_filter =
		config_parsed_get_global_filter_parser(config);
	struct config_export_context *ectx =
		config_export_init(CONFIG_DUMP_SCOPE_SET, 0,
				   DOVECOT_CONFIG_VERSION, "",
				   test_config_set_file_export_callback,
				   &export_ctx);
	config_export_set_module_parsers(ectx, global_filter->module_parsers);
	const char *exp_error;
	for (unsigned int i = 0; i < config_export_get_parser_count(ectx); i++) {
		if (config_export_parser(ectx, i, &exp_error) < 0) {
			i_error("config_export_parser: %s", exp_error);
			break;
		}
	}
	config_export_free(&ectx);
	test_assert(export_ctx.seen);

	config_parsed_free(&config);
	config_parser_deinit();
	i_unlink_if_exists(config_file);
	i_unlink_if_exists(data_file);
	test_end();
}

struct set_file_inline_export_ctx {
	bool seen;
	bool value_is_file_inline;
	const char *value;
};

static void
test_config_set_file_inline_export_callback(const struct config_export_setting *set,
					    struct set_file_inline_export_ctx *ctx)
{
	if (strcmp(set->key, "key_file") != 0 || !set->value_is_file_inline)
		return;
	ctx->seen = TRUE;
	ctx->value_is_file_inline = set->value_is_file_inline;
	ctx->value = t_strdup(set->value);
}

static void
do_set_file_inline_export(const char *config_content,
			  struct set_file_inline_export_ctx *export_ctx)
{
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);
	struct config_parsed *config;
	const char *error = NULL;

	write_config_file(config_content);
	test_assert(config_parse_file(config_file,
				      CONFIG_PARSE_FLAG_EXPAND_VALUES |
				      CONFIG_PARSE_FLAG_NO_DEFAULTS,
				      NULL, &config, &error) == 1);
	if (error != NULL)
		i_error("config_parse_file(): %s", error);

	struct config_filter_parser *global_filter =
		config_parsed_get_global_filter_parser(config);
	struct config_export_context *ectx =
		config_export_init(CONFIG_DUMP_SCOPE_SET, 0,
				   DOVECOT_CONFIG_VERSION, "",
				   test_config_set_file_inline_export_callback,
				   export_ctx);
	config_export_set_module_parsers(ectx, global_filter->module_parsers);
	const char *exp_error;
	for (unsigned int i = 0; i < config_export_get_parser_count(ectx); i++) {
		if (config_export_parser(ectx, i, &exp_error) < 0) {
			i_error("config_export_parser: %s", exp_error);
			break;
		}
	}
	config_export_free(&ectx);
	config_parsed_free(&config);
	config_parser_deinit();
	i_unlink_if_exists(config_file);
}

static void test_config_parser_set_file_inline_export(void)
{
	test_begin("config_parse_file - SET_FILE inline export");

	/* inline: without trailing newline: value stored as \n<content> */
	struct set_file_inline_export_ctx ctx1 = { 0 };
	do_set_file_inline_export(
		"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
		"key_file = inline:some content\n",
		&ctx1);
	test_assert(ctx1.seen);
	test_assert(ctx1.value_is_file_inline);
	test_assert_strcmp(ctx1.value, "\nsome content");

	/* heredoc for SET_FILE: value has trailing newline, also inline */
	struct set_file_inline_export_ctx ctx2 = { 0 };
	do_set_file_inline_export(
		"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
		"key_file = <<EOD\n"
		"some content\n"
		"EOD\n",
		&ctx2);
	test_assert(ctx2.seen);
	test_assert(ctx2.value_is_file_inline);
	test_assert_strcmp(ctx2.value, "\nsome content\n");

	/* empty inline: must also export with value_is_file_inline=TRUE */
	struct set_file_inline_export_ctx ctx3 = { 0 };
	do_set_file_inline_export(
		"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
		"key_file = inline:\n",
		&ctx3);
	test_assert(ctx3.seen);
	test_assert(ctx3.value_is_file_inline);
	test_assert_strcmp(ctx3.value, "\n");

	/* inline: via $ENV: with multiline content (no trailing newline) */
	setenv("TEST_SSL_KEY",
	       "inline:-----BEGIN EC PARAMETERS-----\n"
	       "BgUrgQQAIg==\n"
	       "-----END EC PARAMETERS-----", 1);
	struct set_file_inline_export_ctx ctx4 = { 0 };
	do_set_file_inline_export(
		"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
		"key_file = $ENV:TEST_SSL_KEY\n",
		&ctx4);
	test_assert(ctx4.seen);
	test_assert(ctx4.value_is_file_inline);
	test_assert_strcmp(ctx4.value,
		"\n-----BEGIN EC PARAMETERS-----\n"
		"BgUrgQQAIg==\n"
		"-----END EC PARAMETERS-----");
	unsetenv("TEST_SSL_KEY");

	test_end();
}

static void test_config_parser_heredoc_in_strlist(void)
{
	struct config_parsed *config;
	const char *error = NULL;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);

	test_begin("config_parse_file - heredoc in strlist is rejected");
	write_config_file(
"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
"key_strlist/entry1 = <<EOD\n"
"somevalue\n"
"EOD\n"
	);
	error = NULL;
	test_assert(config_parse_file(config_file,
				      CONFIG_PARSE_FLAG_EXPAND_VALUES |
				      CONFIG_PARSE_FLAG_NO_DEFAULTS,
				      NULL, &config, &error) < 0);
	test_assert(error != NULL);
	test_assert(strstr(error, "Heredoc syntax is not supported for list settings") != NULL);
	if (config != NULL)
		config_parsed_free(&config);
	config_parser_deinit();
	i_unlink_if_exists(config_file);
	test_end();
}

static void test_config_parser_str_novars_var_expand(void)
{
	struct config_parsed *config;
	const char *error = NULL;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);

	test_begin("config_parse_file - STR_NOVARS var-expand syntax is checked");
	write_config_file(
"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
"key_novars = %{unclosed\n"
	);
	test_assert(config_parse_file(config_file,
				      CONFIG_PARSE_FLAG_EXPAND_VALUES |
				      CONFIG_PARSE_FLAG_NO_DEFAULTS,
				      NULL, &config, &error) < 0);
	test_assert(error != NULL);
	if (error != NULL) {
		test_assert(strstr(error, "key_novars") != NULL);
		test_assert(strstr(error, "syntax error") != NULL);
	}
	if (config != NULL)
		config_parsed_free(&config);
	config_parser_deinit();
	i_unlink_if_exists(config_file);
	test_end();

	/* a valid var-expand template must still be accepted */
	test_begin("config_parse_file - STR_NOVARS valid var-expand is accepted");
	write_config_file(
"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
"key_novars = %{user | lower}\n"
	);
	error = NULL;
	test_assert(config_parse_file(config_file,
				      CONFIG_PARSE_FLAG_EXPAND_VALUES |
				      CONFIG_PARSE_FLAG_NO_DEFAULTS,
				      NULL, &config, &error) == 1);
	if (error != NULL)
		i_error("config_parse_file(): %s", error);
	if (config != NULL)
		config_parsed_free(&config);
	config_parser_deinit();
	i_unlink_if_exists(config_file);
	test_end();
}

static void test_config_parser_missing_plugin(void)
{
	static const struct {
		const char *config;
		const char *error;
	} tests[] = {
		{ "missing_plugin_key = foo\n",
		  "Unknown setting: missing_plugin_key (Setting missing_plugin_key requires plugin "MODULEDIR"/lib99_nonexistent_test_plugin"MODULE_SUFFIX", which isn't installed)" },
		{ "missing_plugin {\n}\n",
		  "Unknown section name: missing_plugin (Setting missing_plugin requires plugin "MODULEDIR"/lib99_nonexistent_test_plugin"MODULE_SUFFIX", which isn't installed)" },
		{ "missing_plugin {\n  key = foo\n}\n",
		  "Unknown section name: missing_plugin (Setting missing_plugin requires plugin "MODULEDIR"/lib99_nonexistent_test_plugin"MODULE_SUFFIX", which isn't installed)" },
		{ "unknown_key = foo\n",
		  "Unknown setting: unknown_key" },
	};
	static const struct setting_parser_info *const test_infos[] = {
		&test_settings_info,
		&test_missing_plugin_settings_info,
		NULL
	};
	const struct setting_parser_info *const *orig_all_infos = all_infos;
	ARRAY_TYPE(setting_parser_info_p) available_infos;
	struct config_parsed *config;
	const char *error;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		test_begin(t_strdup_printf(
			"config_parse_file - missing plugin hint %u", i));
		all_infos = test_infos;
		t_array_init(&available_infos, 4);
		config_parser_add_available_infos(&available_infos);
		test_assert(array_count(&available_infos) == 1);
		array_append_zero(&available_infos);
		all_infos = array_front(&available_infos);

		write_config_file(t_strconcat(
			"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n",
			tests[i].config, NULL));
		error = NULL;
		test_assert_idx(config_parse_file(config_file,
				CONFIG_PARSE_FLAG_NO_DEFAULTS,
				NULL, &config, &error) < 0, i);
		test_assert_idx(error != NULL &&
				str_ends_with(error, tests[i].error), i);
		if (error != NULL && !str_ends_with(error, tests[i].error))
			i_error("config_parse_file(): %s", error);
		if (config != NULL)
			config_parsed_free(&config);
		config_parser_deinit();
		all_infos = orig_all_infos;
		i_unlink_if_exists(config_file);
		test_end();
	}
}

static void test_config_parser_nested_local_name(void)
{
	static const struct {
		const char *config;
		/* NULL = parsing succeeds */
		const char *error;
	} tests[] = {
		/* the inner name narrows the outer name */
		{ "local_name *.example.com {\n"
		  "  local_name imap.example.com {\n"
		  "    key = foo\n"
		  "  }\n"
		  "}\n", NULL },
		{ "local_name *.example.com {\n"
		  "  local_name IMAP.EXAMPLE.COM {\n"
		  "    key = foo\n"
		  "  }\n"
		  "}\n", NULL },
		{ "local_name imap.example.com {\n"
		  "  local_name imap.example.com {\n"
		  "    key = foo\n"
		  "  }\n"
		  "}\n", NULL },
		/* the inner name doesn't match the outer name */
		{ "local_name *.example.com {\n"
		  "  local_name imap.example.org {\n"
		  "    key = foo\n"
		  "  }\n"
		  "}\n", "requires name2 to be a hostname matching name1" },
		{ "local_name *.example.com {\n"
		  "  local_name sub.imap.example.com {\n"
		  "    key = foo\n"
		  "  }\n"
		  "}\n", "requires name2 to be a hostname matching name1" },
		/* the inner name is a wildcard */
		{ "local_name *.example.com {\n"
		  "  local_name *.example.com {\n"
		  "    key = foo\n"
		  "  }\n"
		  "}\n", "requires name2 to be a hostname matching name1" },
		{ "local_name imap.example.com {\n"
		  "  local_name *.example.com {\n"
		  "    key = foo\n"
		  "  }\n"
		  "}\n", "requires name2 to be a hostname matching name1" },
	};
	struct config_parsed *config;
	const char *error;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);

	for (unsigned int i = 0; i < N_ELEMENTS(tests); i++) {
		test_begin(t_strdup_printf(
			"config_parse_file - nested local_name %u", i));
		write_config_file(t_strconcat(
			"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n",
			tests[i].config, NULL));
		error = NULL;
		config = NULL;
		int ret = config_parse_file(config_file,
					    CONFIG_PARSE_FLAG_NO_DEFAULTS,
					    NULL, &config, &error);
		if (tests[i].error == NULL) {
			test_assert_idx(ret == 1, i);
			if (error != NULL)
				i_error("config_parse_file(): %s", error);
		} else {
			test_assert_idx(ret < 0, i);
			test_assert_idx(error != NULL &&
					strstr(error, tests[i].error) != NULL, i);
			if (error != NULL && strstr(error, tests[i].error) == NULL)
				i_error("config_parse_file(): %s", error);
		}
		if (config != NULL)
			config_parsed_free(&config);
		i_unlink_if_exists(config_file);
		test_end();
	}
}

struct http_url_export_ctx {
	pool_t pool;
	const char *key;
	const char *value; /* NULL until the key is seen */
};

static void
test_config_http_url_export_callback(const struct config_export_setting *set,
				     struct http_url_export_ctx *ctx)
{
	/* set->value points into a buffer owned by the export callback's
	   own temporary-memory frame, so it must be copied into a pool that
	   outlives config_export_parser() before returning it to the
	   caller. */
	if (strcmp(set->key, ctx->key) == 0)
		ctx->value = p_strdup(ctx->pool, set->value);
}

/* Export "key" from global_filter under the given scope and return the
   value config_export_parser() produced for it, or NULL if it was never
   dumped. The returned string is allocated from "pool". */
static const char *
test_config_http_url_export(pool_t pool,
			    struct config_filter_parser *global_filter,
			    enum config_dump_scope scope, const char *key)
{
	struct http_url_export_ctx export_ctx = { .pool = pool, .key = key };
	struct config_export_context *ectx =
		config_export_init(scope, 0, DOVECOT_CONFIG_VERSION, "",
				   test_config_http_url_export_callback,
				   &export_ctx);
	config_export_set_module_parsers(ectx, global_filter->module_parsers);
	const char *exp_error;
	for (unsigned int i = 0; i < config_export_get_parser_count(ectx); i++) {
		if (config_export_parser(ectx, i, &exp_error) < 0) {
			i_error("config_export_parser: %s", exp_error);
			break;
		}
	}
	config_export_free(&ectx);
	return export_ctx.value;
}

enum http_url_roundtrip_extra {
	HTTP_URL_EXTRA_NONE,
	/* a path-less URL must not be reported empty by
	   config_export_type(), which is the only place
	   http_url_is_empty() gates a stringification. */
	HTTP_URL_EXTRA_PATHLESS,
	/* an explicitly-set value's export must keep userinfo. It
	   never goes through config_export_type()/http_url_create(),
	   which would drop it (see config-request.c's settings_export()). */
	HTTP_URL_EXTRA_CREDENTIALS,
};

struct http_url_roundtrip_test {
	const char *name;
	const char *key;
	const char *config_value;
	const char *expected_export;
	enum http_url_roundtrip_extra extra;
};

static const struct http_url_roundtrip_test http_url_roundtrip_tests[] = {
	/* full URL with path and query round-trips byte-identical */
	{ "full URL with path and query", "key_url",
	  "https://host/path?q=1", "https://host/path?q=1",
	  HTTP_URL_EXTRA_NONE },
	/* path-less URL is set, not empty, and exports unchanged */
	{ "path-less URL", "key_url",
	  "http://host", "http://host",
	  HTTP_URL_EXTRA_PATHLESS },
	/* an explicitly empty value exports as "" */
	{ "explicitly empty", "key_url", "", "",
	  HTTP_URL_EXTRA_NONE },
	/* a %{variable} is not touched by config and survives export */
	{ "unexpanded %{variable}", "key_url",
	  "https://%{user}.example.com/", "https://%{user}.example.com/",
	  HTTP_URL_EXTRA_NONE },
	/* SET_HTTP_URL_AUTH keeps userinfo on the raw-string path */
	{ "userinfo credentials", "key_url_auth",
	  "https://u:p@host/x", "https://u:p@host/x",
	  HTTP_URL_EXTRA_CREDENTIALS },
};

static void test_config_parser_http_url_roundtrip(void)
{
	for (unsigned int i = 0; i < N_ELEMENTS(http_url_roundtrip_tests); i++) {
		const struct http_url_roundtrip_test *test =
			&http_url_roundtrip_tests[i];
		struct config_parsed *config;
		const char *error = NULL;
		const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);

		test_begin(t_strdup_printf(
			"config_parse_file - SET_HTTP_URL round-trip: %s",
			test->name));

		write_config_file(t_strdup_printf(
			"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
			"%s = %s\n", test->key, test->config_value));
		test_assert(config_parse_file(config_file,
					      CONFIG_PARSE_FLAG_EXPAND_VALUES |
					      CONFIG_PARSE_FLAG_NO_DEFAULTS,
					      NULL, &config, &error) == 1);
		if (error != NULL)
			i_error("config_parse_file(): %s", error);

		pool_t pool = pool_alloconly_create("http url roundtrip", 1024);
		struct config_filter_parser *global_filter =
			config_parsed_get_global_filter_parser(config);
		const struct config_module_parser *p = global_filter->module_parsers;
		struct setting_parser_context *set_parser =
			settings_parser_init(pool, p->info, 0);
		config_fill_set_parser(set_parser, p, TRUE);
		struct test_settings *set1 = settings_parser_get_set(set_parser);

		const char *exported = test_config_http_url_export(
			pool, global_filter, CONFIG_DUMP_SCOPE_SET, test->key);
		test_assert_strcmp_idx(exported, test->expected_export, i);

		/* Third leg: feed the exported string back through
		   settings_parse_keyvalue() and assert the result matches
		   the originally parsed struct. */
		pool_t pool2 = pool_alloconly_create("http url roundtrip 2", 1024);
		struct setting_parser_context *set_parser2 =
			settings_parser_init(pool2, p->info, 0);
		test_assert_idx(settings_parse_keyvalue(set_parser2, test->key,
							exported) == 1, i);
		struct test_settings *set2 = settings_parser_get_set(set_parser2);
		test_assert_idx(settings_equal(p->info, set1, set2, NULL), i);
		settings_parser_unref(&set_parser2);
		pool_unref(&pool2);

		switch (test->extra) {
		case HTTP_URL_EXTRA_NONE:
			break;
		case HTTP_URL_EXTRA_PATHLESS: {
			string_t *export_type_str = t_str_new(64);
			test_assert_idx(config_export_type(export_type_str,
				&set1->key_url, SET_HTTP_URL), i);
			pool_t pool3 = pool_alloconly_create("http url roundtrip 3", 128);
			struct setting_parser_context *set_parser3 =
				settings_parser_init(pool3, p->info, 0);
			test_assert_idx(settings_parse_keyvalue(set_parser3,
				test->key, str_c(export_type_str)) == 1, i);
			struct test_settings *set3 =
				settings_parser_get_set(set_parser3);
			test_assert_idx(!http_url_is_empty(&set3->key_url), i);
			settings_parser_unref(&set_parser3);
			pool_unref(&pool3);
			break;
		}
		case HTTP_URL_EXTRA_CREDENTIALS:
			/* Credentials must survive on the raw-passthrough
			   export path, since that is the only path an
			   explicitly-set value takes (config_export_type(),
			   which stringifies via http_url_create(), is never
			   reached here - see config-request.c's
			   settings_export()). */
			test_assert_idx(strstr(exported, "u:p@") != NULL, i);
			break;
		}

		settings_parser_unref(&set_parser);
		pool_unref(&pool);
		config_parsed_free(&config);
		config_parser_deinit();
		i_unlink_if_exists(config_file);
		test_end();
	}
}

static void test_config_parser_http_url_default_unset(void)
{
	/* an unset SET_HTTP_URL exports as "" under a scope that dumps
	   defaults. "key" must also be set so that this info's
	   change_counters array isn't NULL (it stays NULL until the first
	   setting in the info is changed). */
	struct config_parsed *config;
	const char *error = NULL;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);

	test_begin("config_parse_file - SET_HTTP_URL unset exports as \"\"");
	write_config_file(
"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
"key = value\n"
	);
	test_assert(config_parse_file(config_file,
				      CONFIG_PARSE_FLAG_EXPAND_VALUES |
				      CONFIG_PARSE_FLAG_NO_DEFAULTS,
				      NULL, &config, &error) == 1);
	if (error != NULL)
		i_error("config_parse_file(): %s", error);

	pool_t pool = pool_alloconly_create("http url default export", 128);
	struct config_filter_parser *global_filter =
		config_parsed_get_global_filter_parser(config);
	const char *exported = test_config_http_url_export(
		pool, global_filter, CONFIG_DUMP_SCOPE_ALL_WITH_HIDDEN, "key_url");
	test_assert_strcmp(exported, "");
	pool_unref(&pool);

	config_parsed_free(&config);
	config_parser_deinit();
	i_unlink_if_exists(config_file);
	test_end();
}

static void test_config_parser_http_url_parse_error(void)
{
	/* an unparsable URL fails config_parse_file() itself. */
	struct config_parsed *config;
	const char *error = NULL;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);

	test_begin("config_parse_file - SET_HTTP_URL parse error is rejected");
	write_config_file(
"dovecot_config_version = "DOVECOT_CONFIG_VERSION"\n"
"key_url = ::: not a url\n"
	);
	test_assert(config_parse_file(config_file,
				      CONFIG_PARSE_FLAG_EXPAND_VALUES |
				      CONFIG_PARSE_FLAG_NO_DEFAULTS,
				      NULL, &config, &error) < 0);
	test_assert(error != NULL);
	if (config != NULL)
		config_parsed_free(&config);
	config_parser_deinit();
	i_unlink_if_exists(config_file);
	test_end();
}

/* Oldest config version that is still accepted. */
#ifdef DOVECOT_PRO_EDITION
#  define TEST_OLD_CONFIG_VERSION "3.1.0"
#else
#  define TEST_OLD_CONFIG_VERSION "2.4.0"
#endif

#define TEST_HISTORY_CONFIG_PREFIX \
	"dovecot_config_version = "TEST_OLD_CONFIG_VERSION"\n"

static const struct setting_history_rename test_history_renames[] = {
	/* Renamed in a version that is always newer than the config's. */
	{ "testfilter_old_key", "testfilter/new_key", "9999.0.0" }
};
static const struct setting_history_deprecate test_history_deprecates[] = {
	/* Deprecated, but still supported by the config's version. */
	{ "deprecated_key", "9999.0.0" },
	/* Already removed before the config's version. */
	{ "removed_key", "0.0.1" }
};

static void test_history_register(void)
{
	static bool registered = FALSE;

	if (registered)
		return;
	registered = TRUE;
	settings_history_register_renames(test_history_renames,
					  N_ELEMENTS(test_history_renames));
	settings_history_register_deprecates(test_history_deprecates,
					     N_ELEMENTS(test_history_deprecates));
}

static int
test_history_config_parse(const char *config_file, struct config_parsed **config_r,
			  const char **error_r)
{
	*error_r = NULL;
	return config_parse_file(config_file,
				 CONFIG_PARSE_FLAG_EXPAND_VALUES |
				 CONFIG_PARSE_FLAG_NO_DEFAULTS |
				 CONFIG_PARSE_FLAG_HIDE_OBSOLETE_WARNINGS,
				 NULL, config_r, error_r);
}

static const struct test_settings *
test_history_config_get(struct config_parsed *config, pool_t pool,
			struct setting_parser_context **set_parser_r)
{
	struct config_filter_parser *global_filter =
		config_parsed_get_global_filter_parser(config);
	const struct config_module_parser *p = global_filter->module_parsers;

	*set_parser_r = settings_parser_init(pool, p->info, 0);
	config_fill_set_parser(*set_parser_r, p, TRUE);
	return settings_parser_get_set(*set_parser_r);
}

static void test_config_parser_history_rename(void)
{
	/* All of these set the renamed testfilter_new_key setting. */
	const char *const configs[] = {
		"testfilter_old_key = value\n",
		"testfilter {\n"
		"  old_key = value\n"
		"}\n",
		"testfilter {\n"
		"  testfilter_old_key = value\n"
		"}\n"
	};
	struct config_parsed *config;
	struct setting_parser_context *set_parser;
	const char *error;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);
	pool_t pool = pool_alloconly_create("test settings", 256);

	test_begin("config_parse_file - settings history rename");
	test_history_register();

	for (unsigned int i = 0; i < N_ELEMENTS(configs); i++) {
		write_config_file(t_strconcat(TEST_HISTORY_CONFIG_PREFIX,
					      configs[i], NULL));
		test_assert_idx(test_history_config_parse(config_file, &config,
							  &error) == 1, i);
		if (error != NULL) {
			i_error("config_parse_file(): %s", error);
			continue;
		}
		p_clear(pool);
		const struct test_settings *set =
			test_history_config_get(config, pool, &set_parser);
		test_assert_strcmp_idx(set->testfilter_new_key, "value", i);
		settings_parser_unref(&set_parser);
		config_parsed_free(&config);
		config_parser_deinit();
	}
	i_unlink_if_exists(config_file);
	pool_unref(&pool);
	test_end();
}

static void test_config_parser_history_deprecate(void)
{
	struct config_parsed *config = NULL;
	struct setting_parser_context *set_parser;
	const char *error;
	const char *config_file = test_dir_prepend(TEST_CONFIG_FILE);
	pool_t pool = pool_alloconly_create("test settings", 256);

	test_begin("config_parse_file - settings history deprecate");
	test_history_register();

	/* The setting is deprecated, but still supported by the config
	   version. */
	write_config_file(TEST_HISTORY_CONFIG_PREFIX
			  "deprecated_key = value\n");
	test_assert(test_history_config_parse(config_file, &config,
					      &error) == 1);
	if (error != NULL)
		i_error("config_parse_file(): %s", error);
	else {
		const struct test_settings *set =
			test_history_config_get(config, pool, &set_parser);
		test_assert_strcmp(set->deprecated_key, "value");
		settings_parser_unref(&set_parser);
		config_parsed_free(&config);
	}
	config_parser_deinit();

	/* The setting was already removed in the config version, so it is
	   handled as an unknown setting. */
	config = NULL;
	write_config_file(TEST_HISTORY_CONFIG_PREFIX
			  "removed_key = value\n");
	test_assert(test_history_config_parse(config_file, &config,
					      &error) < 0);
	test_assert(error != NULL &&
		    strstr(error, "Unknown setting: removed_key") != NULL);
	if (config != NULL)
		config_parsed_free(&config);
	config_parser_deinit();

	i_unlink_if_exists(config_file);
	pool_unref(&pool);
	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_config_parser,
		test_config_parser_heredoc,
		test_config_parser_heredoc_marker_preserved,
		test_config_parser_set_file_export_value,
		test_config_parser_set_file_inline_export,
		test_config_parser_heredoc_in_strlist,
		test_config_parser_str_novars_var_expand,
		test_config_parser_missing_plugin,
		test_config_parser_nested_local_name,
		test_config_parser_http_url_roundtrip,
		test_config_parser_http_url_default_unset,
		test_config_parser_http_url_parse_error,
		test_config_parser_history_rename,
		test_config_parser_history_deprecate,
		NULL
	};

	test_dir_init("config-parser");
	return test_run(test_functions);
}
