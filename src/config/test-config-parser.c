/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ostream.h"
#include "service-settings.h"
#include "settings-parser.h"
#include "config-filter.h"
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
	ARRAY_TYPE(const_string) key_strlist;
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
	SETTING_DEFINE_STRUCT_STRLIST("key_strlist", key_strlist, struct test_settings),
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

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_config_parser,
		test_config_parser_heredoc,
		test_config_parser_heredoc_marker_preserved,
		test_config_parser_set_file_export_value,
		test_config_parser_set_file_inline_export,
		test_config_parser_heredoc_in_strlist,
		NULL
	};

	test_dir_init("config-parser");
	return test_run(test_functions);
}
