/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "settings.h"
#include "istream.h"
#include "ostream.h"
#include "test-common.h"

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

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_settings_read_nosection,
		NULL
	};
	return test_run(test_functions);
}
