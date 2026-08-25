/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "settings-parser-http-url.h"
#include "http-url.h"
#include "test-common.h"

static const char *const test_settings_blobs[] =
{
/* Blob 0 */
	"bool_true", "yes",
	"bool_false", "no",
	"uintmax_max", "18446744073709551615",
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
	"uintmax_max", "",
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
		uintmax_t uintmax_max;
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
		0,
		"",
		"",
		ARRAY_INIT,
	};
	const struct setting_define defs[] = {
		SETTING_DEFINE_STRUCT_BOOL("bool_true", bool_true, struct test_settings),
		SETTING_DEFINE_STRUCT_BOOL("bool_false", bool_false, struct test_settings),
		SETTING_DEFINE_STRUCT_UINTMAX("uintmax_max", uintmax_max, struct test_settings),
		SETTING_DEFINE_STRUCT_UINT("uint", uint, struct test_settings),
		{ .type = SET_UINT_OCT, .key = "uint_oct",
		  .offset = offsetof(struct test_settings, uint_oct) },
		SETTING_DEFINE_STRUCT_TIME("secs", secs, struct test_settings),
		SETTING_DEFINE_STRUCT_TIME_MSECS("msecs", msecs, struct test_settings),
		SETTING_DEFINE_STRUCT_SIZE("size", size, struct test_settings),
		SETTING_DEFINE_STRUCT_IN_PORT("port", port, struct test_settings),
		SETTING_DEFINE_STRUCT_STR_NOVARS("str", str, struct test_settings),
		{ .type = SET_STR, .key = "expand_str",
		  .offset = offsetof(struct test_settings, expand_str) },
		{ .type = SET_STRLIST, .key = "strlist",
		  .offset = offsetof(struct test_settings, strlist) },
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
	test_assert(settings->uintmax_max == 18446744073709551615ULL);
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
		array_foreach_elem(&output, value) {
			const char *next_output = NULL;
			if (tests[i].output != NULL &&
			    tests[i].output[j] != NULL)
				next_output = tests[i].output[j++];
			test_assert_strcmp_idx(next_output, value, i);
		}
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

struct test_settings {
	bool b;
	unsigned int i;
	uoff_t size;
	in_port_t port;
	const char *str;
	const char *file;
	ARRAY_TYPE(const_string) strlist;
};

static void test_settings_hash_equals(void)
{
#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct test_settings)
	const struct setting_define defines[] = {
		DEF(BOOL, b),
		DEF(UINT, i),
		DEF(SIZE, size),
		DEF(IN_PORT, port),
		DEF(STR, str),
		DEF(FILE, file),
		DEF(STRLIST, strlist),

		SETTING_DEFINE_LIST_END
	};
	const struct setting_parser_info info = {
		.defines = defines,
	};
	struct test_settings set1 = {
		.str = "",
		.file = "\n",
	};
	struct test_settings set2 = set1;

	test_begin("settings_hash() and settings_equal()");

	test_assert(settings_equal(&info, &set1, &set2, NULL));

	/* boolean */
	set1.b = TRUE;
	test_assert(settings_hash(&info, &set1, NULL) !=
		    settings_hash(&info, &set2, NULL));
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	set2.b = TRUE;
	test_assert(settings_hash(&info, &set1, NULL) ==
		    settings_hash(&info, &set2, NULL));
	test_assert(settings_equal(&info, &set1, &set2, NULL));

	/* uint */
	set1.i = 1234567;
	set2.i = 1234568;
	test_assert(settings_hash(&info, &set1, NULL) !=
		    settings_hash(&info, &set2, NULL));
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	set2.i = 1234567;
	test_assert(settings_hash(&info, &set1, NULL) ==
		    settings_hash(&info, &set2, NULL));
	test_assert(settings_equal(&info, &set1, &set2, NULL));

	/* size */
	set1.size = 0x500000000ULL;
	set2.size = 0x600000000ULL;
	test_assert(settings_hash(&info, &set1, NULL) !=
		    settings_hash(&info, &set2, NULL));
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	set2.size = 0x500000000ULL;
	test_assert(settings_hash(&info, &set1, NULL) ==
		    settings_hash(&info, &set2, NULL));
	test_assert(settings_equal(&info, &set1, &set2, NULL));

	/* port */
	set1.port = 65535;
	set2.port = 65534;
	test_assert(settings_hash(&info, &set1, NULL) !=
		    settings_hash(&info, &set2, NULL));
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	set2.port = 65535;
	test_assert(settings_hash(&info, &set1, NULL) ==
		    settings_hash(&info, &set2, NULL));
	test_assert(settings_equal(&info, &set1, &set2, NULL));

	/* string */
	set1.str = "foo1";
	set2.str = "foo2";
	test_assert(settings_hash(&info, &set1, NULL) !=
		    settings_hash(&info, &set2, NULL));
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	set2.str = "foo1";
	test_assert(settings_hash(&info, &set1, NULL) ==
		    settings_hash(&info, &set2, NULL));
	test_assert(settings_equal(&info, &set1, &set2, NULL));

	/* file with filename */
	set1.file = "fname\ncontent";
	set2.file = "fname2\ncontent";
	test_assert(settings_hash(&info, &set1, NULL) !=
		    settings_hash(&info, &set2, NULL));
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	set2.file = "fname\ncontent-with-different";
	test_assert(settings_hash(&info, &set1, NULL) ==
		    settings_hash(&info, &set2, NULL));
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	set2.file = "fname\ncontent";
	test_assert(settings_hash(&info, &set1, NULL) ==
		    settings_hash(&info, &set2, NULL));
	test_assert(settings_equal(&info, &set1, &set2, NULL));

	/* file without filename */
	set1.file = "\ncontent";
	set2.file = "\ncontent2";
	test_assert(settings_hash(&info, &set1, NULL) !=
		    settings_hash(&info, &set2, NULL));
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	set2.file = "\ncontent";
	test_assert(settings_hash(&info, &set1, NULL) ==
		    settings_hash(&info, &set2, NULL));
	test_assert(settings_equal(&info, &set1, &set2, NULL));

	/* string list */
	const char *str;
	t_array_init(&set1.strlist, 4);
	str = "list1"; array_push_back(&set1.strlist, &str);
	str = "list2"; array_push_back(&set1.strlist, &str);
	str = "list3"; array_push_back(&set1.strlist, &str);
	str = "list4"; array_push_back(&set1.strlist, &str);
	t_array_init(&set2.strlist, 4);
	str = "list1"; array_push_back(&set2.strlist, &str);
	str = "list2"; array_push_back(&set2.strlist, &str);
	test_assert(settings_hash(&info, &set1, NULL) !=
		    settings_hash(&info, &set2, NULL));
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	str = "list3"; array_push_back(&set2.strlist, &str);
	str = "list4"; array_push_back(&set2.strlist, &str);
	test_assert(settings_hash(&info, &set1, NULL) ==
		    settings_hash(&info, &set2, NULL));
	test_assert(settings_equal(&info, &set1, &set2, NULL));

	/* test exceptions */
	const char *const except_fields1[] = { "b", NULL };
	set1.b = FALSE;
	test_assert(settings_hash(&info, &set1, NULL) !=
		    settings_hash(&info, &set2, NULL));
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	test_assert(settings_hash(&info, &set1, except_fields1) ==
		    settings_hash(&info, &set2, except_fields1));
	test_assert(settings_equal(&info, &set1, &set2, except_fields1));

	const char *const except_fields2[] = { "b", "i", NULL };
	set1.i = 3535;
	test_assert(settings_hash(&info, &set1, except_fields1) !=
		    settings_hash(&info, &set2, except_fields1));
	test_assert(!settings_equal(&info, &set1, &set2, except_fields1));
	test_assert(settings_hash(&info, &set1, except_fields2) ==
		    settings_hash(&info, &set2, except_fields2));
	test_assert(settings_equal(&info, &set1, &set2, except_fields2));

	test_end();
}

struct http_url_test_settings {
	struct http_url url;
	struct http_url url_auth;
};

static void test_settings_parser_http_url(void)
{
	struct http_url_test_settings test_defaults;
	const struct setting_define defs[] = {
		SETTING_DEFINE_STRUCT_HTTP_URL("url", url,
			struct http_url_test_settings),
		SETTING_DEFINE_STRUCT_HTTP_URL_AUTH("url_auth", url_auth,
			struct http_url_test_settings),
		SETTING_DEFINE_LIST_END
	};
	const struct setting_parser_info root = {
		.name = "http_url_test",
		.defines = defs,
		.defaults = &test_defaults,
		.struct_size = sizeof(struct http_url_test_settings),
	};
	struct http_url_test_settings *set;
	pool_t pool;
	struct setting_parser_context *ctx;

	i_zero(&test_defaults);

	test_begin("settings_parse() SET_HTTP_URL / SET_HTTP_URL_AUTH");

	/* full URL with userinfo parses into a SET_HTTP_URL_AUTH member */
	pool = pool_alloconly_create("http url test", 1024);
	ctx = settings_parser_init(pool, &root, 0);
	test_assert(settings_parse_keyvalue(ctx, "url_auth",
		"https://u:p@h:8080/a/b?q=1") == 1);
	set = settings_parser_get_set(ctx);
	test_assert_strcmp(set->url_auth.host.name, "h");
	test_assert(set->url_auth.port == 8080);
	test_assert(set->url_auth.have_ssl);
	test_assert_strcmp(set->url_auth.path, "/a/b");
	test_assert_strcmp(set->url_auth.enc_query, "q=1");
	test_assert_strcmp(set->url_auth.user, "u");
	test_assert_strcmp(set->url_auth.password, "p");
	settings_parser_unref(&ctx);
	pool_unref(&pool);

	/* the same value on a plain SET_HTTP_URL member is rejected -
	   userinfo is not allowed there */
	pool = pool_alloconly_create("http url test", 1024);
	ctx = settings_parser_init(pool, &root, 0);
	test_assert(settings_parse_keyvalue(ctx, "url",
		"https://u:p@h:8080/a/b?q=1") < 0);
	test_assert_strcmp(settings_parser_get_error(ctx),
		"HTTP URL does not allow `userinfo@' part");
	settings_parser_unref(&ctx);
	pool_unref(&pool);

	/* a URL with no path is set, not empty, and path stays NULL */
	pool = pool_alloconly_create("http url test", 1024);
	ctx = settings_parser_init(pool, &root, 0);
	test_assert(settings_parse_keyvalue(ctx, "url", "http://host") == 1);
	set = settings_parser_get_set(ctx);
	test_assert(!http_url_is_empty(&set->url));
	test_assert(set->url.path == NULL);
	settings_parser_unref(&ctx);
	pool_unref(&pool);

	/* an empty value means unset, not a parse error */
	pool = pool_alloconly_create("http url test", 1024);
	ctx = settings_parser_init(pool, &root, 0);
	test_assert(settings_parse_keyvalue(ctx, "url", "") == 1);
	set = settings_parser_get_set(ctx);
	test_assert(http_url_is_empty(&set->url));
	settings_parser_unref(&ctx);
	pool_unref(&pool);

	/* the set_value_unknown sentinel means unset, not a parse error */
	pool = pool_alloconly_create("http url test", 1024);
	ctx = settings_parser_init(pool, &root, 0);
	test_assert(settings_parse_keyvalue_nodup(ctx, "url",
		set_value_unknown) == 1);
	set = settings_parser_get_set(ctx);
	test_assert(http_url_is_empty(&set->url));
	settings_parser_unref(&ctx);
	pool_unref(&pool);

	/* a literal %{variable} means unset, not a parse error */
	pool = pool_alloconly_create("http url test", 1024);
	ctx = settings_parser_init(pool, &root, 0);
	test_assert(settings_parse_keyvalue(ctx, "url",
		"https://%{user}.example.com/") == 1);
	set = settings_parser_get_set(ctx);
	test_assert(http_url_is_empty(&set->url));
	settings_parser_unref(&ctx);
	pool_unref(&pool);

	test_end();
}

struct http_url_hash_settings {
	struct http_url url;
};

static void test_settings_equal_http_url_differs(void)
{
	const struct setting_define defines[] = {
		SETTING_DEFINE_STRUCT_HTTP_URL_AUTH("url", url,
			struct http_url_hash_settings),
		SETTING_DEFINE_LIST_END
	};
	const struct setting_parser_info info = {
		.defines = defines,
	};
	struct http_url_hash_settings set1, set2;

	test_begin("settings_hash() and settings_equal() for differing SET_HTTP_URL");

	i_zero(&set1);
	set1.url.host.name = "host";
	set1.url.port = 80;
	set1.url.user = "u";
	set1.url.password = "p1";
	set1.url.enc_query = "q=1";
	set2 = set1;

	test_assert(settings_equal(&info, &set1, &set2, NULL));
	test_assert(settings_hash(&info, &set1, NULL) ==
		    settings_hash(&info, &set2, NULL));

	/* differ only in password */
	set2.url.password = "p2";
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	test_assert(settings_hash(&info, &set1, NULL) !=
		    settings_hash(&info, &set2, NULL));
	set2.url.password = set1.url.password;

	/* differ only in enc_query */
	set2.url.enc_query = "q=2";
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	set2.url.enc_query = set1.url.enc_query;

	/* differ only in port */
	set2.url.port = 81;
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	set2.url.port = set1.url.port;

	/* differ only in have_ssl */
	set2.url.have_ssl = !set1.url.have_ssl;
	test_assert(!settings_equal(&info, &set1, &set2, NULL));
	set2.url.have_ssl = set1.url.have_ssl;

	test_assert(settings_equal(&info, &set1, &set2, NULL));

	test_end();
}

static void test_settings_hash_equals_http_url_unset(void)
{
	const struct setting_define defines[] = {
		SETTING_DEFINE_STRUCT_HTTP_URL_AUTH("url", url,
			struct http_url_hash_settings),
		SETTING_DEFINE_LIST_END
	};
	const struct setting_parser_info info = {
		.defines = defines,
	};
	struct http_url_hash_settings set1, set2;

	test_begin("settings_hash() and settings_equal() for unset SET_HTTP_URL");

	/* both unset must not crash and must compare equal */
	i_zero(&set1);
	i_zero(&set2);
	(void)settings_hash(&info, &set1, NULL);
	test_assert(settings_equal(&info, &set1, &set2, NULL));

	test_end();
}

int main(void)
{
	static void (*const test_functions[])(void) = {
		test_settings_parser,
		test_settings_parse_boollist_string,
		test_settings_section_escape,
		test_settings_hash_equals,
		test_settings_parser_http_url,
		test_settings_equal_http_url_differs,
		test_settings_hash_equals_http_url_unset,
		NULL
	};
	return test_run(test_functions);
}
