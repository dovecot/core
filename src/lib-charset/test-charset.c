/* Copyright (c) 2015-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "test-common.h"
#include "charset-utf8.h"

static void test_charset_is_utf8(void)
{
	test_begin("charset_is_utf8");
	test_assert(charset_is_utf8("AScII"));
	test_assert(charset_is_utf8("us-AScII"));
	test_assert(charset_is_utf8("uTF8"));
	test_assert(charset_is_utf8("uTF-8"));
	test_end();
}

static void test_charset_utf8_common(const char *input_charset)
{
	struct {
		const char *input;
		const char *output;
		enum charset_result result;
	} tests[] = {
		{ "p\xC3\xA4\xC3", "p\xC3\xA4", CHARSET_RET_INCOMPLETE_INPUT },
		{ "p\xC3\xA4\xC3""a", "p\xC3\xA4"UNICODE_REPLACEMENT_CHAR_UTF8"a", CHARSET_RET_INVALID_INPUT }
	};
	string_t *src, *str = t_str_new(256);
	enum charset_result result;
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		test_assert_idx(charset_to_utf8_str(input_charset, NULL,
						    tests[i].input, str, &result) == 0, i);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		test_assert_idx(result == tests[i].result, i);
	}
	/* check that E2BIG handling works. We assume that iconv() is called
	   with 8192 byte buffer (tmpbuf[8192]) */
	src = str_new(default_pool, 16384);
	for (i = 0; i < 8190; i++)
		str_append_c(src, 'a' + i % ('z'-'a'+1));
	for (i = 0; i < 256; i++) {
		str_truncate(str, 0);
		str_append_c(src, 'A' + i % ('Z'-'A'+1));
		test_assert_idx(charset_to_utf8_str(input_charset, NULL,
						    str_c(src), str, &result) == 0, i);
	}
	str_free(&src);
}

static void test_charset_utf8(void)
{
	test_begin("charset utf8");
	test_charset_utf8_common("UTF-8");
	test_end();
}

#ifdef HAVE_ICONV
static void test_charset_iconv(void)
{
	struct {
		const char *charset;
		const char *input;
		const char *output;
		enum charset_result result;
	} tests[] = {
		{ "ISO-8859-1", "p\xE4\xE4", "p\xC3\xA4\xC3\xA4", CHARSET_RET_OK },
		{ "UTF-7", "+AOQA5AD2AOQA9gDkAPYA5AD2AOQA9gDkAPYA5AD2AOQA9gDkAPYA5AD2AOQA9gDkAPYA5AD2AOQA9gDkAPYA5AD2AOQA9gDk",
		  "\xC3\xA4\xC3\xA4\xC3\xB6\xC3\xA4\xC3\xB6\xC3\xA4\xC3\xB6\xC3\xA4"
		  "\xC3\xB6\xC3\xA4\xC3\xB6\xC3\xA4\xC3\xB6\xC3\xA4\xC3\xB6\xC3\xA4"
		  "\xC3\xB6\xC3\xA4\xC3\xB6\xC3\xA4\xC3\xB6\xC3\xA4\xC3\xB6\xC3\xA4"
		  "\xC3\xB6\xC3\xA4\xC3\xB6\xC3\xA4\xC3\xB6\xC3\xA4\xC3\xB6\xC3\xA4"
		  "\xC3\xB6\xC3\xA4\xC3\xB6\xC3\xA4", CHARSET_RET_OK }
	};
	string_t *str = t_str_new(128);
	struct charset_translation *trans;
	enum charset_result result;
	size_t pos, left, limit, len;
	unsigned int i;

	test_begin("charset iconv");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		test_assert_idx(charset_to_utf8_str(tests[i].charset, NULL,
						    tests[i].input, str, &result) == 0, i);
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		test_assert_idx(result == tests[i].result, i);

		str_truncate(str, 0);
		test_assert_idx(charset_to_utf8_begin(tests[i].charset, NULL, &trans) == 0, i);
		len = strlen(tests[i].input);
		for (pos = 0, limit = 1; limit <= len; pos += left, limit++) {
			left = limit - pos;
			result = charset_to_utf8(trans, (const void *)(tests[i].input + pos),
						 &left, str);
			if (result != CHARSET_RET_INCOMPLETE_INPUT &&
			    result != CHARSET_RET_OK)
				break;
		}
		test_assert_idx(strcmp(tests[i].output, str_c(str)) == 0, i);
		test_assert_idx(result == tests[i].result, i);
		charset_to_utf8_end(&trans);
	}
	/* Use //IGNORE just to force handling to be done by iconv
	   instead of our own UTF-8 routines. */
	test_charset_utf8_common("UTF-8//TEST");
	test_end();
}
static void test_charset_iconv_crashes(void)
{
	struct {
		const char *charset;
		const char *input;
	} tests[] = {
		{ "CP932", "\203\334" }
	};
	string_t *str = t_str_new(128);
	enum charset_result result;
	unsigned int i;

	test_begin("charset iconv crashes");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		str_truncate(str, 0);
		/* we don't care about checking the result. we only want to
		   verify that there's no crash. */
		(void)charset_to_utf8_str(tests[i].charset, NULL,
					  tests[i].input, str, &result);
	}
	test_end();
}

static void test_charset_iconv_utf7_state(void)
{
	struct charset_translation *trans;
	string_t *str = t_str_new(32);
	unsigned char nextbuf[5+CHARSET_MAX_PENDING_BUF_SIZE+1];
	size_t size;

	test_begin("charset iconv utf7 state");
	test_assert(charset_to_utf8_begin("UTF-7", NULL, &trans) == 0);
	size = 2;
	test_assert(charset_to_utf8(trans, (const void *)"a+", &size, str) == CHARSET_RET_INCOMPLETE_INPUT);
	test_assert(strcmp(str_c(str), "a") == 0);
	test_assert(size == 1);
	memset(nextbuf, '?', sizeof(nextbuf));
	memcpy(nextbuf, "+AOQ-", 5);
	size = sizeof(nextbuf);
	test_assert(charset_to_utf8(trans, nextbuf, &size, str) == CHARSET_RET_OK);
	test_assert(strcmp(str_c(str), "a\xC3\xA4???????????") == 0);
	charset_to_utf8_end(&trans);
	test_end();
}
#endif

int main(void)
{
	static void (*test_functions[])(void) = {
		test_charset_is_utf8,
		test_charset_utf8,
#ifdef HAVE_ICONV
		test_charset_iconv,
		test_charset_iconv_crashes,
		test_charset_iconv_utf7_state,
#endif
		NULL
	};

	return test_run(test_functions);
}
