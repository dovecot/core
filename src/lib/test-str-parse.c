/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str-parse.h"

static void test_str_parse_get_interval(void)
{
	static const struct {
		const char *input;
		unsigned int output;
	} tests[] = {
		{ "0", 0 },

		{ "59s", 59 },
		{ "59 s", 59 },
		{ "59se", 59 },
		{ "59sec", 59 },
		{ "59secs", 59 },
		{ "59seco", 59 },
		{ "59secon", 59 },
		{ "59second", 59 },
		{ "59seconds", 59 },
		{ "123456   seconds", 123456 },

		{ "123m", 123*60 },
		{ "123 m", 123*60 },
		{ "123 mi", 123*60 },
		{ "123 min", 123*60 },
		{ "123 mins", 123*60 },
		{ "123 minu", 123*60 },
		{ "123 minut", 123*60 },
		{ "123 minute", 123*60 },
		{ "123 minutes", 123*60 },

		{ "123h", 123*60*60 },
		{ "123 h", 123*60*60 },
		{ "123 ho", 123*60*60 },
		{ "123 hou", 123*60*60 },
		{ "123 hour", 123*60*60 },
		{ "123 hours", 123*60*60 },

		{ "12d", 12*60*60*24 },
		{ "12 d", 12*60*60*24 },
		{ "12 da", 12*60*60*24 },
		{ "12 day", 12*60*60*24 },
		{ "12 days", 12*60*60*24 },

		{ "3w", 3*60*60*24*7 },
		{ "3 w", 3*60*60*24*7 },
		{ "3 we", 3*60*60*24*7 },
		{ "3 wee", 3*60*60*24*7 },
		{ "3 week", 3*60*60*24*7 },
		{ "3 weeks", 3*60*60*24*7 },

		{ "1000ms", 1 },
		{ "50000ms", 50 },
	};
	struct {
		const char *input;
		unsigned int output;
	} msecs_tests[] = {
		{ "0ms", 0 },
		{ "1ms", 1 },
		{ "123456ms", 123456 },
		{ "123456 ms", 123456 },
		{ "123456mse", 123456 },
		{ "123456msec", 123456 },
		{ "123456msecs", 123456 },
		{ "123456mseco", 123456 },
		{ "123456msecon", 123456 },
		{ "123456msecond", 123456 },
		{ "123456mseconds", 123456 },
		{ "123456mil", 123456 },
		{ "123456mill", 123456 },
		{ "123456milli", 123456 },
		{ "123456millis", 123456 },
		{ "123456millisec", 123456 },
		{ "123456millisecs", 123456 },
		{ "123456milliseco", 123456 },
		{ "123456millisecon", 123456 },
		{ "123456millisecond", 123456 },
		{ "123456milliseconds", 123456 },
		{ "4294967295 ms", 4294967295 },
	};
	const char *secs_errors[] = {
		"-1",
		"1",
		/* wrong spellings: */
		"1ss",
		"1secss",
		"1secondss",
		"1ma",
		"1minsa",
		"1hu",
		"1hoursa",
		"1dd",
		"1days?",
		"1wa",
		"1weeksb",

		/* milliseconds: */
		"1ms",
		"999ms",
		"1001ms",
		/* overflows: */
		"7102 w",
		"4294967296 s",
	};
	const char *msecs_errors[] = {
		"-1",
		"1",
		/* wrong spellings: */
		"1mis",
		"1mss",
		/* overflows: */
		"8 w",
		"4294967296 ms",
	};
	unsigned int i, secs, msecs;
	const char *error;

	test_begin("str_parse_get_interval()");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(str_parse_get_interval(tests[i].input, &secs,
						       &error) == 0, i);
		test_assert_idx(secs == tests[i].output, i);

		test_assert_idx(str_parse_get_interval_msecs(
					tests[i].input, &msecs, &error) == 0, i);
		test_assert_idx(msecs == tests[i].output*1000, i);
	}
	for (i = 0; i < N_ELEMENTS(msecs_tests); i++) {
		test_assert_idx(str_parse_get_interval_msecs(
					msecs_tests[i].input, &msecs, &error) == 0, i);
		test_assert_idx(msecs == msecs_tests[i].output, i);
	}
	for (i = 0; i < N_ELEMENTS(secs_errors); i++)
		test_assert_idx(str_parse_get_interval(secs_errors[i], &secs,
						       &error) < 0, i);
	for (i = 0; i < N_ELEMENTS(msecs_errors); i++)
		test_assert_idx(str_parse_get_interval_msecs(
					msecs_errors[i], &msecs, &error) < 0, i);
	test_end();
}

static void test_str_parse_get_size(void)
{
	test_begin("str_parse_get_size()");

	static const struct {
		const char *input;
		uoff_t output;
	} tests[] = {
		{ "0", 0 },
		{ "0000", 0 },
		{ "1b", 1 },
		{ "1B", 1 },
		{ "1 b", 1 },
		{ "1k", 1024 },
		{ "1K", 1024 },
		{ "1 k", 1024 },
		{ "1m", 1024*1024 },
		{ "1M", 1024*1024 },
		{ "1 m", 1024*1024 },
		{ "1g", 1024*1024*1024ULL },
		{ "1G", 1024*1024*1024ULL },
		{ "1 g", 1024*1024*1024ULL },
		{ "1t", 1024*1024*1024*1024ULL },
		{ "1T", 1024*1024*1024*1024ULL },
		{ "1 t", 1024*1024*1024*1024ULL },
	};

	const char *size_errors[] = {
		"-1",
		"one",
		"",
		"340282366920938463463374607431768211456",
		"2^32",
		"2**32",
		"1e10",
		"1 byte",
	};

	size_t i;
	uoff_t size;
	const char *error;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		error = NULL;
		test_assert_idx(str_parse_get_size(tests[i].input, &size,
						   &error) == 0, i);
		test_assert_idx(size == tests[i].output, i);
		test_assert(error == NULL);
	}
	for (i = 0; i < N_ELEMENTS(size_errors); i++) {
		error = NULL;
		test_assert_idx(str_parse_get_size(size_errors[i], &size,
						   &error) < 0, i);
		test_assert(error != NULL);
	};

	test_end();
}

void test_str_parse(void)
{
	test_str_parse_get_interval();
	test_str_parse_get_size();
}
