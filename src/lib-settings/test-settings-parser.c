/* Copyright (c) 2009-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "settings-parser.h"
#include "test-common.h"

static void test_settings_get_time(void)
{
	struct {
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
		/* wrong spellings: */
		"1mis",
		"1mss",
		/* overflows: */
		"8 w",
		"4294967296 ms",
	};
	unsigned int i, secs, msecs;
	const char *error;

	test_begin("settings_get_time()");
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_assert_idx(settings_get_time(tests[i].input, &secs, &error) == 0, i);
		test_assert_idx(secs == tests[i].output, i);

		test_assert_idx(settings_get_time_msecs(tests[i].input, &msecs, &error) == 0, i);
		test_assert_idx(msecs == tests[i].output*1000, i);
	}
	for (i = 0; i < N_ELEMENTS(msecs_tests); i++) {
		test_assert_idx(settings_get_time_msecs(msecs_tests[i].input, &msecs, &error) == 0, i);
		test_assert_idx(msecs == msecs_tests[i].output, i);
	}
	for (i = 0; i < N_ELEMENTS(secs_errors); i++)
		test_assert_idx(settings_get_time(secs_errors[i], &secs, &error) < 0, i);
	for (i = 0; i < N_ELEMENTS(msecs_errors); i++)
		test_assert_idx(settings_get_time_msecs(msecs_errors[i], &msecs, &error) < 0, i);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_settings_get_time,
		NULL
	};
	return test_run(test_functions);
}
