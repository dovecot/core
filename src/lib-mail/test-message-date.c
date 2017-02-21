/* Copyright (c) 2007-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "message-date.h"
#include "test-common.h"

struct test_message_date {
	const char *input;
	time_t time;
	int tz_offset;
	bool ret;
};

static void test_message_date_parse(void)
{
	static const struct test_message_date tests[] = {
#ifdef TIME_T_SIGNED
		{ "Thu, 01 Jan 1970 01:59:59 +0200", -1, 2*60, TRUE },
		{ "Fri, 13 Dec 1901 20:45:53 +0000", -2147483647, 0, TRUE },
#endif
#if (TIME_T_MAX_BITS > 32 || !defined(TIME_T_SIGNED))
		{ "Sun, 07 Feb 2106 06:28:15 +0000", 4294967295U, 0, TRUE },
#endif
		{ "Wed, 07 Nov 2007 01:07:20 +0200", 1194390440, 2*60, TRUE },
		{ "Wed, 07 Nov 2007 01:07:20", 1194397640, 0, TRUE },
		{ "Thu, 01 Jan 1970 02:00:00 +0200", 0, 2*60, TRUE },
		{ "Tue, 19 Jan 2038 03:14:07 +0000", 2147483647, 0, TRUE },
		{ "Tue, 19 Jan 2038", 0, 0, FALSE },
		/* June leap second */
		{ "Tue, 30 Jun 2015 23:59:59 +0300", 1435697999, 3*60, TRUE },
		{ "Tue, 30 Jun 2015 23:59:60 +0300", 1435697999, 3*60, TRUE },
		{ "Wed, 01 Jul 2015 00:00:00 +0300", 1435698000, 3*60, TRUE },
		/* Invalid leap second */
		{ "Tue, 24 Jan 2017 15:59:60 +0300", 1485262799, 3*60, TRUE },
		/* December leap second */
		{ "Sat, 31 Dec 2016 23:59:59 +0200", 1483221599, 2*60, TRUE },
		{ "Sat, 31 Dec 2016 23:59:60 +0200", 1483221599, 2*60, TRUE },
		{ "Sun, 01 Jan 2017 00:00:00 +0200", 1483221600, 2*60, TRUE },
	};
	unsigned int i;
	bool success;
	time_t t;
	int tz;
	bool ret;

	for (i = 0; i < N_ELEMENTS(tests); i++) {
		const struct test_message_date *test = &tests[i];
		ret = message_date_parse((const unsigned char *)test->input,
					 strlen(test->input), &t, &tz);
		success = (!ret && !test->ret) ||
			(ret == test->ret && t == test->time &&
			 tz == test->tz_offset);
		test_out(t_strdup_printf("message_date_parse(%d)", i), success);
	}
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_message_date_parse,
		NULL
	};
	return test_run(test_functions);
}
