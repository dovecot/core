/* Copyright (c) 2007-2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "message-date.h"
#include "test-common.h"

struct test_message_date_output {
	time_t time;
	int tz_offset;
	bool ret;
};

static void test_message_date_parse(void)
{
	static const char *input[] = {
#ifdef TIME_T_SIGNED
		"Thu, 01 Jan 1970 01:59:59 +0200",
		"Fri, 13 Dec 1901 20:45:53 +0000",
#endif
#if (TIME_T_MAX_BITS > 32 || !defined(TIME_T_SIGNED))
		"Sun, 07 Feb 2106 06:28:15 +0000",
#endif
		"Wed, 07 Nov 2007 01:07:20 +0200",
		"Wed, 07 Nov 2007 01:07:20",
		"Thu, 01 Jan 1970 02:00:00 +0200",
		"Tue, 19 Jan 2038 03:14:07 +0000",
		"Tue, 19 Jan 2038"
	};
	static struct test_message_date_output output[] = {
#ifdef TIME_T_SIGNED
		{ -1, 2*60, TRUE },
		{ -2147483647, 0, TRUE },
#endif
#if (TIME_T_MAX_BITS > 32 || !defined(TIME_T_SIGNED))
		{ 4294967295, 0, TRUE },
#endif
		{ 1194390440, 2*60, TRUE },
		{ 1194397640, 0, TRUE },
		{ 0, 2*60, TRUE },
		{ 2147483647, 0, TRUE },
		{ 0, 0, FALSE }
	};
	unsigned int i;
	bool success;
	time_t t;
	int tz;
	bool ret;

	for (i = 0; i < N_ELEMENTS(input); i++) {
		ret = message_date_parse((const unsigned char *)input[i],
					 strlen(input[i]), &t, &tz);
		success = (!ret && !output[i].ret) ||
			(ret == output[i].ret && t == output[i].time &&
			 tz == output[i].tz_offset);
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
