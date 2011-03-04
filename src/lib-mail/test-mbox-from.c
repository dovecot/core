/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "utc-offset.h"
#include "mbox-from.h"
#include "test-common.h"

#include <time.h>

struct test_mbox_from_parse_output {
	time_t time;
	int tz_offset;
	const char *sender;
	int ret;
};

static void test_mbox_from_parse(void)
{
	static const char *input[] = {
		"user@domain Thu Nov 29 23:33:09 1973 +0200",
		"user@domain Thu Nov 29 19:33:09 1973 -0200",
		"\"user name\"@domain  Fri Jan  2 10:13:52 UTC 1970 +0000",
		"user  Fri Jan  2 10:14 1970 +0000",
		"user Fri, 2 Jan 1970 10:14:00 +0000",
		"user Fri, 2 Jan 1970 10:14 +0000",
		" Fri Jan  2 10:14 1970 +0000",
		"user Fri, 2 Foo 1970 10:14:00",
		"Fri Jan  2 10:14 1970 +0000",
		"user  Fri Jan  x 10:14 1970 +0000",
		"user  Fri Jan  2 0:14 1970 +0000",
		"user  Fri Jan  2 xx:14 1970 +0000",
		"user  Fri Jan  2 10: 1970 +0000",
		"user  Fri Jan  2 10:xx 1970 +0000",
		"user  Fri Jan  2 10:xx +0000",
	};
	static struct test_mbox_from_parse_output output[] = {
		{ 123456789, 2*60, "user@domain", 0 },
		{ 123456789, -2*60, "user@domain", 0 },
		{ 123232, 0, "\"user name\"@domain", 0 },
		{ 123240, 0, "user", 0 },
		{ 123240, 0, "user", 0 },
		{ 123240, 0, "user", 0 },
		{ 123240, 0, "", 0 },
		{ 0, 0, NULL, -1 },
		{ 0, 0, NULL, -1 },
		{ 0, 0, NULL, -1 },
		{ 0, 0, NULL, -1 },
		{ 0, 0, NULL, -1 },
		{ 0, 0, NULL, -1 },
		{ 0, 0, NULL, -1 },
		{ 0, 0, NULL, -1 },
	};
	unsigned int i, j, len;
	struct tm *tm;
	char *sender;
	bool success;
	time_t t;
	int tz, ret;

	for (j = 0; j < 2; j++) {
	for (i = 0; i < N_ELEMENTS(input); i++) {
		len = strlen(input[i]) - j*6;
		ret = mbox_from_parse((const unsigned char *)input[i],
				      len, &t, &tz, &sender);
		success = (ret < 0 && output[i].ret < 0) ||
			(ret == output[i].ret && t == output[i].time &&
			 tz == output[i].tz_offset &&
			 strcmp(sender, output[i].sender) == 0);
		i_free(sender);
		test_out(t_strdup_printf("mbox_from_parse(%d,%d)", j, i), success);

		/* prepare for testing without timezone */
		if (output[i].ret == 0) {
			output[i].time += output[i].tz_offset*60;
			tm = localtime(&output[i].time);
			output[i].tz_offset = utc_offset(tm, output[i].time);
			output[i].time -= output[i].tz_offset*60;
		}
	}
	}
}

static void test_mbox_from_create(void)
{
	time_t t = 1234567890;
	int tz;

	test_begin("mbox_from_create()");
	tz = utc_offset(localtime(&t), t) * -60;
	test_assert(strcmp(mbox_from_create("user", t+tz),
			   "From user  Fri Feb 13 23:31:30 2009\n") == 0);
	test_end();
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_mbox_from_parse,
		test_mbox_from_create,
		NULL
	};
	return test_run(test_functions);
}
