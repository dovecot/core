/* Copyright (c) Dovecot authors, see top-level COPYING file */

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
		"user Fri Nov  9 22:33:52 5",
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
		{ 0, 0, NULL, -1 },
	};
	unsigned int i, j;
	size_t len;
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

static void test_mbox_from_parse_no_overread(void)
{
	/* A truncated non-alt date whose trailing space leaves the parser
	   pointing exactly at the end of the input when the year field is
	   read. Feed it from an exact-size heap buffer so an over-read past
	   msg+size is caught under valgrind/ASAN. */
	const char *date = "x Fri Jan  22 12:34:56 ";
	size_t len = strlen(date);
	char *sender = NULL;
	time_t t;
	int tz, ret;

	test_begin("mbox_from_parse() no over-read of year");
	unsigned char *buf = i_memdup(date, len);
	ret = mbox_from_parse(buf, len, &t, &tz, &sender);
	test_assert(ret < 0);
	i_free(sender);
	i_free(buf);
	test_end();
}

static void test_mbox_from_parse_quoted_backslash(void)
{
	/* mbox_from_create() gets the sender from smtp_address_encode(),
	   which writes a backslash in a quoted local part as "\\". Such a
	   From_ line must parse. */
	static const char *const senders[] = {
		"\"a\\\\\"@example.com",		/* "a\\"@example.com */
		"\"\\\\\"@example.com",		/* "\\"@example.com */
		"\"a\\\\\\\"b\"@example.com",	/* "a\\\"b"@example.com */
		"\"a b\\\\\"@example.com",	/* "a b\\"@example.com */
	};
	char *sender;
	time_t t;
	int tz;

	test_begin("mbox_from_parse() quoted sender with escaped backslash");
	for (unsigned int i = 0; i < N_ELEMENTS(senders); i++) {
		const char *line = mbox_from_create(senders[i], 1234567890);
		test_assert_cmp_idx(mbox_from_parse(
			(const unsigned char *)line + 5, strlen(line) - 6,
			&t, &tz, &sender), ==, 0, i);
		test_assert_strcmp_idx(sender, senders[i], i);
		i_free(sender);
	}
	test_end();
}

static void test_mbox_from_parse_line_break_in_date(void)
{
	static const char *const input[] = {
		"x Mo\n Jan  1 00:00:00 2024",
		"x Mon\n Jan  1 00:00:00 2024",
		"x Mon Jan\n 1 00:00:00 2024",
		"x Mon Jan\r 1 00:00:00 2024",
		"x Mon, 1 Jan\n2024 00:00:00",
		"x Mon, 1 Jan 2024\r00:00:00",
	};
	char *sender;
	time_t t;
	int tz;

	test_begin("mbox_from_parse() line break in date");
	/* the same lines without the line break are valid */
	test_assert_cmp(mbox_from_parse((const unsigned char *)
					"x Mon Jan  1 00:00:00 2024 +0000", 32,
					&t, &tz, &sender), ==, 0);
	i_free(sender);
	test_assert_cmp(mbox_from_parse((const unsigned char *)
					"x Mon, 1 Jan 2024 00:00:00", 26,
					&t, &tz, &sender), ==, 0);
	i_free(sender);
	for (unsigned int i = 0; i < N_ELEMENTS(input); i++) {
		test_assert_cmp_idx(mbox_from_parse(
			(const unsigned char *)input[i], strlen(input[i]),
			&t, &tz, &sender), <, 0, i);
		test_assert_idx(sender == NULL, i);
	}
	test_end();
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
	static void (*const test_functions[])(void) = {
		test_mbox_from_parse,
		test_mbox_from_parse_no_overread,
		test_mbox_from_parse_quoted_backslash,
		test_mbox_from_parse_line_break_in_date,
		test_mbox_from_create,
		NULL
	};
	return test_run(test_functions);
}
