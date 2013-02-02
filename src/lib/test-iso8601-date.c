/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "test-common.h"
#include "iso8601-date.h"

#include <time.h>

struct iso8601_date_test {
	const char *date_in;
	const char *date_out;

	struct tm tm;
	int zone_offset;
};

/* Valid date tests */
struct iso8601_date_test valid_date_tests[] = {
	{ 
		.date_in = "2007-11-07T23:05:34+00:00",
		.tm = {
			.tm_year = 107, .tm_mon = 10, .tm_mday = 7,
			.tm_hour = 23, .tm_min = 5, .tm_sec = 34 },
	},{ 
		.date_in = "2011-01-07T21:03:31+00:30",
		.tm = {
			.tm_year = 111, .tm_mon = 0, .tm_mday = 7,
			.tm_hour = 21, .tm_min = 3, .tm_sec = 31 },
		.zone_offset = 30
	},{ 
		.date_in = "2006-05-09T18:04:12+05:30",
		.tm = {
			.tm_year = 106, .tm_mon = 4, .tm_mday = 9,
			.tm_hour = 18, .tm_min = 4, .tm_sec = 12 },
		.zone_offset = 5*60+30
	},{ 
		.date_in = "1975-10-30T06:33:29Z",
		.date_out = "1975-10-30T06:33:29+00:00",
		.tm = {
			.tm_year = 75, .tm_mon = 9, .tm_mday = 30,
			.tm_hour = 6, .tm_min = 33, .tm_sec = 29 },
	},{ 
		.date_in = "1988-04-24t15:02:12z",
		.date_out = "1988-04-24T15:02:12+00:00",
		.tm = {
			.tm_year = 88, .tm_mon = 3, .tm_mday = 24,
			.tm_hour = 15, .tm_min = 2, .tm_sec = 12 },
	},{ 
		.date_in = "2012-02-29T08:12:34.23198Z",
		.date_out = "2012-02-29T08:12:34+00:00",
		.tm = {
			.tm_year = 112, .tm_mon = 1, .tm_mday = 29,
			.tm_hour = 8, .tm_min = 12, .tm_sec = 34 },
	}
};

unsigned int valid_date_test_count = N_ELEMENTS(valid_date_tests);

static void test_iso8601_date_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_date_test_count; i++) T_BEGIN {
		const char *date_in, *date_out, *pdate_out;
		struct tm *tm = &valid_date_tests[i].tm, ptm;
		int zone_offset = valid_date_tests[i].zone_offset, pzone_offset;
		bool result;

		date_in = valid_date_tests[i].date_in;
		date_out = valid_date_tests[i].date_out == NULL ?
			date_in : valid_date_tests[i].date_out;

		test_begin(t_strdup_printf("iso8601 date valid [%d]", i));

		result = iso8601_date_parse_tm
			((const unsigned char *)date_in, strlen(date_in), &ptm, &pzone_offset);
		test_out(t_strdup_printf("parse %s", date_in), result);
		if (result) {
			bool equal = tm->tm_year == ptm.tm_year && tm->tm_mon == ptm.tm_mon &&
				tm->tm_mday == ptm.tm_mday && tm->tm_hour == ptm.tm_hour &&
				tm->tm_min == ptm.tm_min && tm->tm_sec == ptm.tm_sec;

			test_out("valid timestamp", equal);
			test_out_reason("valid timezone", zone_offset == pzone_offset,
				t_strdup_printf("%d", pzone_offset));

			pdate_out = iso8601_date_create_tm(tm, zone_offset);
			test_out_reason("valid create", strcmp(date_out, pdate_out) == 0,
				pdate_out);
		}

		test_end();
	} T_END;
}

/* Invalid date tests */
const char *invalid_date_tests[] = {
	"200-11-17T23:05:34+00:00",
	"2007:11-17T23:05:34+00:00",
	"2007-11?17T23:05:34+00:00",
	"2007-49-17T23:05:34+00:00",
	"2007-11-77T23:05:34+00:00",
	"2007-11-17K23:05:34+00:00",
	"2007-11-13T59:05:34+00:00",
	"2007-112-13T12:15:34+00:00",
	"2007-11-133T12:15:34+00:00",
	"2007-11-13T12J15:34+00:00",
	"2007-11-13T12:15*34+00:00",
	"2007-11-13T12:15:34/00:00",
	"2007-11-13T12:15:34+00-00",
	"2007-11-13T123:15:34+00:00",
	"2007-11-13T12:157:34+00:00",
	"2007-11-13T12:15:342+00:00",
	"2007-11-13T12:15:34+001:00",
	"2007-11-13T12:15:32+00:006",
	"2007-02-29T15:13:21Z"
};

unsigned int invalid_date_test_count = N_ELEMENTS(invalid_date_tests);

static void test_iso8601_date_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_date_test_count; i++) T_BEGIN {
		const char *date_in;
		struct tm tm;
		int tz;
		bool result;

		date_in = invalid_date_tests[i];

		test_begin(t_strdup_printf("iso8601 date invalid [%d]", i));

		result = iso8601_date_parse_tm
			((const unsigned char *)date_in, strlen(date_in), &tm, &tz);
		test_out(t_strdup_printf("parse %s", date_in), !result);

		test_end();
	} T_END;
}

void test_iso8601_date(void)
{
	test_iso8601_date_valid();
	test_iso8601_date_invalid();
}
