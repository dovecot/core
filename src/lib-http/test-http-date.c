/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "test-common.h"
#include "http-date.h"

#include <time.h>

struct http_date_test {
	const char *date_in;
	const char *date_out;

	struct tm tm;
};

/* Valid date tests */
struct http_date_test valid_date_tests[] = {
	/* Preferred format: */
	{ 
		.date_in = "Sun, 11 Nov 2007 09:42:43 GMT",
		.tm = {
			.tm_year = 107, .tm_mon = 10, .tm_mday = 11,
			.tm_hour = 9, .tm_min = 42, .tm_sec = 43 },
	},{ 
		.date_in = "Mon, 17 Aug 1992 13:06:27 GMT",
		.tm = {
			.tm_year = 92, .tm_mon = 7, .tm_mday = 17,
			.tm_hour = 13, .tm_min = 06, .tm_sec = 27 },
	},{ 
		.date_in = "Tue, 03 Sep 1974 04:38:08 GMT",
		.tm = {
			.tm_year = 74, .tm_mon = 8, .tm_mday = 3,
			.tm_hour = 4, .tm_min = 38, .tm_sec = 8 },
	},{ 
		.date_in = "Wed, 07 May 1980 06:20:42 GMT",
		.tm = {
			.tm_year = 80, .tm_mon = 4, .tm_mday = 7,
			.tm_hour = 6, .tm_min = 20, .tm_sec = 42 },
	},{ 
		.date_in = "Thu, 15 Oct 1987 18:30:14 GMT",
		.tm = {
			.tm_year = 87, .tm_mon = 9, .tm_mday = 15,
			.tm_hour = 18, .tm_min = 30, .tm_sec = 14 },
	},{ 
		.date_in = "Fri, 20 Dec 1996 00:20:07 GMT",
		.tm = {
			.tm_year = 96, .tm_mon = 11, .tm_mday = 20,
			.tm_hour = 0, .tm_min = 20, .tm_sec = 7 },
	},{ 
		.date_in = "Sat, 19 Jan 2036 19:52:18 GMT",
		.tm = {
			.tm_year = 136, .tm_mon = 0, .tm_mday = 19,
			.tm_hour = 19, .tm_min = 52, .tm_sec = 18 },
	},{ 
		.date_in = "Mon, 17 Apr 2006 14:41:45 GMT",
		.tm = {
			.tm_year = 106, .tm_mon = 3, .tm_mday = 17,
			.tm_hour = 14, .tm_min = 41, .tm_sec = 45 },
	},{ 
		.date_in = "Sun, 06 Mar 2011 16:18:41 GMT",
		.tm = {
			.tm_year = 111, .tm_mon = 2, .tm_mday = 6,
			.tm_hour = 16, .tm_min = 18, .tm_sec = 41 },
	},{ 
		.date_in = "Sat, 14 Jun 1975 16:09:30 GMT",
		.tm = {
			.tm_year = 75, .tm_mon = 5, .tm_mday = 14,
			.tm_hour = 16, .tm_min = 9, .tm_sec = 30 },
	},{ 
		.date_in = "Fri, 05 Feb 2027 06:53:58 GMT",
		.tm = {
			.tm_year = 127, .tm_mon = 1, .tm_mday = 5,
			.tm_hour = 6, .tm_min = 53, .tm_sec = 58 },
	},{ 
		.date_in = "Mon, 09 Jul 2018 02:24:29 GMT",
		.tm = {
			.tm_year = 118, .tm_mon = 6, .tm_mday = 9,
			.tm_hour = 2, .tm_min = 24, .tm_sec = 29 },

	/* Obsolete formats: */
	},{
		.date_in = "Wednesday, 02-Jun-82 16:06:23 GMT",
		.date_out = "Wed, 02 Jun 1982 16:06:23 GMT",
		.tm = {
			.tm_year = 82, .tm_mon = 5, .tm_mday = 2,
			.tm_hour = 16, .tm_min = 6, .tm_sec = 23 },
	},{
		.date_in = "Thursday, 23-May-02 12:16:24 GMT",
		.date_out = "Thu, 23 May 2002 12:16:24 GMT",
		.tm = {
			.tm_year = 102, .tm_mon = 4, .tm_mday = 23,
			.tm_hour = 12, .tm_min = 16, .tm_sec = 24 },
	},{
		.date_in = "Sun Nov  6 08:49:37 1994",
		.date_out = "Sun, 06 Nov 1994 08:49:37 GMT",
		.tm = {
			.tm_year = 94, .tm_mon = 10, .tm_mday = 6,
			.tm_hour = 8, .tm_min = 49, .tm_sec = 37 },
	},{
		.date_in = "Mon Apr 30 02:45:01 2012",
		.date_out = "Mon, 30 Apr 2012 02:45:01 GMT",
		.tm = {
			.tm_year = 112, .tm_mon = 3, .tm_mday = 30,
			.tm_hour = 2, .tm_min = 45, .tm_sec = 01 },
	}
};

unsigned int valid_date_test_count = N_ELEMENTS(valid_date_tests);

static void test_http_date_valid(void)
{
	unsigned int i;

	for (i = 0; i < valid_date_test_count; i++) T_BEGIN {
		const char *date_in, *date_out, *pdate_out;
		struct tm *tm = &valid_date_tests[i].tm, ptm;
		bool result;

		date_in = valid_date_tests[i].date_in;
		date_out = valid_date_tests[i].date_out == NULL ?
			date_in : valid_date_tests[i].date_out;

		test_begin(t_strdup_printf("http date valid [%d]", i));

		result = http_date_parse_tm
			((const unsigned char *)date_in, strlen(date_in), &ptm);
		test_out(t_strdup_printf("parse %s", date_in), result);
		if (result) {
			bool equal = tm->tm_year == ptm.tm_year && tm->tm_mon == ptm.tm_mon &&
				tm->tm_mday == ptm.tm_mday && tm->tm_hour == ptm.tm_hour &&
				tm->tm_min == ptm.tm_min && tm->tm_sec == ptm.tm_sec;

			test_out("valid timestamp", equal);

			pdate_out = http_date_create_tm(&ptm);
			test_out_reason("valid create", strcmp(date_out, pdate_out) == 0,
				pdate_out);
		}

		test_end();
	} T_END;
}

/* Invalid date tests */
const char *invalid_date_tests[] = {
	"Mom, 09 Jul 2018 02:24:29 GMT",
	"Mon; 09 Jul 2018 02:24:29 GMT",
	"Mon,  09 Jul 2018 02:24:29 GMT",
	"Mon, 90 Jul 2018 02:24:29 GMT",
	"Mon, 090 Jul 2018 02:24:29 GMT",
	"Mon, 09  Jul 2018 02:24:29 GMT",
	"Mon, 09 Lul 2018 02:24:29 GMT",
	"Mon, 09 July 2018 02:24:29 GMT",
	"Mon, 09 Jul  2018 02:24:29 GMT",
	"Mon, 09 Jul 22018 02:24:29 GMT",
	"Mon, 09 Jul 2018  02:24:29 GMT",
	"Mon, 09 Jul 2018 032:24:29 GMT",
	"Mon, 09 Jul 2018 02:224:29 GMT",
	"Mon, 09 Jul 2018 02:24:239 GMT",
	"Mon, 09 Jul 2018 02;24:29 GMT",
	"Mon, 09 Jul 2018 02:24;29 GMT",
	"Mon, 09 Jul 2018 45:24:29 GMT",
	"Mon, 09 Jul 2018 02:90:29 GMT",
	"Mon, 09 Jul 2018 02:24:84 GMT",
	"Mon, 09 Jul 2018 02:24:29  GMT",
	"Mon, 09 Jul 2018 02:24:29 UTC",
	"Mon, 09 Jul 2018 02:24:29 GM",
	"Mon, 09 Jul 2018 02:24:29 GMTREE",
	"Thu, 23-May-02 12:16:24 GMT",
	"Thursday; 23-May-02 12:16:24 GMT",
	"Thursday, 223-May-02 12:16:24 GMT",
	"Thursday, 23-Mays-02 12:16:24 GMT",
	"Thursday, 23-May-2002 12:16:24 GMT",
	"Thursday, 23-May-02 122:16:24 GMT",
	"Thursday, 23-May-02 12:164:24 GMT",
	"Thursday, 23-May-02 12:16:244 GMT",
	"Thursday, 23-May-02 12:16:24 EET",
	"Sunday Nov  6 08:49:37 1994",
	"Sun  Nov  6 08:49:37 1994",
	"Sun November  6 08:49:37 1994",
	"Sun Nov 6 08:49:37 1994",
	"Sun Nov  16 08:49:37 1994",
	"Sun Nov 16  08:49:37 1994",
	"Sun Nov  6 082:49:37 1994",
	"Sun Nov  6 08:492:37 1994",
	"Sun Nov  6 08:49:137 1994",
	"Sun Nov  6 08:49:37 19914",
	"Sun Nov  6 08:49:37 0000",
};

unsigned int invalid_date_test_count = N_ELEMENTS(invalid_date_tests);

static void test_http_date_invalid(void)
{
	unsigned int i;

	for (i = 0; i < invalid_date_test_count; i++) T_BEGIN {
		const char *date_in;
		struct tm tm;
		bool result;

		date_in = invalid_date_tests[i];

		test_begin(t_strdup_printf("http date invalid [%d]", i));

		result = http_date_parse_tm
			((const unsigned char *)date_in, strlen(date_in), &tm);
		test_out(t_strdup_printf("parse %s", date_in), !result);

		test_end();
	} T_END;
}

int main(void)
{
	static void (*test_functions[])(void) = {
		test_http_date_valid,
		test_http_date_invalid,
		NULL
	};
	return test_run(test_functions);
}
