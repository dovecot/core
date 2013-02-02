/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "utc-offset.h"
#include "utc-mktime.h"
#include "iso8601-date.h"

#include <ctype.h>

/* RFC3339/ISO8601 date-time syntax

   date-fullyear   = 4DIGIT
   date-month      = 2DIGIT  ; 01-12
   date-mday       = 2DIGIT  ; 01-28, 01-29, 01-30, 01-31 based on
                             ; month/year
   time-hour       = 2DIGIT  ; 00-23
   time-minute     = 2DIGIT  ; 00-59
   time-second     = 2DIGIT  ; 00-58, 00-59, 00-60 based on leap second
                             ; rules
   time-secfrac    = "." 1*DIGIT
   time-numoffset  = ("+" / "-") time-hour ":" time-minute
   time-offset     = "Z" / time-numoffset

   partial-time    = time-hour ":" time-minute ":" time-second [time-secfrac]
   full-date       = date-fullyear "-" date-month "-" date-mday
   full-time       = partial-time time-offset

   date-time       = full-date "T" full-time
 */

struct iso8601_date_parser {
	const unsigned char *cur, *end;

	struct tm tm;
	int timezone_offset;
};

static inline int
iso8601_date_parse_number(struct iso8601_date_parser *parser,
			  int digits, int *number_r)
{
	int i;

	if (parser->cur >= parser->end || !i_isdigit(parser->cur[0]))
		return 0;

	*number_r = parser->cur[0] - '0';
	parser->cur++;

	for (i=0; i < digits-1; i++) {
		if (parser->cur >= parser->end || !i_isdigit(parser->cur[0]))
			return -1;
		*number_r = ((*number_r) * 10) + parser->cur[0] - '0';
		parser->cur++;
	}
	return 1;
}

static int
iso8601_date_parse_secfrac(struct iso8601_date_parser *parser)
{
	/* time-secfrac    = "." 1*DIGIT

	   NOTE: Currently not applied anywhere, so fraction is just skipped.
	*/

	/* "." */
	if (parser->cur >= parser->end || parser->cur[0] != '.')
		return 0;
	parser->cur++;

	/* 1DIGIT */
	if (parser->cur >= parser->end || !i_isdigit(parser->cur[0]))
		return -1;
	parser->cur++;

	/* *DIGIT */
	while (parser->cur < parser->end && i_isdigit(parser->cur[0]))
		parser->cur++;
	return 1;
}

static int is08601_date_parse_time_offset(struct iso8601_date_parser *parser)
{
	int tz_sign = 1, tz_hour = 0, tz_min = 0;
	
	/* time-offset     = "Z" / time-numoffset
	   time-numoffset  = ("+" / "-") time-hour ":" time-minute 
	   time-hour       = 2DIGIT  ; 00-23
	   time-minute     = 2DIGIT  ; 00-59
	 */

	if (parser->cur >= parser->end)
		return 0;

	/* time-offset = "Z" / time-numoffset */
	switch (parser->cur[0]) {
	case '-':
		tz_sign = -1;

	case '+':
		parser->cur++;

		/* time-hour = 2DIGIT */
		if (iso8601_date_parse_number(parser, 2, &tz_hour) <= 0)
			return -1;
		if (tz_hour > 23)
			return -1;

		/* ":" */
		if (parser->cur >= parser->end || parser->cur[0] != ':')
			return -1;
		parser->cur++;

		/* time-minute = 2DIGIT */
		if (iso8601_date_parse_number(parser, 2, &tz_min) <= 0)
			return -1;
		if (tz_min > 59)
			return -1;
		break;
	case 'Z':
	case 'z':
		parser->cur++;
		break;
	default:
		return -1;
	}

	parser->timezone_offset = tz_sign*(tz_hour*60 + tz_min);
	return 1;
}

static int is08601_date_parse_full_time(struct iso8601_date_parser *parser)
{
	/* full-time       = partial-time time-offset
	   partial-time    = time-hour ":" time-minute ":" time-second [time-secfrac]	   
	   time-hour       = 2DIGIT  ; 00-23
	   time-minute     = 2DIGIT  ; 00-59
	   time-second     = 2DIGIT  ; 00-58, 00-59, 00-60 based on leap second
	                             ; rules
	 */

	/* time-hour = 2DIGIT */
	if (iso8601_date_parse_number(parser, 2, &parser->tm.tm_hour) <= 0)
		return -1;

	/* ":" */
	if (parser->cur >= parser->end || parser->cur[0] != ':')
		return -1;
	parser->cur++;

	/* time-minute = 2DIGIT */
	if (iso8601_date_parse_number(parser, 2, &parser->tm.tm_min) <= 0)
		return -1;

	/* ":" */
	if (parser->cur >= parser->end || parser->cur[0] != ':')
		return -1;
	parser->cur++;

	/* time-second = 2DIGIT */
	if (iso8601_date_parse_number(parser, 2, &parser->tm.tm_sec) <= 0)
		return -1;

	/* [time-secfrac] */
	if (iso8601_date_parse_secfrac(parser) < 0)
		return -1;

	/* time-offset */
	if (is08601_date_parse_time_offset(parser) <= 0)
		return -1;
	return 1;
}

static int is08601_date_parse_full_date(struct iso8601_date_parser *parser)
{
	/* full-date       = date-fullyear "-" date-month "-" date-mday
	   date-fullyear   = 4DIGIT
	   date-month      = 2DIGIT  ; 01-12
	   date-mday       = 2DIGIT  ; 01-28, 01-29, 01-30, 01-31 based on
	                             ; month/year
	 */
	
	/* date-fullyear = 4DIGIT */
	if (iso8601_date_parse_number(parser, 4, &parser->tm.tm_year) <= 0)
		return -1;
	if (parser->tm.tm_year < 1900)
		return -1;
	parser->tm.tm_year -= 1900;

	/* "-" */
	if (parser->cur >= parser->end || parser->cur[0] != '-')
		return -1;
	parser->cur++;

	/* date-month = 2DIGIT */
	if (iso8601_date_parse_number(parser, 2, &parser->tm.tm_mon) <= 0)
		return -1;
	parser->tm.tm_mon -= 1;

	/* "-" */
	if (parser->cur >= parser->end || parser->cur[0] != '-')
		return -1;
	parser->cur++;

	/* time-second = 2DIGIT */
	if (iso8601_date_parse_number(parser, 2, &parser->tm.tm_mday) <= 0)
		return -1;
	return 1;
}

static int iso8601_date_parse_date_time(struct iso8601_date_parser *parser)
{
	/* date-time       = full-date "T" full-time */

	/* full-date */
	if (is08601_date_parse_full_date(parser) <= 0)
		return -1;

	/* "T" */
	if (parser->cur >= parser->end ||
	    (parser->cur[0] != 'T' && parser->cur[0] != 't'))
		return -1;
	parser->cur++;

	/* full-time */
	if (is08601_date_parse_full_time(parser) <= 0)
		return -1;

	if (parser->cur != parser->end)
		return -1;
	return 1;
}

static bool
iso8601_date_do_parse(const unsigned char *data, size_t size, struct tm *tm_r,
		      time_t *timestamp_r, int *timezone_offset_r)
{
	struct iso8601_date_parser parser;
	time_t timestamp;

	memset(&parser, 0, sizeof(parser));
	parser.cur = data;
	parser.end = data + size;

	if (iso8601_date_parse_date_time(&parser) <= 0)
		return FALSE;

	parser.tm.tm_isdst = -1;
	timestamp = utc_mktime(&parser.tm);
	if (timestamp == (time_t)-1)
		return FALSE;

	*timezone_offset_r = parser.timezone_offset;
	*tm_r = parser.tm;
	*timestamp_r = timestamp - parser.timezone_offset * 60;
	return TRUE;
}

bool iso8601_date_parse(const unsigned char *data, size_t size,
			time_t *timestamp_r, int *timezone_offset_r)
{
	struct tm tm;

	return iso8601_date_do_parse(data, size, &tm,
				     timestamp_r, timezone_offset_r);
}

bool iso8601_date_parse_tm(const unsigned char *data, size_t size,
			   struct tm *tm_r, int *timezone_offset_r)
{
	time_t timestamp;

	return iso8601_date_do_parse(data, size, tm_r,
				     &timestamp, timezone_offset_r);
}

const char *iso8601_date_create_tm(struct tm *tm, int timezone_offset)
{
	const char *time_offset;

	if (timezone_offset == INT_MAX)
		time_offset = "Z";
	else {
		char sign = '+';
		if (timezone_offset < 0) {
			timezone_offset = -timezone_offset;
			sign = '-';
		} 
		time_offset = t_strdup_printf("%c%02d:%02d", sign,
					      timezone_offset / 60,
					      timezone_offset % 60);
	}

	return t_strdup_printf("%04d-%02d-%02dT%02d:%02d:%02d%s",
			tm->tm_year + 1900, tm->tm_mon+1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec, time_offset);
}

const char *iso8601_date_create(time_t timestamp)
{
	struct tm *tm;
	int timezone_offset;

	tm = localtime(&timestamp);
	timezone_offset = utc_offset(tm, timestamp);
	
	return iso8601_date_create_tm(tm, timezone_offset);
}
