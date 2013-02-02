/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "utc-mktime.h"
#include "http-date.h"

#include <ctype.h>

/*
	Official specification is still RFC261, Section 3.3, but we anticipate
	HTTPbis and use the draft Part 2, Section 5.1 as reference for our
	parser:
 
	http://tools.ietf.org/html/draft-ietf-httpbis-p2-semantics-20#section-5.1

	The defined syntax is as follows:

	 HTTP-date    = rfc1123-date / obs-date

	Preferred format:

	 rfc1123-date = day-name "," SP date1 SP time-of-day SP GMT
	                ; fixed length subset of the format defined in
	                ; Section 5.2.14 of [RFC1123]
	 day-name     = %x4D.6F.6E ; "Mon", case-sensitive
	              / %x54.75.65 ; "Tue", case-sensitive
	              / %x57.65.64 ; "Wed", case-sensitive
	              / %x54.68.75 ; "Thu", case-sensitive
	              / %x46.72.69 ; "Fri", case-sensitive
	              / %x53.61.74 ; "Sat", case-sensitive
	              / %x53.75.6E ; "Sun", case-sensitive
	 date1        = day SP month SP year
	                ; e.g., 02 Jun 1982
	 day          = 2DIGIT
	 month        = %x4A.61.6E ; "Jan", case-sensitive
                / %x46.65.62 ; "Feb", case-sensitive
	              / %x4D.61.72 ; "Mar", case-sensitive
	              / %x41.70.72 ; "Apr", case-sensitive
	              / %x4D.61.79 ; "May", case-sensitive
	              / %x4A.75.6E ; "Jun", case-sensitive
	              / %x4A.75.6C ; "Jul", case-sensitive
	              / %x41.75.67 ; "Aug", case-sensitive
	              / %x53.65.70 ; "Sep", case-sensitive
	              / %x4F.63.74 ; "Oct", case-sensitive
	              / %x4E.6F.76 ; "Nov", case-sensitive
	              / %x44.65.63 ; "Dec", case-sensitive
	 year         = 4DIGIT
	 GMT          = %x47.4D.54 ; "GMT", case-sensitive
	 time-of-day  = hour ":" minute ":" second
	 	              ; 00:00:00 - 23:59:59
	 hour         = 2DIGIT
	 minute       = 2DIGIT
	 second       = 2DIGIT

  The semantics of day-name, day, month, year, and time-of-day are the
  same as those defined for the RFC 5322 constructs with the
  corresponding name ([RFC5322], Section 3.3).

  Obsolete formats:

	 obs-date     = rfc850-date / asctime-date

	 rfc850-date  = day-name-l "," SP date2 SP time-of-day SP GMT
	 date2        = day "-" month "-" 2DIGIT
		              ; day-month-year (e.g., 02-Jun-82)
	 day-name-l   = %x4D.6F.6E.64.61.79 ; "Monday", case-sensitive
	              / %x54.75.65.73.64.61.79 ; "Tuesday", case-sensitive
	              / %x57.65.64.6E.65.73.64.61.79 ; "Wednesday", case-sensitive
	              / %x54.68.75.72.73.64.61.79 ; "Thursday", case-sensitive
	              / %x46.72.69.64.61.79 ; "Friday", case-sensitive
	              / %x53.61.74.75.72.64.61.79 ; "Saturday", case-sensitive
	              / %x53.75.6E.64.61.79 ; "Sunday", case-sensitive

	 asctime-date = day-name SP date3 SP time-of-day SP year
	 date3        = month SP ( 2DIGIT / ( SP 1DIGIT ))
		              ; month day (e.g., Jun  2)

 */

static const char *month_names[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static const char *weekday_names[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *weekday_names_long[] = {
	"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"
};

struct http_date_parser {
	const unsigned char *cur, *end;

	struct tm tm;
	int timezone_offset;
};

static inline int
http_date_parse_sp(struct http_date_parser *parser)
{
	if (parser->cur >= parser->end)
		return -1;
	if (parser->cur[0] != ' ')
		return 0;
	parser->cur++;
	return 1;
}

static inline int
http_date_parse_number(struct http_date_parser *parser,
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

static inline int
http_date_parse_word(struct http_date_parser *parser,
			  int maxchars, string_t **word_r)
{
	string_t *word;
	int i;

	if (parser->cur >= parser->end || !i_isalpha(parser->cur[0]))
		return 0;

	word = t_str_new(maxchars);
	str_append_c(word, parser->cur[0]);
	parser->cur++;

	for (i=0; i < maxchars-1; i++) {
		if (parser->cur >= parser->end || !i_isalpha(parser->cur[0]))
			break;
		str_append_c(word, parser->cur[0]);
		parser->cur++;
	}
	
	if (i_isalpha(parser->cur[0]))
		return -1;
	*word_r = word;
	return 1;
}

static inline int
http_date_parse_year(struct http_date_parser *parser)
{
	/* year = 4DIGIT */
	if (http_date_parse_number(parser, 4, &parser->tm.tm_year) <= 0)
		return -1;
	if (parser->tm.tm_year < 1900)
		return -1;
	parser->tm.tm_year -= 1900;
	return 1;
}

static inline int
http_date_parse_month(struct http_date_parser *parser)
{
	string_t *month;
	int i;

	if (http_date_parse_word(parser, 3, &month) <= 0 || str_len(month) != 3)
		return -1;
	
	for (i = 0; i < 12; i++) {
		if (strcmp(month_names[i], str_c(month)) == 0) {
			break;
		}
	}
	if (i >= 12)
		return -1;
	
	parser->tm.tm_mon = i;
	return 1;
}

static inline int
http_date_parse_day(struct http_date_parser *parser)
{
	/* day = 2DIGIT */
	if (http_date_parse_number(parser, 2, &parser->tm.tm_mday) <= 0)
		return -1;
	return 1;
}

static int
http_date_parse_time_of_day(struct http_date_parser *parser)
{
	/* time-of-day  = hour ":" minute ":" second
	 	              ; 00:00:00 - 23:59:59
		 hour         = 2DIGIT
		 minute       = 2DIGIT
		 second       = 2DIGIT
	 */

	/* hour = 2DIGIT */
	if (http_date_parse_number(parser, 2, &parser->tm.tm_hour) <= 0)
		return -1;

	/* ":" */
	if (parser->cur >= parser->end || parser->cur[0] != ':')
		return -1;
	parser->cur++;

	/* minute = 2DIGIT */
	if (http_date_parse_number(parser, 2, &parser->tm.tm_min) <= 0)
		return -1;

	/* ":" */
	if (parser->cur >= parser->end || parser->cur[0] != ':')
		return -1;
	parser->cur++;

	/* second = 2DIGIT */
	if (http_date_parse_number(parser, 2, &parser->tm.tm_sec) <= 0)
		return -1;
	return 1;
}

static inline int
http_date_parse_time_gmt(struct http_date_parser *parser)
{
	string_t *gmt;

	/* Remaining: 	 {...} SP time-of-day SP GMT
	 */

	/* SP time-of-day */
	if (http_date_parse_sp(parser) <= 0)
		return -1;
	if (http_date_parse_time_of_day(parser) <= 0)
		return -1;

	/* SP GMT */
	if (http_date_parse_sp(parser) <= 0)
		return -1;
	if (http_date_parse_word(parser, 3, &gmt) <= 0 ||
		strcmp("GMT", str_c(gmt)) != 0)
		return -1;
	return 1;
}

static int
http_date_parse_format_rfc1123(struct http_date_parser *parser)
{
	/*
	 rfc1123-date = day-name "," SP date1 SP time-of-day SP GMT
	                ; fixed length subset of the format defined in
	                ; Section 5.2.14 of [RFC1123]
	 date1        = day SP month SP year
	                ; e.g., 02 Jun 1982
	 
	 Remaining: 	 {...} SP day SP month SP year SP time-of-day SP GMT

	 */

	/* SP day */
	if (http_date_parse_sp(parser) <= 0)
		return -1;
	if (http_date_parse_day(parser) <= 0)
		return -1;

	/* SP month */
	if (http_date_parse_sp(parser) <= 0)
		return -1;
	if (http_date_parse_month(parser) <= 0)
		return -1;

	/* SP year */
	if (http_date_parse_sp(parser) <= 0)
		return -1;
	if (http_date_parse_year(parser) <= 0)
		return -1;

	/* SP time-of-day SP GMT */
	return http_date_parse_time_gmt(parser);
}

static int
http_date_parse_format_rfc850(struct http_date_parser *parser)
{
	/* 
	 rfc850-date  = day-name-l "," SP date2 SP time-of-day SP GMT
	 date2        = day "-" month "-" 2DIGIT
		              ; day-month-year (e.g., 02-Jun-82)

	 Remaining: "," SP day "-" month "-" 2DIGIT SP time-of-day SP GMT
	 */

	/* "," SP */
	if (parser->cur >= parser->end || parser->cur[0] != ',')
		return -1;
	parser->cur++;
	if (http_date_parse_sp(parser) <= 0)
		return -1;

	/* day */
	if (http_date_parse_day(parser) <= 0)
		return -1;	

	/* "-" */
	if (parser->cur >= parser->end || parser->cur[0] != '-')
		return -1;
	parser->cur++;

	/* month */
	if (http_date_parse_month(parser) <= 0)
		return -1;	

	/* "-" */
	if (parser->cur >= parser->end || parser->cur[0] != '-')
		return -1;
	parser->cur++;

	/* 2DIGIT */
	if (http_date_parse_number(parser, 2, &parser->tm.tm_year) <= 0)
		return -1;
	if (parser->tm.tm_year < 70)
		parser->tm.tm_year += 100;

	/* SP time-of-day SP GMT */
	return http_date_parse_time_gmt(parser);
}

static int
http_date_parse_format_asctime(struct http_date_parser *parser)
{
	int ret;

	/*
	 asctime-date = day-name SP date3 SP time-of-day SP year
	 date3        = month SP ( 2DIGIT / ( SP 1DIGIT ))
		              ; month day (e.g., Jun  2)

	 Remaining: {...} month SP ( 2DIGIT / ( SP 1DIGIT )) SP time-of-day SP year
	*/

	/* month */
	if (http_date_parse_month(parser) <= 0)
		return -1;

	/* SP */
	if (http_date_parse_sp(parser) <= 0)
		return -1;

	/* SP 1DIGIT / 2DIGIT */
	if ((ret=http_date_parse_sp(parser)) < 0)
		return -1;
	if (ret == 0) {
		if (http_date_parse_number(parser, 2, &parser->tm.tm_mday) <= 0)
			return -1;
	} else {
		if (http_date_parse_number(parser, 1, &parser->tm.tm_mday) <= 0)
			return -1;
	}

	/* SP time-of-day */
	if (http_date_parse_sp(parser) <= 0)
		return -1;
	if (http_date_parse_time_of_day(parser) <= 0)
		return -1;

	/* SP year */
	if (http_date_parse_sp(parser) <= 0)
		return -1;

	return http_date_parse_year(parser);
}

static int
http_date_parse_format_any(struct http_date_parser *parser)
{
	string_t *dayname;
	int i;

	/*
	 HTTP-date    = rfc1123-date / obs-date
	 rfc1123-date = day-name "," SP date1 SP time-of-day SP GMT
	                ; fixed length subset of the format defined in
	                ; Section 5.2.14 of [RFC1123]
	 obs-date     = rfc850-date / asctime-date
	 rfc850-date  = day-name-l "," SP date2 SP time-of-day SP GMT
	 asctime-date = day-name SP date3 SP time-of-day SP year
	 */

	if (http_date_parse_word(parser, 9, &dayname) <= 0)
		return -1;
	
	if (str_len(dayname) > 3) {
		/* rfc850-date */
		for (i = 0; i < 7; i++) {
			if (strcmp(weekday_names_long[i], str_c(dayname)) == 0) {
				break;
			}
		}
		if (i >= 7)
			return -1;
		return http_date_parse_format_rfc850(parser);
	}

	/* rfc1123-date / asctime-date */
	for (i = 0; i < 7; i++) {
		if (strcmp(weekday_names[i], str_c(dayname)) == 0) {
			break;
		}
	}

	if (i >= 7 || parser->cur >= parser->end)
		return -1;

	if (parser->cur[0] == ' ') {
		/* asctime-date */
		parser->cur++;
		return http_date_parse_format_asctime(parser);
	}

	if (parser->cur[0] != ',')
		return -1;

	/* rfc1123-date */
	parser->cur++;
	return http_date_parse_format_rfc1123(parser);
}

bool http_date_parse(const unsigned char *data, size_t size,
			time_t *timestamp_r)
{
	struct http_date_parser parser;
	time_t timestamp;
	
	memset(&parser, 0, sizeof(parser));
	parser.cur = data;
	parser.end = data + size;

	if (http_date_parse_format_any(&parser) <= 0)
		return FALSE;

	if (parser.cur != parser.end)
		return FALSE;

	parser.tm.tm_isdst = -1;
	timestamp = utc_mktime(&parser.tm);
	if (timestamp == (time_t)-1)
		return FALSE;

	*timestamp_r = timestamp;
	return TRUE;
}

bool http_date_parse_tm(const unsigned char *data, size_t size,
			   struct tm *tm_r)
{
	time_t timestamp;
	struct tm *tm;

	if (!http_date_parse(data, size, &timestamp))
		return FALSE;

	tm = gmtime(&timestamp);
	*tm_r = *tm;
	return TRUE;
}

const char *http_date_create_tm(struct tm *tm)
{
	return t_strdup_printf("%s, %02d %s %04d %02d:%02d:%02d GMT",
			       weekday_names[tm->tm_wday],
			       tm->tm_mday,
			       month_names[tm->tm_mon],
			       tm->tm_year+1900,
			       tm->tm_hour, tm->tm_min, tm->tm_sec);
}

const char *http_date_create(time_t timestamp)
{
	struct tm *tm;
	tm = gmtime(&timestamp);

	return http_date_create_tm(tm);
}

