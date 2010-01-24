/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "utc-offset.h"
#include "utc-mktime.h"
#include "imap-date.h"

#include <ctype.h>

static const char *month_names[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static int parse_timezone(const char *str)
{
	int offset;

	/* +|-zone */
	if ((*str != '+' && *str != '-') ||
	    !i_isdigit(str[1]) || !i_isdigit(str[2]) ||
	    !i_isdigit(str[3]) || !i_isdigit(str[4]))
		return 0;

	offset = (str[1]-'0') * 10*60 + (str[2]-'0') * 60 +
		(str[3]-'0') * 10 + (str[4]-'0');
	return *str == '+' ? offset : -offset;
}

static const char *imap_parse_date_internal(const char *str, struct tm *tm)
{
	int i;

	if (str == NULL || *str == '\0')
		return NULL;

	memset(tm, 0, sizeof(struct tm));

	/* "dd-mon-yyyy [hh:mi:ss +|-zone]"
	   dd is 1-2 digits and may be prefixed with space or zero. */

	if (str[0] == ' ') {
		/* " d-..." */
		str++;
	}

	if (!(i_isdigit(str[0]) && (str[1] == '-' ||
				    (i_isdigit(str[1]) && str[2] == '-'))))
	      return NULL;

	tm->tm_mday = (str[0]-'0');
	if (str[1] == '-')
		str += 2;
	else {
		tm->tm_mday = (tm->tm_mday * 10) + (str[1]-'0');
		str += 3;
	}

	/* month name */
	for (i = 0; i < 12; i++) {
		if (strncasecmp(month_names[i], str, 3) == 0) {
			tm->tm_mon = i;
			break;
		}
	}
	if (i == 12 || str[3] != '-')
		return NULL;
	str += 4;

	/* yyyy */
	if (!i_isdigit(str[0]) || !i_isdigit(str[1]) ||
	    !i_isdigit(str[2]) || !i_isdigit(str[3]))
		return NULL;

	tm->tm_year = (str[0]-'0') * 1000 + (str[1]-'0') * 100 +
		(str[2]-'0') * 10 + (str[3]-'0') - 1900;

	str += 4;
	return str;
}

static bool imap_mktime(struct tm *tm, time_t *time_r)
{
	*time_r = utc_mktime(tm);
	if (*time_r != (time_t)-1)
		return TRUE;

	/* the date is outside valid range for time_t. it might still be
	   technically valid though, so try to handle this case.
	   with 64bit time_t the full 0..9999 year range is valid. */
	if (tm->tm_year <= 100) {
		/* too old. time_t can be signed or unsigned, handle
		   both cases. */
		*time_r = (time_t)-1 < (int)0 ? INT_MIN : 0;
	} else {
		/* too high. return the highest allowed value.
		   we shouldn't get here with 64bit time_t,
		   but handle that anyway. */
#if (TIME_T_MAX_BITS == 32 || TIME_T_MAX_BITS == 64)
		*time_r = (1UL << (TIME_T_MAX_BITS-1)) - 1;
#else
		*time_r = (1UL << TIME_T_MAX_BITS) - 1;
#endif
	}
	return FALSE;
}

bool imap_parse_date(const char *str, time_t *timestamp_r)
{
	struct tm tm;

	str = imap_parse_date_internal(str, &tm);
	if (str == NULL || str[0] != '\0')
		return FALSE;

	tm.tm_isdst = -1;
	(void)imap_mktime(&tm, timestamp_r);
	return TRUE;
}

bool imap_parse_datetime(const char *str, time_t *timestamp_r,
			 int *timezone_offset_r)
{
	struct tm tm;

	str = imap_parse_date_internal(str, &tm);
	if (str == NULL)
		return FALSE;

	if (str[0] != ' ')
		return FALSE;
	str++;

	/* hh: */
	if (!i_isdigit(str[0]) || !i_isdigit(str[1]) || str[2] != ':')
		return FALSE;
	tm.tm_hour = (str[0]-'0') * 10 + (str[1]-'0');
	str += 3;

	/* mm: */
	if (!i_isdigit(str[0]) || !i_isdigit(str[1]) || str[2] != ':')
		return FALSE;
	tm.tm_min = (str[0]-'0') * 10 + (str[1]-'0');
	str += 3;

	/* ss */
	if (!i_isdigit(str[0]) || !i_isdigit(str[1]) || str[2] != ' ')
		return FALSE;
	tm.tm_sec = (str[0]-'0') * 10 + (str[1]-'0');
	str += 3;

	/* timezone */
	*timezone_offset_r = parse_timezone(str);

	tm.tm_isdst = -1;
	if (imap_mktime(&tm, timestamp_r))
		*timestamp_r -= *timezone_offset_r * 60;
	return TRUE;
}

static const char *
imap_to_datetime_tm(const struct tm *tm, int timezone_offset)
{
	char *buf;
	int year;

	/* @UNSAFE: but faster than t_strdup_printf() call.. */
	buf = t_malloc(27);

	/* dd-mon- */
	buf[0] = (tm->tm_mday / 10) + '0';
	buf[1] = (tm->tm_mday % 10) + '0';
	buf[2] = '-';
	memcpy(buf+3, month_names[tm->tm_mon], 3);
	buf[6] = '-';

	/* yyyy */
	year = tm->tm_year + 1900;
	buf[7] = (year / 1000) + '0';
	buf[8] = ((year / 100) % 10) + '0';
	buf[9] = ((year / 10) % 10) + '0';
	buf[10] = (year % 10) + '0';
	buf[11] = ' ';

	/* hh:mi:ss */
	buf[12] = (tm->tm_hour / 10) + '0';
	buf[13] = (tm->tm_hour % 10) + '0';
	buf[14] = ':';
	buf[15] = (tm->tm_min / 10) + '0';
	buf[16] = (tm->tm_min % 10) + '0';
	buf[17] = ':';
	buf[18] = (tm->tm_sec / 10) + '0';
	buf[19] = (tm->tm_sec % 10) + '0';
	buf[20] = ' ';

	/* timezone */
	if (timezone_offset >= 0)
		buf[21] = '+';
	else {
		buf[21] = '-';
		timezone_offset = -timezone_offset;
	}
	buf[22] = (timezone_offset / 600) + '0';
	buf[23] = ((timezone_offset / 60) % 10) + '0';
	buf[24] = ((timezone_offset % 60) / 10) + '0';
	buf[25] = (timezone_offset % 10) + '0';
	buf[26] = '\0';

	return buf;
}

const char *imap_to_datetime(time_t timestamp)
{
	struct tm *tm;
	int timezone_offset;

	tm = localtime(&timestamp);
	timezone_offset = utc_offset(tm, timestamp);
	return imap_to_datetime_tm(tm, timezone_offset);
}

const char *imap_to_datetime_tz(time_t timestamp, int timezone_offset)
{
	const struct tm *tm;
	time_t adjusted = timestamp + timezone_offset*60;

	tm = gmtime(&adjusted);
	return imap_to_datetime_tm(tm, timezone_offset);
}
