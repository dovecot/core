/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "utc-mktime.h"
#include "mbox-index.h"

#include <time.h>
#include <ctype.h>

static const char *weekdays[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static const char *months[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

time_t mbox_from_parse_date(const unsigned char *msg, size_t size)
{
	const unsigned char *msg_end;
	struct tm tm;
	int i, timezone;
	time_t t;

	/* <sender> <date> <moreinfo> */
	msg_end = msg + size;

	/* skip sender */
	while (msg < msg_end && *msg != ' ') {
		if (*msg == '\r' || *msg == '\n')
			return (time_t)-1;
		msg++;
	}
	while (msg < msg_end && *msg == ' ') msg++;

	/* next 24 chars should be in the date in asctime() format, eg.
	   "Thu Nov 29 22:33:52 2001 +0300"

	   Some also include named timezone, which we ignore:

	   "Thu Nov 29 22:33:52 EEST 2001"
	*/
	if (msg+24 > msg_end)
		return (time_t)-1;

	memset(&tm, 0, sizeof(tm));

	/* skip weekday */
	msg += 4;

	/* month */
	for (i = 0; i < 12; i++) {
		if (memcasecmp(months[i], msg, 3) == 0) {
			tm.tm_mon = i;
			break;
		}
	}

	if (i == 12 && memcmp(msg, "???", 3) == 0) {
		/* just a hack to parse one special mbox I have :) */
		i = 0;
	}

	if (i == 12 || msg[3] != ' ')
		return (time_t)-1;
	msg += 4;

	/* day */
	if (msg[0] == ' ') {
		if (!i_isdigit(msg[1]) || msg[2] != ' ')
			return (time_t)-1;
		tm.tm_mday = msg[1]-'0';
	} else {
		if (!i_isdigit(msg[0]) || !i_isdigit(msg[1]) || msg[2] != ' ')
			return (time_t)-1;
		tm.tm_mday = (msg[0]-'0') * 10 + (msg[1]-'0');
	}
	if (tm.tm_mday == 0)
		tm.tm_mday = 1;
	msg += 3;

	/* hour */
	if (!i_isdigit(msg[0]) || !i_isdigit(msg[1]) || msg[2] != ':')
		return (time_t)-1;
	tm.tm_hour = (msg[0]-'0') * 10 + (msg[1]-'0');
	msg += 3;

	/* minute */
	if (!i_isdigit(msg[0]) || !i_isdigit(msg[1]) || msg[2] != ':')
		return (time_t)-1;
	tm.tm_min = (msg[0]-'0') * 10 + (msg[1]-'0');
	msg += 3;

	/* second */
	if (!i_isdigit(msg[0]) || !i_isdigit(msg[1]) || msg[2] != ' ')
		return (time_t)-1;
	tm.tm_sec = (msg[0]-'0') * 10 + (msg[1]-'0');
	msg += 3;

	/* optional named timezone */
	if (!i_isdigit(msg[0]) || !i_isdigit(msg[1]) ||
	    !i_isdigit(msg[2]) || !i_isdigit(msg[3])) {
		/* skip to next space */
		while (msg < msg_end && *msg != ' ') {
			if (*msg == '\r' || *msg == '\n')
				return (time_t)-1;
			msg++;
		}
		if (msg+5 > msg_end)
			return (time_t)-1;
		msg++;
	}

	/* year */
	if (!i_isdigit(msg[0]) || !i_isdigit(msg[1]) ||
	    !i_isdigit(msg[2]) || !i_isdigit(msg[3]))
		return (time_t)-1;

	tm.tm_year = (msg[0]-'0') * 1000 + (msg[1]-'0') * 100 +
		(msg[2]-'0') * 10 + (msg[3]-'0') - 1900;
	msg += 4;

	tm.tm_isdst = -1;
	if (msg[0] == ' ' && (msg[1] == '-' || msg[1] == '+') &&
	    i_isdigit(msg[2]) && i_isdigit(msg[3]) &&
	    i_isdigit(msg[4]) && i_isdigit(msg[5])) {
		timezone = (msg[2]-'0') * 1000 + (msg[3]-'0') * 100 +
			(msg[4]-'0') * 10 +(msg[5]-'0');
		if (msg[1] == '-') timezone = -timezone;

		t = utc_mktime(&tm);
		if (t == (time_t)-1)
			return (time_t)-1;

		t -= timezone * 60;
		return t;
	} else {
		/* assume local timezone */
		return mktime(&tm);
	}
}

const char *mbox_from_create(const char *sender, time_t time)
{
	string_t *str;
	struct tm *tm;
	int year;

	str = t_str_new(256);
	str_append(str, "From ");
	str_append(str, sender);
	str_append(str, "  ");

	/* we could use simply asctime(), but i18n etc. may break it.
	   Example: "Thu Nov 29 22:33:52 2001" */
	tm = localtime(&time);

	/* week day */
	str_append(str, weekdays[tm->tm_wday]);
	str_append_c(str, ' ');

	/* month */
	str_append(str, months[tm->tm_mon]);
	str_append_c(str, ' ');

	/* day */
	str_append_c(str, (tm->tm_mday / 10) + '0');
	str_append_c(str, (tm->tm_mday % 10) + '0');
	str_append_c(str, ' ');

	/* hour */
	str_append_c(str, (tm->tm_hour / 10) + '0');
	str_append_c(str, (tm->tm_hour % 10) + '0');
	str_append_c(str, ':');

	/* minute */
	str_append_c(str, (tm->tm_min / 10) + '0');
	str_append_c(str, (tm->tm_min % 10) + '0');
	str_append_c(str, ':');

	/* second */
	str_append_c(str, (tm->tm_sec / 10) + '0');
	str_append_c(str, (tm->tm_sec % 10) + '0');
	str_append_c(str, ' ');

	/* year */
	year = tm->tm_year + 1900;
	str_append_c(str, (year / 1000) + '0');
	str_append_c(str, ((year / 100) % 10) + '0');
	str_append_c(str, ((year / 10) % 10) + '0');
	str_append_c(str, (year % 10) + '0');

	str_append_c(str, '\n');
	return str_c(str);
}
