/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
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

time_t mbox_from_parse_date(const char *msg, size_t size)
{
	const char *msg_end;
	struct tm tm;
	int i;

	/* <sender> <date> <moreinfo> */
	msg_end = msg + size;

	/* skip sender */
	while (*msg != ' ' && msg < msg_end) msg++;
	while (*msg == ' ' && msg < msg_end) msg++;

	/* next 24 chars are the date in asctime() format,
	   eg. "Thu Nov 29 22:33:52 2001" */
	if (msg+24 > msg_end)
		return (time_t)-1;

	memset(&tm, 0, sizeof(tm));

	/* skip weekday */
	msg += 4;

	/* month */
	for (i = 0; i < 12; i++) {
		if (strncasecmp(months[i], msg, 3) == 0) {
			tm.tm_mon = i;
			break;
		}
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

	/* year */
	if (!i_isdigit(msg[0]) || !i_isdigit(msg[1]) ||
	    !i_isdigit(msg[2]) || !i_isdigit(msg[3]))
		return (time_t)-1;
	tm.tm_year = (msg[0]-'0') * 1000 + (msg[1]-'0') * 100 +
		(msg[2]-'0') * 10 + (msg[3]-'0') - 1900;

	tm.tm_isdst = -1;
	return mktime(&tm);
}

const char *mbox_from_create(const char *sender, time_t time)
{
	String *str;
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
