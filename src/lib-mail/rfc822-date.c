/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "utc-offset.h"
#include "utc-mktime.h"
#include "rfc822-date.h"
#include "rfc822-tokenize.h"

#include <ctype.h>

static const char *month_names[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

static const char *weekday_names[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
};

static int parse_timezone(const unsigned char *str, size_t len)
{
	int offset;
	char chr;

	if (len == 5 && (*str == '+' || *str == '-')) {
		/* numeric offset */
		if (!i_isdigit(str[1]) || !i_isdigit(str[2]) ||
		    !i_isdigit(str[3]) || !i_isdigit(str[4]))
			return FALSE;

		offset = (str[1]-'0') * 1000 + (str[2]-'0') * 100 +
			(str[3]-'0') * 10 + (str[4]-'0');
		return *str == '+' ? offset : -offset;
	}

	if (len == 1) {
		/* military zone - handle them the correct way, not as
		   RFC822 says. RFC2822 though suggests that they'd be
		   considered as unspecified.. */
		chr = i_toupper(*str);
		if (chr < 'J')
			return (*str-'A'+1) * 60;
		if (chr == 'J')
			return 0;
		if (chr <= 'M')
			return (*str-'A') * 60;
		if (chr < 'Z')
			return ('M'-*str) * 60;
		return 0;
	}

	if (len == 2 && i_toupper(str[0]) == 'U' && i_toupper(str[1]) == 'T') {
		/* UT - Universal Time */
		return 0;
	}

	if (len == 3) {
		/* GMT | [ECMP][DS]T */
		if (str[2] != 'T')
			return 0;

		switch (i_toupper(*str)) {
		case 'E':
			offset = -5 * 60;
			break;
		case 'C':
			offset = -6 * 60;
			break;
		case 'M':
			offset = -7 * 60;
			break;
		case 'P':
			offset = -8 * 60;
			break;
		default:
			/* GMT and others */
			return 0;
		}

		if (i_toupper(str[1]) == 'D')
			return offset + 60;
		if (i_toupper(str[1]) == 'S')
			return offset;
	}

	return 0;
}

static Rfc822Token next_token(Rfc822TokenizeContext *ctx,
			      const unsigned char **value, size_t *value_len)
{
	Rfc822Token token;

	token = rfc822_tokenize_next(ctx);
	if (token == 'A')
		*value = rfc822_tokenize_get_value(ctx, value_len);
	return token;
}

static int rfc822_parse_date_tokens(Rfc822TokenizeContext *ctx, time_t *time,
				    int *timezone_offset)
{
	struct tm tm;
	Rfc822Token token;
	const unsigned char *value;
	size_t i, len;

	/* [weekday_name "," ] dd month_name [yy]yy hh:mi[:ss] timezone */
	memset(&tm, 0, sizeof(tm));

	/* skip the optional weekday */
	token = next_token(ctx, &value, &len);
	if (token == 'A' && len == 3) {
		token = next_token(ctx, &value, &len);
		if (token != ',')
			return FALSE;

		token = next_token(ctx, &value, &len);
	}

	/* dd */
	if (token != 'A' || len > 2 || !i_isdigit(value[0]))
		return FALSE;

	tm.tm_mday = value[0]-'0';
	if (len == 2) {
		if (!i_isdigit(value[1]))
			return FALSE;
		tm.tm_mday = (tm.tm_mday * 10) + (value[1]-'0');
	}

	/* month name */
	token = next_token(ctx, &value, &len);
	if (token != 'A' || len != 3)
		return FALSE;

	for (i = 0; i < 12; i++) {
		if (memcasecmp(month_names[i], value, 3) == 0) {
			tm.tm_mon = i;
			break;
		}
	}
	if (i == 12)
		return FALSE;

	/* [yy]yy */
	token = next_token(ctx, &value, &len);
	if (token != 'A' || (len != 2 && len != 4))
		return FALSE;

	for (i = 0; i < len; i++) {
		if (!i_isdigit(value[i]))
			return FALSE;
		tm.tm_year = tm.tm_year * 10 + (value[i]-'0');
	}

	if (len == 2) {
		/* two digit year, assume 1970+ */
		if (tm.tm_year < 70)
			tm.tm_year += 100;
	} else {
		if (tm.tm_year < 1900)
			return FALSE;
		tm.tm_year -= 1900;
	}

	/* hh */
	token = next_token(ctx, &value, &len);
	if (token != 'A' || len != 2 ||
	    !i_isdigit(value[0]) || !i_isdigit(value[1]))
		return FALSE;
	tm.tm_hour = (value[0]-'0') * 10 + (value[1]-'0');

	/* :mm */
	token = next_token(ctx, &value, &len);
	if (token != ':')
		return FALSE;
	token = next_token(ctx, &value, &len);
	if (token != 'A' || len != 2 ||
	    !i_isdigit(value[0]) || !i_isdigit(value[1]))
		return FALSE;
	tm.tm_min = (value[0]-'0') * 10 + (value[1]-'0');

	/* [:ss] */
	token = next_token(ctx, &value, &len);
	if (token == ':') {
		token = next_token(ctx, &value, &len);
		if (token != 'A' || len != 2 ||
		    !i_isdigit(value[0]) || !i_isdigit(value[1]))
			return FALSE;
		tm.tm_sec = (value[0]-'0') * 10 + (value[1]-'0');
	}

	/* timezone */
	if (token != 'A')
		return FALSE;
	*timezone_offset = parse_timezone(value, len);

	tm.tm_isdst = -1;
	*time = utc_mktime(&tm);
	if (*time == (time_t)-1)
		return FALSE;

	*time -= *timezone_offset;

	return TRUE;
}

int rfc822_parse_date(const char *data, time_t *time, int *timezone_offset)
{
	Rfc822TokenizeContext *ctx;
	int ret;

	if (data == NULL || *data == '\0')
		return FALSE;

	ctx = rfc822_tokenize_init((const unsigned char *) data, (size_t)-1,
				   NULL, NULL);
	ret = rfc822_parse_date_tokens(ctx, time, timezone_offset);
	rfc822_tokenize_deinit(ctx);

	return ret;
}

const char *rfc822_to_date(time_t time)
{
	struct tm *tm;
	int offset, negative;

	tm = localtime(&time);
	offset = utc_offset(tm, time);
	if (offset >= 0)
		negative = 0;
	else {
		negative = 1;
		offset = -offset;
	}

	return t_strdup_printf("%s, %02d %s %04d %02d:%02d:%02d %c%02d%02d",
			       weekday_names[tm->tm_wday],
			       tm->tm_mday,
			       month_names[tm->tm_mon],
			       tm->tm_year+1900,
			       tm->tm_hour, tm->tm_min, tm->tm_sec,
			       negative ? '-' : '+', offset / 60, offset % 60);
}
