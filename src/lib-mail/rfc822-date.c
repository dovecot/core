/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "gmtoff.h"
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

static int parse_timezone(const char *str, unsigned int len)
{
	int offset;
	char chr;

	if (len == 5 && (*str == '+' || *str == '-')) {
		/* numeric offset */
		if (!i_isdigit(str[0]) || !i_isdigit(str[1]) ||
		    !i_isdigit(str[1]) || !i_isdigit(str[2]))
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
		if (i_toupper(str[1] == 'S'))
			return offset;
	}

	return 0;
}

static const Rfc822Token *next_token(const Rfc822Token **tokens)
{
	const Rfc822Token *ret;

	if ((*tokens)->token == 0)
		return NULL;

	ret = *tokens;
	(*tokens)++;
	return ret;
}

int rfc822_parse_date(const char *str, time_t *time)
{
	struct tm tm;
	const Rfc822Token *tokens, *tok;
	unsigned int i;
	int zone_offset;

	if (str == NULL || *str == '\0')
		return FALSE;

	/* [weekday_name "," ] dd month_name [yy]yy hh:mi[:ss] timezone

	   we support comments here even while no-one ever uses them */

	tokens = rfc822_tokenize(str, NULL, NULL, NULL);

	memset(&tm, 0, sizeof(tm));

	/* skip the optional weekday */
	tok = next_token(&tokens);
	if (tok != NULL && tok->token == 'A' && tok->len == 3) {
		tok = next_token(&tokens);
		if (tok == NULL || tok->token != ',')
			return FALSE;

		tok = next_token(&tokens);
	}

	/* dd */
	if (tok == NULL || tok->token != 'A' || tok->len != 2 ||
	    !i_isdigit(tok->ptr[0]) || !i_isdigit(tok->ptr[1]))
		return FALSE;
	tm.tm_mday = (tok->ptr[0]-'0') * 10 + (tok->ptr[1]-'0');

	/* month name */
	tok = next_token(&tokens);
	if (tok == NULL || tok->token != 'A' || tok->len != 3)
		return FALSE;

	for (i = 0; i < 12; i++) {
		if (strncasecmp(month_names[i], tok->ptr, 3) == 0) {
			tm.tm_mon = i;
			break;
		}
	}
	if (i == 12)
		return FALSE;

	/* [yy]yy */
	tok = next_token(&tokens);
	if (tok == NULL || tok->token != 'A' ||
	    (tok->len != 2 && tok->len != 4))
		return FALSE;

	for (i = 0; i < tok->len; i++) {
		if (!i_isdigit(tok->ptr[i]))
			return FALSE;
		tm.tm_year = tm.tm_year * 10 + (tok->ptr[i]-'0');
	}

	if (tok->len == 2) {
		/* two digit year, assume 1970+ */
		if (tm.tm_year < 70)
			tm.tm_year += 100;
	} else {
		if (tm.tm_year < 1900)
			return FALSE;
		tm.tm_year -= 1900;
	}

	/* hh */
	tok = next_token(&tokens);
	if (tok == NULL || tok->token != 'A' || tok->len != 2 ||
	    !i_isdigit(tok->ptr[0]) || !i_isdigit(tok->ptr[1]))
		return FALSE;
	tm.tm_hour = (tok->ptr[0]-'0') * 10 + (tok->ptr[1]-'0');

	/* :mm */
	tok = next_token(&tokens);
	if (tok == NULL || tok->token != ':')
		return FALSE;
	tok = next_token(&tokens);
	if (tok == NULL || tok->token != 'A' || tok->len != 2 ||
	    !i_isdigit(tok->ptr[0]) || !i_isdigit(tok->ptr[1]))
		return FALSE;
	tm.tm_min = (tok->ptr[0]-'0') * 10 + (tok->ptr[1]-'0');

	/* [:ss] */
	tok = next_token(&tokens);
	if (tok != NULL && tok->token == ':') {
		tok = next_token(&tokens);
		if (tok == NULL || tok->token != 'A' || tok->len != 2 ||
		    !i_isdigit(tok->ptr[0]) || !i_isdigit(tok->ptr[1]))
			return FALSE;
		tm.tm_sec = (tok->ptr[0]-'0') * 10 + (tok->ptr[1]-'0');
	}

	/* timezone */
	if (tok == NULL || tok->token != 'A')
		return FALSE;

	zone_offset = parse_timezone(tok->ptr, tok->len);

	tm.tm_isdst = -1;
	*time = mktime(&tm);
	if (*time < 0)
		return FALSE;

	*time -= zone_offset * 60;
	return TRUE;
}

const char *rfc822_to_date(time_t time)
{
	struct tm *tm;
	int offset, negative;

	tm = localtime(&time);
	offset = gmtoff(tm, time);
	if (offset >= 0)
		negative = 0;
	else {
		negative = 1;
		offset = -offset;
	}
	offset /= 60;

	return t_strdup_printf("%s, %02d %s %04d %02d:%02d:%02d %c%02d%02d",
			       weekday_names[tm->tm_wday],
			       tm->tm_mday,
			       month_names[tm->tm_mon],
			       tm->tm_year+1900,
			       tm->tm_hour, tm->tm_min, tm->tm_sec,
			       negative ? '-' : '+', offset / 60, offset % 60);
}
