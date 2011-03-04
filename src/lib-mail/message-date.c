/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "utc-offset.h"
#include "utc-mktime.h"
#include "rfc822-parser.h"
#include "message-date.h"

#include <ctype.h>

struct message_date_parser_context {
	struct rfc822_parser_context parser;
	string_t *str;
};

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

		offset = ((str[1]-'0') * 10 + (str[2]-'0')) * 60  +
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

static int next_token(struct message_date_parser_context *ctx,
		      const unsigned char **value, size_t *value_len)
{
	int ret;

	str_truncate(ctx->str, 0);
	ret = ctx->parser.data == ctx->parser.end ? 0 :
		rfc822_parse_atom(&ctx->parser, ctx->str);

	*value = str_data(ctx->str);
	*value_len = str_len(ctx->str);
	return ret < 0 ? -1 : *value_len > 0;
}

static bool
message_date_parser_tokens(struct message_date_parser_context *ctx,
			   time_t *timestamp_r, int *timezone_offset_r)
{
	struct tm tm;
	const unsigned char *value;
	size_t i, len;
	int ret;

	/* [weekday_name "," ] dd month_name [yy]yy hh:mi[:ss] timezone */
	memset(&tm, 0, sizeof(tm));

        (void)rfc822_skip_lwsp(&ctx->parser);

	/* skip the optional weekday */
	if (next_token(ctx, &value, &len) <= 0)
		return FALSE;
	if (len == 3) {
		if (*ctx->parser.data != ',')
			return FALSE;
		ctx->parser.data++;
		(void)rfc822_skip_lwsp(&ctx->parser);

		if (next_token(ctx, &value, &len) <= 0)
			return FALSE;
	}

	/* dd */
	if (len < 1 || len > 2 || !i_isdigit(value[0]))
		return FALSE;

	tm.tm_mday = value[0]-'0';
	if (len == 2) {
		if (!i_isdigit(value[1]))
			return FALSE;
		tm.tm_mday = (tm.tm_mday * 10) + (value[1]-'0');
	}

	/* month name */
	if (next_token(ctx, &value, &len) <= 0 || len < 3)
		return FALSE;

	for (i = 0; i < 12; i++) {
		if (i_memcasecmp(month_names[i], value, 3) == 0) {
			tm.tm_mon = i;
			break;
		}
	}
	if (i == 12)
		return FALSE;

	/* [yy]yy */
	if (next_token(ctx, &value, &len) <= 0 || (len != 2 && len != 4))
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

	/* hh, allow also single digit */
	if (next_token(ctx, &value, &len) <= 0 ||
	    len < 1 || len > 2 || !i_isdigit(value[0]))
		return FALSE;
	tm.tm_hour = value[0]-'0';
	if (len == 2) {
		if (!i_isdigit(value[1]))
			return FALSE;
		tm.tm_hour = tm.tm_hour * 10 + (value[1]-'0');
	}

	/* :mm (may be the last token) */
	if (*ctx->parser.data != ':')
		return FALSE;
	ctx->parser.data++;
	(void)rfc822_skip_lwsp(&ctx->parser);

	if (next_token(ctx, &value, &len) < 0 || len != 2 ||
	    !i_isdigit(value[0]) || !i_isdigit(value[1]))
		return FALSE;
	tm.tm_min = (value[0]-'0') * 10 + (value[1]-'0');

	/* [:ss] */
	if (ctx->parser.data != ctx->parser.end && *ctx->parser.data == ':') {
		ctx->parser.data++;
		(void)rfc822_skip_lwsp(&ctx->parser);

		if (next_token(ctx, &value, &len) <= 0 || len != 2 ||
		    !i_isdigit(value[0]) || !i_isdigit(value[1]))
			return FALSE;
		tm.tm_sec = (value[0]-'0') * 10 + (value[1]-'0');
	}

	if ((ret = next_token(ctx, &value, &len)) < 0)
		return FALSE;
	if (ret == 0) {
		/* missing timezone */
		*timezone_offset_r = 0;
	} else {
		/* timezone */
		*timezone_offset_r = parse_timezone(value, len);
	}

	tm.tm_isdst = -1;
	*timestamp_r = utc_mktime(&tm);
	if (*timestamp_r == (time_t)-1)
		return FALSE;

	*timestamp_r -= *timezone_offset_r * 60;

	return TRUE;
}

bool message_date_parse(const unsigned char *data, size_t size,
			time_t *timestamp_r, int *timezone_offset_r)
{
	bool success;

	T_BEGIN {
		struct message_date_parser_context ctx;

		rfc822_parser_init(&ctx.parser, data, size, NULL);
		ctx.str = t_str_new(128);
		success = message_date_parser_tokens(&ctx, timestamp_r,
						     timezone_offset_r);
	} T_END;

	return success;
}

const char *message_date_create(time_t timestamp)
{
	struct tm *tm;
	int offset;
	bool negative;

	tm = localtime(&timestamp);
	offset = utc_offset(tm, timestamp);
	if (offset >= 0)
		negative = FALSE;
	else {
		negative = TRUE;
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
