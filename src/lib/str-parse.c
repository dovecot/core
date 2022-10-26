/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str-parse.h"

#include <ctype.h>

static int str_parse_get_interval_full(
	const char *str, unsigned int *interval_r, bool milliseconds,
	const char **error_r)
{
	uintmax_t num, multiply = milliseconds ? 1000 : 1;
	const char *p;

	if (str_parse_uintmax(str, &num, &p) < 0) {
		*error_r = t_strconcat("Invalid time interval: ", str, NULL);
		return -1;
	}
	while (*p == ' ') p++;
	if (*p == '\0' && num != 0) {
		*error_r = t_strdup_printf("Time interval '%s' is missing units "
			"(add e.g. 's' for seconds)", str);
		return -1;
	}
	switch (i_toupper(*p)) {
	case 'S':
		multiply *= 1;
		if (str_begins_icase_with("secs", p) ||
		    str_begins_icase_with("seconds", p))
			p = "";
		break;
	case 'M':
		multiply *= 60;
		if (str_begins_icase_with("mins", p) ||
		    str_begins_icase_with("minutes", p))
			p = "";
		else if (str_begins_icase_with("msecs", p) ||
			 str_begins_icase_with("mseconds", p) ||
			 str_begins_icase_with("millisecs", p) ||
			 str_begins_icase_with("milliseconds", p)) {
			if (milliseconds || (num % 1000) == 0) {
				if (!milliseconds) {
					/* allow ms also for seconds, as long
					   as it's divisible by seconds */
					num /= 1000;
				}
				multiply = 1;
				p = "";
				break;
			}
			*error_r = t_strdup_printf(
				"Milliseconds not supported for this setting: %s", str);
			return -1;
		}
		break;
	case 'H':
		multiply *= 60*60;
		if (str_begins_icase_with("hours", p))
			p = "";
		break;
	case 'D':
		multiply *= 60*60*24;
		if (str_begins_icase_with("days", p))
			p = "";
		break;
	case 'W':
		multiply *= 60*60*24*7;
		if (str_begins_icase_with("weeks", p))
			p = "";
		break;
	}

	if (*p != '\0') {
		*error_r = t_strconcat("Invalid time interval: ", str, NULL);
		return -1;
	}
	if (num > UINT_MAX / multiply) {
		*error_r = t_strconcat("Time interval is too large: ",
				       str, NULL);
		return -1;
	}
	*interval_r = num * multiply;
	return 0;
}

int str_parse_get_interval(const char *str, unsigned int *secs_r,
			   const char **error_r)
{
	return str_parse_get_interval_full(str, secs_r, FALSE, error_r);
}

int str_parse_get_interval_msecs(const char *str, unsigned int *msecs_r,
				 const char **error_r)
{
	return str_parse_get_interval_full(str, msecs_r, TRUE, error_r);
}

int str_parse_get_size(const char *str, uoff_t *bytes_r,
		       const char **error_r)
{
	uintmax_t num, multiply = 1;
	const char *p;

	if (str_parse_uintmax(str, &num, &p) < 0) {
		*error_r = t_strconcat("Invalid size: ", str, NULL);
		return -1;
	}
	while (*p == ' ') p++;
	switch (i_toupper(*p)) {
	case 'B':
		multiply = 1;
		p += 1;
		break;
	case 'K':
		multiply = 1024;
		p += 1;
		break;
	case 'M':
		multiply = 1024*1024;
		p += 1;
		break;
	case 'G':
		multiply = 1024*1024*1024;
		p += 1;
		break;
	case 'T':
		multiply = 1024ULL*1024*1024*1024;
		p += 1;
		break;
	}

	if (multiply > 1) {
		/* Allow: k, ki, kiB */
		if (i_toupper(*p) == 'I')
			p++;
		if (i_toupper(*p) == 'B')
			p++;
	}
	if (*p != '\0') {
		*error_r = t_strconcat("Invalid size: ", str, NULL);
		return -1;
	}
	if (num > (UOFF_T_MAX) / multiply) {
		*error_r = t_strconcat("Size is too large: ", str, NULL);
		return -1;
	}
	*bytes_r = num * multiply;
	return 0;
}

int str_parse_get_bool(const char *value, bool *result_r,
		       const char **error_r)
{
	/* FIXME: eventually we'd want to support only yes/no */
	if (strcasecmp(value, "yes") == 0 ||
	    strcasecmp(value, "y") == 0 || strcmp(value, "1") == 0)
		*result_r = TRUE;
	else if (strcasecmp(value, "no") == 0)
		*result_r = FALSE;
	else {
		*error_r = t_strdup_printf("Invalid boolean value: %s (use yes or no)",
					   value);
		return -1;
	}

	return 0;
}
