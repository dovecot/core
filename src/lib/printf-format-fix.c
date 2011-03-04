/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "printf-format-fix.h"

static const char *
fix_format_real(const char *fmt, const char *p, unsigned int *len_r)
{
	const char *errstr;
	char *buf;
	unsigned int len1, len2, len3;

	i_assert((size_t)(p - fmt) < INT_MAX);

	errstr = strerror(errno);

	/* we'll assume that there's only one %m in the format string.
	   this simplifies the code and there's really no good reason to have
	   it multiple times. */
	len1 = p - fmt;
	len2 = strlen(errstr);
	len3 = strlen(p + 2);

	/* @UNSAFE */
	buf = t_buffer_get(len1 + len2 + len3 + 1);
	memcpy(buf, fmt, len1);
	memcpy(buf + len1, errstr, len2);
	memcpy(buf + len1 + len2, p + 2, len3 + 1);

	*len_r = len1 + len2 + len3;
	return buf;
}

static const char *
printf_format_fix_noalloc(const char *format, unsigned int *len_r)
{
	const char *p;

	for (p = format; *p != '\0'; ) {
		if (*p++ == '%') {
			switch (*p) {
			case 'n':
				i_panic("%%n modifier used");
			case 'm':
				return fix_format_real(format, p-1, len_r);
			case '\0':
				i_panic("%% modifier missing");
			}
		}
	}

	*len_r = p - format;
	return format;
}

const char *printf_format_fix_get_len(const char *format, unsigned int *len_r)
{
	const char *ret;

	ret = printf_format_fix_noalloc(format, len_r);
	if (ret != format)
		t_buffer_alloc(*len_r + 1);
	return ret;
}

const char *printf_format_fix(const char *format)
{
	const char *ret;
	unsigned int len;

	ret = printf_format_fix_noalloc(format, &len);
	if (ret != format)
		t_buffer_alloc(len + 1);
	return ret;
}

const char *printf_format_fix_unsafe(const char *format)
{
	unsigned int len;

	return printf_format_fix_noalloc(format, &len);
}
