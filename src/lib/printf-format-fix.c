/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "printf-format-fix.h"

static const char *
fix_format_real(const char *fmt, const char *p, size_t *len_r)
{
	const char *errstr;
	char *buf;
	size_t len1, len2, len3;

	i_assert((size_t)(p - fmt) < INT_MAX);
	i_assert(p[0] == '%' && p[1] == 'm');

	errstr = strerror(errno);

	/* we'll assume that there's only one %m in the format string.
	   this simplifies the code and there's really no good reason to have
	   it multiple times. Callers can trap this case themselves. */
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
printf_format_fix_noalloc(const char *format, size_t *len_r)
{
	static const char *printf_skip_chars = "# -+'I.*0123456789hlLjzt";
	/* as a tiny optimization keep the most commonly used conversion
	   modifiers first, so strchr() stops early. */
	static const char *printf_allowed_conversions = "sudcioxXp%eEfFgGaA";
	const char *ret, *p, *p2;

	p = ret = format;
	while ((p2 = strchr(p, '%')) != NULL) {
		p = p2+1;
		while (*p != '\0' && strchr(printf_skip_chars, *p) != NULL)
			p++;

		if (*p == '\0') {
			i_panic("%% modifier missing in '%s'", format);
		} else if (strchr(printf_allowed_conversions, *p) != NULL) {
			/* allow & ignore */
		} else {
			switch (*p) {
			case 'n':
				i_panic("%%n modifier used");
			case 'm':
				if (ret != format)
					i_panic("%%m used twice");
				ret = fix_format_real(format, p-1, len_r);
				break;
			default:
				i_panic("Unsupported %%%c modifier", *p);
			}
		}
		p++;
	}

	if (ret == format)
		*len_r = p - format + strlen(p);
	return ret;
}

const char *printf_format_fix_get_len(const char *format, size_t *len_r)
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
	size_t len;

	ret = printf_format_fix_noalloc(format, &len);
	if (ret != format)
		t_buffer_alloc(len + 1);
	return ret;
}

const char *printf_format_fix_unsafe(const char *format)
{
	size_t len;

	return printf_format_fix_noalloc(format, &len);
}
