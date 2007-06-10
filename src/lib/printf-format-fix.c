/* Copyright (c) 2002-2007 Timo Sirainen */

#include "lib.h"
#include "printf-format-fix.h"

static const char *fix_format_real(const char *fmt, const char *p)
{
	const char *errstr;
	char *buf;
	size_t pos, alloc, errlen;

	errstr = strerror(errno);
	errlen = strlen(errstr);

	pos = (size_t) (p-fmt);
	i_assert(pos < SSIZE_T_MAX);

	alloc = pos + errlen + 128;
	buf = t_buffer_get(alloc);

	memcpy(buf, fmt, pos);

	while (*p != '\0') {
		if (*p == '%' && p[1] == 'm') {
			if (pos+errlen+1 > alloc) {
				alloc += errlen+1 + 128;
				buf = t_buffer_get(alloc);
			}

			memcpy(buf+pos, errstr, errlen);
			pos += errlen;
			p += 2;
		} else {
			/* p + \0 */
			if (pos+2 > alloc) {
				alloc += 128;
				buf = t_buffer_get(alloc);
			}

			buf[pos++] = *p;
			p++;
		}
	}

	buf[pos++] = '\0';
	t_buffer_alloc(pos);
	return buf;
}

bool printf_format_fix(const char **format)
{
	const char *p;

	for (p = *format; *p != '\0'; p++) {
		if (*p++ == '%') {
			switch (*p) {
			case 'n':
				i_panic("%%n modifier used");
			case 'm':
				*format = fix_format_real(*format, p-1);
				return TRUE;
			case '\0':
				i_panic("%% modifier missing");
			}
		}
	}

	return FALSE;
}

