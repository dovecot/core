/*
    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "lib.h"
#include "buffer.h"
#include "printf-upper-bound.h"
#include "str.h"

#include <stdio.h>

String *str_new(Pool pool, size_t initial_size)
{
	return buffer_create_dynamic(pool, initial_size, (size_t)-1);
}

String *t_str_new(size_t initial_size)
{
	return str_new(data_stack_pool, initial_size);
}

static int str_add_nul(String *str)
{
	size_t len;

	len = str_len(str);
	if (buffer_write(str, len, "", 1) != 1) {
		/* no space - doesn't happen with our dynamically growing
		   strings though, but make sure it's \0 terminated. */
		if (len == 0)
			return FALSE;

		len--;
		if (buffer_write(str, len, "", 1) != 1)
			i_panic("BUG in str_c()");
	}

	/* remove the \0 - we don't want to keep it */
	buffer_set_used_size(str, len);
	return TRUE;
}

const char *str_c(String *str)
{
	if (!str_add_nul(str))
		return "";

	return buffer_get_data(str, NULL);
}

char *str_c_modifyable(String *str)
{
	if (!str_add_nul(str))
		return NULL;

	return buffer_get_modifyable_data(str, NULL);
}

size_t str_len(const String *str)
{
	return buffer_get_used_size(str);
}

void str_append(String *str, const char *cstr)
{
	buffer_append(str, cstr, strlen(cstr));
}

void str_append_n(String *str, const char *cstr, size_t max_len)
{
	size_t len;

	len = 0;
	while (len < max_len && cstr[len] != '\0')
		len++;

	buffer_append(str, cstr, len);
}

void str_append_c(String *str, char chr)
{
	buffer_append_c(str, chr);
}

void str_append_str(String *dest, const String *src)
{
	const char *cstr;
	size_t len;

	cstr = buffer_get_data(src, &len);
	buffer_append(dest, cstr, len);
}

void str_printfa(String *str, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	str_vprintfa(str, fmt, args);
	va_end(args);
}

void str_vprintfa(String *str, const char *fmt, va_list args)
{
	char *buf;
	int ret;
	size_t len, append_len;

	len = buffer_get_used_size(str);

	fmt = printf_string_fix_format(fmt);
	append_len = printf_string_upper_bound(fmt, args);

	buf = buffer_append_space(str, append_len);

#ifdef HAVE_VSNPRINTF
	ret = vsnprintf(buf, append_len, fmt, args);
	i_assert(ret >= 0 && (size_t)ret <= append_len);
#else
	ret = vsprintf(buf, fmt, args);
	i_assert(ret >= 0);
#endif

	len += ret;

	buffer_set_used_size(str, len);
}

void str_delete(String *str, size_t pos, size_t len)
{
	buffer_delete(str, pos, len);
}

void str_truncate(String *str, size_t len)
{
	buffer_set_used_size(str, len);
}
