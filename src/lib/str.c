/* Copyright (c) 2002-2003 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "printf-upper-bound.h"
#include "str.h"

#include <stdio.h>

string_t *str_new(pool_t pool, size_t initial_size)
{
	return buffer_create_dynamic(pool, initial_size, (size_t)-1);
}

string_t *t_str_new(size_t initial_size)
{
	return str_new(pool_datastack_create(), initial_size);
}

void str_free(string_t *str)
{
	buffer_free(str);
}

static int str_add_nul(string_t *str)
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

const char *str_c(string_t *str)
{
	if (!str_add_nul(str))
		return "";

	return buffer_get_data(str, NULL);
}

const unsigned char *str_data(const string_t *str)
{
	return buffer_get_data(str, NULL);
}

char *str_c_modifyable(string_t *str)
{
	if (!str_add_nul(str))
		return NULL;

	return buffer_get_modifyable_data(str, NULL);
}

size_t str_len(const string_t *str)
{
	return buffer_get_used_size(str);
}

void str_append(string_t *str, const char *cstr)
{
	buffer_append(str, cstr, strlen(cstr));
}

void str_append_n(string_t *str, const void *cstr, size_t max_len)
{
	size_t len;

	len = 0;
	while (len < max_len && ((const char *)cstr)[len] != '\0')
		len++;

	buffer_append(str, cstr, len);
}

void str_append_c(string_t *str, char chr)
{
	buffer_append_c(str, chr);
}

void str_append_str(string_t *dest, const string_t *src)
{
	const char *cstr;
	size_t len;

	cstr = buffer_get_data(src, &len);
	buffer_append(dest, cstr, len);
}

void str_printfa(string_t *str, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	str_vprintfa(str, fmt, args);
	va_end(args);
}

void str_vprintfa(string_t *str, const char *fmt, va_list args)
{
	char *buf;
	int ret;
	va_list args2;
	size_t len, append_len;

	VA_COPY(args2, args);

	len = buffer_get_used_size(str);

	append_len = printf_string_upper_bound(&fmt, args);
	buf = buffer_append_space_unsafe(str, append_len);

#ifdef HAVE_VSNPRINTF
	ret = vsnprintf(buf, append_len, fmt, args2);
	i_assert(ret >= 0 && (size_t)ret <= append_len);
#else
	ret = vsprintf(buf, fmt, args2);
	i_assert(ret >= 0);
#endif

	len += ret;

	buffer_set_used_size(str, len);
}

void str_delete(string_t *str, size_t pos, size_t len)
{
	buffer_delete(str, pos, len);
}

void str_truncate(string_t *str, size_t len)
{
	buffer_set_used_size(str, len);
}
