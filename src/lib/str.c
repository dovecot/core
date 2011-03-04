/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "printf-format-fix.h"
#include "str.h"

#include <stdio.h>

string_t *str_new(pool_t pool, size_t initial_size)
{
	return buffer_create_dynamic(pool, initial_size);
}

string_t *str_new_const(pool_t pool, const char *str, size_t len)
{
	string_t *ret;

	i_assert(str[len] == '\0');

	ret = p_new(pool, buffer_t, 1);
	buffer_create_const_data(ret, str, len + 1);
	str_truncate(ret, len);
	return ret;
}

string_t *t_str_new(size_t initial_size)
{
	return str_new(pool_datastack_create(), initial_size);
}

string_t *t_str_new_const(const char *str, size_t len)
{
	return str_new_const(pool_datastack_create(), str, len);
}

void str_free(string_t **str)
{
	buffer_free(str);
}

static void str_add_nul(string_t *str)
{
	const unsigned char *data = str_data(str);
	size_t len = str_len(str);
	size_t alloc = buffer_get_size(str);

	if (len == alloc || data[len] != '\0') {
		buffer_write(str, len, "", 1);
		/* remove the \0 - we don't want to keep it */
		buffer_set_used_size(str, len);
	}
}

char *str_free_without_data(string_t **str)
{
	str_add_nul(*str);
	return buffer_free_without_data(str);
}

const char *str_c(string_t *str)
{
	str_add_nul(str);
	return buffer_get_data(str, NULL);
}

const unsigned char *str_data(const string_t *str)
{
	return buffer_get_data(str, NULL);
}

char *str_c_modifiable(string_t *str)
{
	str_add_nul(str);
	return buffer_get_modifiable_data(str, NULL);
}

size_t str_len(const string_t *str)
{
	return buffer_get_used_size(str);
}

bool str_equals(const string_t *str1, const string_t *str2)
{
	if (str1->used != str2->used)
		return FALSE;

	return memcmp(str1->data, str2->data, str1->used) == 0;
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

void str_append_c(string_t *str, unsigned char chr)
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
#define SNPRINTF_INITIAL_EXTRA_SIZE 128
	va_list args2;
	char *tmp;
	unsigned int init_size;
	size_t pos = str->used;
	int ret, ret2;

	VA_COPY(args2, args);

	/* the format string is modified only if %m exists in it. it happens
	   only in error conditions, so don't try to t_push() here since it'll
	   just slow down the normal code path. */
	fmt = printf_format_fix_get_len(fmt, &init_size);
	init_size += SNPRINTF_INITIAL_EXTRA_SIZE;

	/* @UNSAFE */
	tmp = buffer_get_space_unsafe(str, pos, init_size);
	ret = vsnprintf(tmp, init_size, fmt, args);
	i_assert(ret >= 0);

	if ((unsigned int)ret >= init_size) {
		/* didn't fit with the first guess. now we know the size,
		   so try again. */
		tmp = buffer_get_space_unsafe(str, pos, ret + 1);
		ret2 = vsnprintf(tmp, ret + 1, fmt, args2);
		i_assert(ret2 == ret);
	}

	/* drop the unused data, including terminating NUL */
	buffer_set_used_size(str, pos + ret);
}

void str_insert(string_t *str, size_t pos, const char *cstr)
{
	buffer_insert(str, pos, cstr, strlen(cstr));
}

void str_delete(string_t *str, size_t pos, size_t len)
{
	buffer_delete(str, pos, len);
}

void str_truncate(string_t *str, size_t len)
{
	buffer_set_used_size(str, len);
}
