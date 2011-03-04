/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"

pool_t default_pool = &static_system_pool;

void *i_malloc(size_t size)
{
        return p_malloc(default_pool, size);
}

void *i_realloc(void *mem, size_t old_size, size_t new_size)
{
        return p_realloc(default_pool, mem, old_size, new_size);
}

char *i_strdup(const char *str)
{
        return p_strdup(default_pool, str);
}

char *i_strdup_empty(const char *str)
{
        return p_strdup_empty(default_pool, str);
}

char *i_strdup_until(const void *str, const void *end)
{
	return p_strdup_until(default_pool, str, end);
}

char *i_strndup(const void *str, size_t max_chars)
{
        return p_strndup(default_pool, str, max_chars);
}

char *i_strdup_printf(const char *format, ...)
{
	va_list args;
        char *ret;

        va_start(args, format);
	ret = p_strdup_vprintf(default_pool, format, args);
	va_end(args);
        return ret;
}

char *i_strdup_vprintf(const char *format, va_list args)
{
        return p_strdup_vprintf(default_pool, format, args);
}

char *i_strconcat(const char *str1, ...)
{
	va_list args;
	char *ret;
        size_t len;

	va_start(args, str1);

	T_BEGIN {
		const char *temp = vstrconcat(str1, args, &len);
	
		if (temp == NULL)
			ret = NULL;
		else {
			t_buffer_alloc(len);
			ret = p_malloc(default_pool, len);
			memcpy(ret, temp, len);
		}
	} T_END;

	va_end(args);
        return ret;
}
