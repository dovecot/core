/*
 imem.c : Wrappers for allocating memory from default memory pool

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

pool_t default_pool;

void *i_malloc(size_t size)
{
        return p_malloc(default_pool, size);
}

void i_free(void *mem)
{
        p_free(default_pool, mem);
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
        const char *temp;
	char *ret;
        size_t len;

	va_start(args, str1);

	temp = _vstrconcat(str1, args, &len);
	if (temp == NULL)
		ret = NULL;
	else {
		ret = p_malloc(default_pool, len);
		memcpy(ret, temp, len);
	}

	va_end(args);
        return ret;
}

void imem_init(void)
{
	default_pool = system_pool;
}

void imem_deinit(void)
{
}
