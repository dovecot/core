/*
 temp-string.c : Temporary string

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
#include "temp-string.h"

#include <stdio.h>

typedef struct {
	char *str;
	size_t len;

	size_t alloc_size;
	unsigned int data_stack_frame;
} RealTempString;

TempString *t_string_new(size_t initial_size)
{
	RealTempString *rstr;

	if (initial_size <= 0)
		initial_size = 64;

	rstr = t_new(RealTempString, 1);
	rstr->data_stack_frame = data_stack_frame;
	rstr->alloc_size = initial_size;
	rstr->str = t_malloc(rstr->alloc_size);
	rstr->str[0] = '\0';
	return (TempString *) rstr;
}

static void t_string_inc(TempString *tstr, size_t size)
{
	RealTempString *rstr = (RealTempString *) tstr;
	char *str;

	i_assert(data_stack_frame == rstr->data_stack_frame);

	size += rstr->len + 1;
	if (size <= rstr->len || size > SSIZE_T_MAX) {
		/* overflow */
		i_panic("t_string_inc(): Out of memory %"PRIuSIZE_T" bytes",
			size);
	}

	if (size > rstr->alloc_size) {
                rstr->alloc_size = nearest_power(size);

		if (!t_try_realloc(rstr->str, rstr->alloc_size)) {
			str = t_malloc(rstr->alloc_size);
			memcpy(str, rstr->str, rstr->len+1);
			rstr->str = str;
		}
	}
}

/* Append string/character */
void t_string_append(TempString *tstr, const char *str)
{
	t_string_append_n(tstr, str, strlen(str));
}

void t_string_append_n(TempString *tstr, const char *str, size_t size)
{
	i_assert(size < SSIZE_T_MAX);

	t_string_inc(tstr, size);
	memcpy(tstr->str + tstr->len, str, size);

	tstr->len += size;
	tstr->str[tstr->len] = '\0';
}

void t_string_append_c(TempString *tstr, char chr)
{
	t_string_inc(tstr, 1);
	tstr->str[tstr->len++] = chr;
	tstr->str[tstr->len] = '\0';
}

void t_string_printfa(TempString *tstr, const char *fmt, ...)
{
	va_list args, args2;

	va_start(args, fmt);
	VA_COPY(args2, args);

	t_string_inc(tstr, printf_string_upper_bound(fmt, args));
	tstr->len += vsprintf(tstr->str + tstr->len, fmt, args2);

	va_end(args);
}

void t_string_erase(TempString *tstr, size_t pos, size_t len)
{
	RealTempString *rstr = (RealTempString *) tstr;

	i_assert(data_stack_frame == rstr->data_stack_frame);
	i_assert(pos < tstr->len && tstr->len - pos >= len);

	memmove(tstr->str + pos + len, tstr->str + pos,
		tstr->len - pos - len + 1);
}

void t_string_truncate(TempString *tstr, size_t len)
{
	RealTempString *rstr = (RealTempString *) tstr;

	i_assert(data_stack_frame == rstr->data_stack_frame);
	i_assert(len <= tstr->len);

	tstr->len = len;
	tstr->str[tstr->len] = '\0';
}
