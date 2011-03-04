/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

/* @UNSAFE: whole file */

#include "lib.h"
#include "printf-format-fix.h"
#include "strfuncs.h"

#include <stdio.h>
#include <limits.h>
#include <ctype.h>

#define STRCONCAT_BUFSIZE 512

int i_snprintf(char *dest, size_t max_chars, const char *format, ...)
{
	va_list args;
	int ret;

	i_assert(max_chars < INT_MAX);

	va_start(args, format);
	ret = vsnprintf(dest, max_chars, printf_format_fix_unsafe(format),
			args);
	va_end(args);

	i_assert(ret >= 0);
	return (unsigned int)ret < max_chars ? 0 : -1;
}

char *p_strdup(pool_t pool, const char *str)
{
	void *mem;
	size_t len;

	if (str == NULL)
                return NULL;

	len = strlen(str) + 1;
	mem = p_malloc(pool, len);
	memcpy(mem, str, len);
	return mem;
}

char *p_strdup_empty(pool_t pool, const char *str)
{
	if (str == NULL || *str == '\0')
                return NULL;

	return p_strdup(pool, str);
}

char *p_strdup_until(pool_t pool, const void *start, const void *end)
{
	size_t size;
	char *mem;

	i_assert((const char *) start <= (const char *) end);

	size = (size_t) ((const char *) end - (const char *) start);

	mem = p_malloc(pool, size + 1);
	memcpy(mem, start, size);
	return mem;
}

char *p_strndup(pool_t pool, const void *str, size_t max_chars)
{
	char *mem;
	size_t len;

	i_assert(max_chars != (size_t)-1);

	if (str == NULL)
		return NULL;

	len = 0;
	while (len < max_chars && ((const char *) str)[len] != '\0')
		len++;

	mem = p_malloc(pool, len+1);
	memcpy(mem, str, len);
	mem[len] = '\0';
	return mem;
}

char *p_strdup_printf(pool_t pool, const char *format, ...)
{
	va_list args;
        char *ret;

	va_start(args, format);
        ret = p_strdup_vprintf(pool, format, args);
	va_end(args);

	return ret;
}

char *t_noalloc_strdup_vprintf(const char *format, va_list args,
			       unsigned int *size_r)
{
#define SNPRINTF_INITIAL_EXTRA_SIZE 256
	va_list args2;
	char *tmp;
	unsigned int init_size;
	int ret;

	VA_COPY(args2, args);

	/* the format string is modified only if %m exists in it. it happens
	   only in error conditions, so don't try to t_push() here since it'll
	   just slow down the normal code path. */
	format = printf_format_fix_get_len(format, &init_size);
	init_size += SNPRINTF_INITIAL_EXTRA_SIZE;

	tmp = t_buffer_get(init_size);
	ret = vsnprintf(tmp, init_size, format, args);
	i_assert(ret >= 0);

	*size_r = ret + 1;
	if ((unsigned int)ret >= init_size) {
		/* didn't fit with the first guess. now we know the size,
		   so try again. */
		tmp = t_buffer_get(*size_r);
		ret = vsnprintf(tmp, *size_r, format, args2);
		i_assert((unsigned int)ret == *size_r-1);
	}
	return tmp;
}

char *p_strdup_vprintf(pool_t pool, const char *format, va_list args)
{
	char *tmp, *buf;
	unsigned int size;

	tmp = t_noalloc_strdup_vprintf(format, args, &size);
	if (pool->datastack_pool) {
		t_buffer_alloc(size);
		return tmp;
	} else {
		buf = p_malloc(pool, size);
		memcpy(buf, tmp, size - 1);
		return buf;
	}
}

char *vstrconcat(const char *str1, va_list args, size_t *ret_len)
{
	const char *str;
        char *temp;
	size_t bufsize, i, len;

	if (str1 == NULL)
		return NULL;

	str = str1;
	bufsize = STRCONCAT_BUFSIZE;
	temp = t_buffer_get(bufsize);

	i = 0;
	do {
		len = strlen(str);

		if (i + len >= bufsize) {
			/* need more memory */
			bufsize = nearest_power(i + len + 1);
			temp = t_buffer_reget(temp, bufsize);
		}

		memcpy(temp + i, str, len); i += len;

		/* next string */
		str = va_arg(args, const char *);
	} while (str != NULL);

	i_assert(i < bufsize);

	temp[i++] = '\0';
        *ret_len = i;
        return temp;
}

char *p_strconcat(pool_t pool, const char *str1, ...)
{
	va_list args;
	char *temp, *ret;
        size_t len;

	va_start(args, str1);

	if (pool->datastack_pool) {
		ret = vstrconcat(str1, args, &len);
		if (ret != NULL)
			t_buffer_alloc(len);
	} else {
		T_BEGIN {
			temp = vstrconcat(str1, args, &len);
			if (temp == NULL)
				ret = NULL;
			else {
				t_buffer_alloc(len);
				ret = p_malloc(pool, len);
				memcpy(ret, temp, len);
			}
		} T_END;
	}

	va_end(args);
        return ret;
}

const char *t_strdup(const char *str)
{
	return p_strdup(unsafe_data_stack_pool, str);
}

char *t_strdup_noconst(const char *str)
{
	return p_strdup(unsafe_data_stack_pool, str);
}

const char *t_strdup_empty(const char *str)
{
	return p_strdup_empty(unsafe_data_stack_pool, str);
}

const char *t_strdup_until(const void *start, const void *end)
{
	return p_strdup_until(unsafe_data_stack_pool, start, end);
}

const char *t_strndup(const void *str, size_t max_chars)
{
	return p_strndup(unsafe_data_stack_pool, str, max_chars);
}

const char *t_strdup_printf(const char *format, ...)
{
	va_list args;
	const char *ret;

	va_start(args, format);
	ret = p_strdup_vprintf(unsafe_data_stack_pool, format, args);
	va_end(args);

	return ret;
}

const char *t_strdup_vprintf(const char *format, va_list args)
{
	return p_strdup_vprintf(unsafe_data_stack_pool, format, args);
}

const char *t_strconcat(const char *str1, ...)
{
	va_list args;
	const char *ret;
        size_t len;

	va_start(args, str1);

	ret = vstrconcat(str1, args, &len);
	if (ret != NULL)
		t_buffer_alloc(len);

	va_end(args);
        return ret;
}

const char *t_strcut(const char *str, char cutchar)
{
	const char *p;

	for (p = str; *p != '\0'; p++) {
		if (*p == cutchar)
                        return t_strdup_until(str, p);
	}

        return str;
}

int i_strocpy(char *dest, const char *src, size_t dstsize)
{
	if (dstsize == 0)
		return -1;

	while (*src != '\0' && dstsize > 1) {
		*dest++ = *src++;
		dstsize--;
	}

	*dest = '\0';
	return *src == '\0' ? 0 : -1;
}

char *str_ucase(char *str)
{
	char *p;

	for (p = str; *p != '\0'; p++)
		*p = i_toupper(*p);
        return str;
}

char *str_lcase(char *str)
{
	char *p;

	for (p = str; *p != '\0'; p++)
		*p = i_tolower(*p);
        return str;
}

const char *t_str_lcase(const char *str)
{
	return str_lcase(t_strdup_noconst(str));
}

const char *t_str_ucase(const char *str)
{
	return str_ucase(t_strdup_noconst(str));
}

int null_strcmp(const char *s1, const char *s2)
{
	if (s1 == NULL)
		return s2 == NULL ? 0 : -1;
	if (s2 == NULL)
		return 1;

	return strcmp(s1, s2);
}

int i_memcasecmp(const void *p1, const void *p2, size_t size)
{
	const unsigned char *s1 = p1;
	const unsigned char *s2 = p2;
	int ret;

	while (size > 0) {
		ret = i_toupper(*s1) - i_toupper(*s2);
		if (ret != 0)
			return ret;

		s1++; s2++; size--;
	}

        return 0;
}

int bsearch_strcmp(const void *p1, const void *p2)
{
	const char *key = p1;
	const char *const *member = p2;

	return strcmp(key, *member);
}

int i_strcmp_p(const void *p1, const void *p2)
{
	const char *const *s1 = p1, *const *s2 = p2;

	return strcmp(*s1, *s2);
}

int bsearch_strcasecmp(const void *p1, const void *p2)
{
	const char *key = p1;
	const char *const *member = p2;

	return strcasecmp(key, *member);
}

int i_strcasecmp_p(const void *p1, const void *p2)
{
	const char *const *s1 = p1, *const *s2 = p2;

	return strcasecmp(*s1, *s2);
}

static char **
split_str(pool_t pool, const char *data, const char *separators, int spaces)
{
        char **array;
	char *str;
        unsigned int count, alloc_count, new_alloc_count;

	i_assert(*separators != '\0');

	if (spaces) {
		/* skip leading separators */
		while (*data != '\0' && strchr(separators, *data) != NULL)
			data++;
	}
	if (*data == '\0')
		return p_new(pool, char *, 1);

	str = p_strdup(pool, data);

	alloc_count = 32;
	array = p_new(pool, char *, alloc_count);

	array[0] = str; count = 1;
	while (*str != '\0') {
		if (strchr(separators, *str) != NULL) {
			/* separator found */
			if (count+1 >= alloc_count) {
                                new_alloc_count = nearest_power(alloc_count+1);
				array = p_realloc(pool, array,
						  sizeof(char *) * alloc_count,
						  sizeof(char *) *
						  new_alloc_count);
				alloc_count = new_alloc_count;
			}

			*str = '\0';
			if (spaces) {
				while (str[1] != '\0' &&
				       strchr(separators, str[1]) != NULL)
					str++;

				/* ignore trailing separators */
				if (str[1] == '\0')
					break;
			}

			array[count++] = str+1;
		}

                str++;
	}

	i_assert(count < alloc_count);
        array[count] = NULL;

        return array;
}

const char **t_strsplit(const char *data, const char *separators)
{
	return (const char **)split_str(unsafe_data_stack_pool, data,
					separators, FALSE);
}

const char **t_strsplit_spaces(const char *data, const char *separators)
{
	return (const char **)split_str(unsafe_data_stack_pool, data,
					separators, TRUE);
}

char **p_strsplit(pool_t pool, const char *data, const char *separators)
{
	return split_str(pool, data, separators, FALSE);
}

char **p_strsplit_spaces(pool_t pool, const char *data,
			 const char *separators)
{
	return split_str(pool, data, separators, TRUE);
}

void p_strsplit_free(pool_t pool, char **arr)
{
	p_free(pool, arr[0]);
	p_free(pool, arr);
}

unsigned int str_array_length(const char *const *arr)
{
	unsigned int count;

	if (arr == NULL)
		return 0;

	for (count = 0; *arr != NULL; arr++)
		count++;

	return count;
}

const char *t_strarray_join(const char *const *arr, const char *separator)
{
	size_t alloc_len, sep_len, len, pos, needed_space;
	char *str;

	sep_len = strlen(separator);
        alloc_len = 64;
        str = t_buffer_get(alloc_len);

	for (pos = 0; *arr != NULL; arr++) {
		len = strlen(*arr);
		needed_space = pos + len + sep_len + 1;
		if (needed_space > alloc_len) {
			alloc_len = nearest_power(needed_space);
			str = t_buffer_reget(str, alloc_len);
		}

		if (pos != 0) {
			memcpy(str + pos, separator, sep_len);
			pos += sep_len;
		}

		memcpy(str + pos, *arr, len);
		pos += len;
	}
	str[pos] = '\0';
	t_buffer_alloc(pos + 1);
	return str;
}

bool str_array_remove(const char **arr, const char *value)
{
	const char **dest;

	for (; *arr != NULL; arr++) {
		if (strcmp(*arr, value) == 0) {
			/* found it. now move the rest. */
			for (dest = arr, arr++; *arr != NULL; arr++, dest++)
				*dest = *arr;
			*dest = NULL;
			return TRUE;
		}
	}
	return FALSE;
}

bool str_array_find(const char *const *arr, const char *value)
{
	for (; *arr != NULL; arr++) {
		if (strcmp(*arr, value) == 0)
			return TRUE;
	}
	return FALSE;
}

bool str_array_icase_find(const char *const *arr, const char *value)
{
	for (; *arr != NULL; arr++) {
		if (strcasecmp(*arr, value) == 0)
			return TRUE;
	}
	return FALSE;
}

const char **p_strarray_dup(pool_t pool, const char *const *arr)
{
	unsigned int i;
	const char **ret;
	char *p;
	size_t len, size = sizeof(const char *);

	for (i = 0; arr[i] != NULL; i++)
		size += sizeof(const char *) + strlen(arr[i]) + 1;

	ret = p_malloc(pool, size);
	p = PTR_OFFSET(ret, sizeof(const char *) * (i + 1));
	for (i = 0; arr[i] != NULL; i++) {
		len = strlen(arr[i]) + 1;
		memcpy(p, arr[i], len);
		ret[i] = p;
		p += len;
	}
	i_assert(PTR_OFFSET(ret, size) == (void *)p);
	return ret;
}

const char *dec2str(uintmax_t number)
{
	char *buffer;
	int pos;

	pos = MAX_INT_STRLEN;
	buffer = t_malloc(pos);

	buffer[--pos] = '\0';
	do {
		buffer[--pos] = (number % 10) + '0';
		number /= 10;
	} while (number != 0 && pos >= 0);

	i_assert(pos >= 0);
	return buffer + pos;
}
