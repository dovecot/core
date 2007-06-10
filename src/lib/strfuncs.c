/* Copyright (c) 2002-2003 Timo Sirainen */

/* @UNSAFE: whole file */

#include "lib.h"
#include "printf-upper-bound.h"
#include "strfuncs.h"

#include <stdio.h>
#include <limits.h>
#include <ctype.h>

#define STRCONCAT_BUFSIZE 512

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

/* replace %m with strerror() */
const char *printf_string_fix_format(const char *fmt)
{
	const char *p;

	for (p = fmt; *p != '\0'; p++) {
		if (*p++ == '%') {
			switch (*p) {
			case 'n':
				i_panic("%%n modifier used");
			case 'm':
				return fix_format_real(fmt, p-1);
			case '\0':
				i_panic("%% modifier missing");
			}
		}
	}

	return fmt;
}

int i_snprintf(char *dest, size_t max_chars, const char *format, ...)
{
#ifndef HAVE_VSNPRINTF
	char *buf;
#endif
	va_list args, args2;
	ssize_t len;
	int ret;

	i_assert(max_chars < INT_MAX);

	t_push();

	va_start(args, format);
	VA_COPY(args2, args);

	len = printf_string_upper_bound(&format, args);

	i_assert(len >= 0);

#ifdef HAVE_VSNPRINTF
	len = vsnprintf(dest, max_chars, format, args2);
#else
	buf = t_buffer_get(len);
	len = vsprintf(buf, format, args2);
#endif
	va_end(args);

	if (len < 0) {
		/* some error occurred */
		len = 0;
		ret = -1;
	} else if ((size_t)len >= max_chars) {
		/* too large */
		len = max_chars-1;
		ret = -1;
	} else {
		ret = 0;
	}

#ifndef HAVE_VSNPRINTF
	memcpy(dest, buf, len);
#endif
	dest[len] = '\0';

	t_pop();
	return ret;
}

char *p_strdup(pool_t pool, const char *str)
{
	void *mem;
	size_t len;

	if (str == NULL)
                return NULL;

	for (len = 0; (str)[len] != '\0'; )
		len++;
	len++;

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

char *p_strdup_vprintf(pool_t pool, const char *format, va_list args)
{
	char *ret;
	va_list args2;
	size_t len;

	if (!pool->datastack_pool)
		t_push();

	VA_COPY(args2, args);

	len = printf_string_upper_bound(&format, args);
        ret = p_malloc(pool, len);

#ifdef HAVE_VSNPRINTF
	vsnprintf(ret, len, format, args2);
#else
	vsprintf(ret, format, args2);
#endif
	if (!pool->datastack_pool)
		t_pop();
	return ret;
}

char *_vstrconcat(const char *str1, va_list args, size_t *ret_len)
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

	if (!pool->datastack_pool)
		t_push();

	temp = _vstrconcat(str1, args, &len);
	if (temp == NULL)
		ret = NULL;
	else {
		t_buffer_alloc(len);
		if (pool->datastack_pool)
			ret = temp;
		else {
			ret = p_malloc(pool, len);
			memcpy(ret, temp, len);
		}
	}

	if (!pool->datastack_pool)
		t_pop();

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

	ret = _vstrconcat(str1, args, &len);
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

bool is_numeric(const char *str, char end_char)
{
	if (*str == '\0' || *str == end_char)
		return FALSE;

	while (*str != '\0' && *str != end_char) {
		if (!i_isdigit(*str))
			return FALSE;
		str++;
	}

	return TRUE;
}

int strocpy(char *dest, const char *src, size_t dstsize)
{
	if (dstsize == 0)
		return -1;

	while (*src != '\0' && dstsize > 1) {
		*dest++ = *src++;
		dstsize--;
	}

	*dest++ = '\0';
	return *src == '\0' ? 0 : -1;
}

int str_path(char *dest, size_t dstsize, const char *dir, const char *file)
{
	size_t dirlen, filelen;

	dirlen = strlen(dir);
	filelen = strlen(file);

	if (dirlen+1+filelen >= dstsize) {
		if (dstsize > 0)
			*dest = '\0';
		errno = ENAMETOOLONG;
		return -1;
	}

	memcpy(dest, dir, dirlen);
	dest[dirlen] = '/';
	memcpy(dest + dirlen + 1, file, filelen);
	dest[dirlen + 1 + filelen] = '\0';
	return 0;
}

int str_ppath(char *dest, size_t dstsize, const char *dir,
	      const char *file_prefix, const char *file)
{
	size_t dirlen, prefixlen, filelen;

	dirlen = strlen(dir);
	prefixlen = strlen(file_prefix);
	filelen = strlen(file);

	if (dirlen+1+prefixlen+filelen >= dstsize) {
		if (dstsize > 0)
			*dest = '\0';
		errno = ENAMETOOLONG;
		return -1;
	}

	memcpy(dest, dir, dirlen);
	dest[dirlen] = '/';
	memcpy(dest + dirlen + 1, file_prefix, prefixlen);
	memcpy(dest + dirlen + prefixlen + 1, file, filelen);
	dest[dirlen + 1 + prefixlen + filelen] = '\0';
	return 0;
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

int memcasecmp(const void *p1, const void *p2, size_t size)
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

int strcmp_p(const void *p1, const void *p2)
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

int strcasecmp_p(const void *p1, const void *p2)
{
	const char *const *s1 = p1, *const *s2 = p2;

	return strcasecmp(*s1, *s2);
}

static char **
_strsplit(pool_t pool, const char *data, const char *separators, int spaces)
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
	return (const char **)_strsplit(unsafe_data_stack_pool, data,
					separators, FALSE);
}

const char **t_strsplit_spaces(const char *data, const char *separators)
{
	return (const char **)_strsplit(unsafe_data_stack_pool, data,
					separators, TRUE);
}

char **p_strsplit(pool_t pool, const char *data, const char *separators)
{
	return _strsplit(pool, data, separators, FALSE);
}

char **p_strsplit_spaces(pool_t pool, const char *data,
			 const char *separators)
{
	return _strsplit(pool, data, separators, TRUE);
}

void p_strsplit_free(pool_t pool, char **arr)
{
	p_free(pool, arr[0]);
	p_free(pool, arr);
}

unsigned int strarray_length(const char *const *arr)
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

bool strarray_remove(const char **arr, const char *value)
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
