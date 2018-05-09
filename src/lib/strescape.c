/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"

const char *str_nescape(const void *str, size_t len)
{
	string_t *dest = t_str_new(len*2);
	str_append_escaped(dest, str, len);
	return str_c(dest);
}

void str_append_escaped(string_t *dest, const void *src, size_t src_size)
{
	const unsigned char *pstart = src, *p = src, *pend = pstart + src_size;
	/* see if we need to quote it */
	for (; p < pend; p++) {
		if (IS_ESCAPED_CHAR(*p))
			break;
	}

	/* quote */
	str_append_data(dest, pstart, (size_t)(p - pstart));

	for (; p < pend; p++) {
		if (IS_ESCAPED_CHAR(*p))
			str_append_c(dest, '\\');
		str_append_data(dest, p, 1);
	}
}

void str_append_unescaped(string_t *dest, const void *src, size_t src_size)
{
	const unsigned char *src_c = src;
	size_t start = 0, i = 0;

	while (i < src_size) {
		for (; i < src_size; i++) {
			if (src_c[i] == '\\')
				break;
		}

		str_append_n(dest, src_c + start, i-start);

		if (i < src_size) {
			if (++i == src_size)
				break;
			str_append_c(dest, src_c[i++]);
		}
		start = i;
	}
}

char *str_unescape(char *str)
{
	/* @UNSAFE */
	char *dest, *start = str;

	while (*str != '\\') {
		if (*str == '\0')
			return start;
		str++;
	}

	for (dest = str; *str != '\0'; str++) {
		if (*str == '\\') {
			str++;
			if (*str == '\0')
				break;
		}

		*dest++ = *str;
	}

	*dest = '\0';
	return start;
}

int str_unescape_next(const char **str, const char **unescaped_r)
{
	const char *p;
	char *escaped;
	bool esc_found = FALSE;

	for (p = *str; *p != '\0'; p++) {
		if (*p == '"')
			break;
		else if (*p == '\\') {
			if (p[1] == '\0')
				return -1;
			esc_found = TRUE;
			p++;
		}
	}
	if (*p != '"')
		return -1;
	escaped = p_strdup_until(unsafe_data_stack_pool, *str, p);
	*str = p+1;
	*unescaped_r = !esc_found ? escaped : str_unescape(escaped);
	return 0;
}

void str_append_tabescaped_n(string_t *dest, const unsigned char *src, size_t src_size)
{
	for (size_t i = 0; i < src_size; i++) {
		switch (src[i]) {
		case '\000':
			str_append_c(dest, '\001');
			str_append_c(dest, '0');
			break;
		case '\001':
			str_append_c(dest, '\001');
			str_append_c(dest, '1');
			break;
		case '\t':
			str_append_c(dest, '\001');
			str_append_c(dest, 't');
			break;
		case '\r':
			str_append_c(dest, '\001');
			str_append_c(dest, 'r');
			break;
		case '\n':
			str_append_c(dest, '\001');
			str_append_c(dest, 'n');
			break;
		default:
			str_append_c(dest, src[i]);
			break;
		}
	}
}

void str_append_tabescaped(string_t *dest, const char *src) {
	str_append_tabescaped_n(dest, (const unsigned char*)src, strlen(src));
}


const char *str_tabescape(const char *str)
{
	string_t *tmp;
	const char *p;

	for (p = str; *p != '\0'; p++) {
		if (*p <= '\r') {
			tmp = t_str_new(128);
			str_append_n(tmp, str, p-str);
			str_append_tabescaped(tmp, p);
			return str_c(tmp);
		}
	}
	return str;
}

void str_append_tabunescaped(string_t *dest, const void *src, size_t src_size)
{
	const unsigned char *src_c = src;
	size_t start = 0, i = 0;

	while (i < src_size) {
		for (; i < src_size; i++) {
			if (src_c[i] == '\001')
				break;
		}

		str_append_n(dest, src_c + start, i-start);

		if (i < src_size) {
			i++;
			if (i < src_size) {
				switch (src_c[i]) {
				case '0':
					str_append_c(dest, '\000');
					break;
				case '1':
					str_append_c(dest, '\001');
					break;
				case 't':
					str_append_c(dest, '\t');
					break;
				case 'r':
					str_append_c(dest, '\r');
					break;
				case 'n':
					str_append_c(dest, '\n');
					break;
				default:
					str_append_c(dest, src_c[i]);
					break;
				}
				i++;
			}
		}
		start = i;
	}
}

char *str_tabunescape(char *str)
{
	/* @UNSAFE */
	char *dest, *start = str;

	str = strchr(str, '\001');
	if (str == NULL) {
		/* no unescaping needed */
		return start;
	}

	for (dest = str; *str != '\0'; str++) {
		if (*str != '\001')
			*dest++ = *str;
		else {
			str++;
			if (*str == '\0')
				break;
			switch (*str) {
			case '0':
				*dest++ = '\000';
				break;
			case '1':
				*dest++ = '\001';
				break;
			case 't':
				*dest++ = '\t';
				break;
			case 'r':
				*dest++ = '\r';
				break;
			case 'n':
				*dest++ = '\n';
				break;
			default:
				*dest++ = *str;
				break;
			}
		}
	}

	*dest = '\0';
	return start;
}

const char *t_str_tabunescape(const char *str)
{
	if (strchr(str, '\001') == NULL)
		return str;
	else
		return str_tabunescape(t_strdup_noconst(str));
}

const char *const *t_strsplit_tabescaped_inplace(char *data)
{
	/* @UNSAFE */
	char **array;
	unsigned int count, new_alloc_count, alloc_count;

	if (*data == '\0')
		return t_new(const char *, 1);

	alloc_count = 32;
	array = t_malloc_no0(sizeof(char *) * alloc_count);

	array[0] = data; count = 1;
	bool need_unescape = FALSE;
	while ((data = strpbrk(data, "\t\001")) != NULL) {
		/* separator or escape char found */
		if (*data == '\001') {
			need_unescape = TRUE;
			data++;
			continue;
		}
		if (count+1 >= alloc_count) {
			new_alloc_count = nearest_power(alloc_count+1);
			array = p_realloc(unsafe_data_stack_pool, array,
					  sizeof(char *) * alloc_count,
					  sizeof(char *) *
					  new_alloc_count);
			alloc_count = new_alloc_count;
		}
		*data++ = '\0';
		if (need_unescape) {
			str_tabunescape(array[count-1]);
			need_unescape = FALSE;
		}
		array[count++] = data;
	}
	if (need_unescape)
		str_tabunescape(array[count-1]);
	i_assert(count < alloc_count);
	array[count] = NULL;

	return (const char *const *)array;
}

char **p_strsplit_tabescaped(pool_t pool, const char *str)
{
	char **args;
	unsigned int i;

	args = p_strsplit(pool, str, "\t");
	for (i = 0; args[i] != NULL; i++)
		args[i] = str_tabunescape(args[i]);
	return args;
}

const char *const *t_strsplit_tabescaped(const char *str)
{
	return (void *)p_strsplit_tabescaped(unsafe_data_stack_pool, str);
}
