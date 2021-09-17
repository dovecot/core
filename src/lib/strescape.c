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

		str_append_data(dest, src_c + start, i-start);

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
	size_t prev_pos = 0;
	char esc[2] = { '\001', '\0' };

	for (size_t i = 0; i < src_size; i++) {
		switch (src[i]) {
		case '\000':
			esc[1] = '0';
			break;
		case '\001':
			esc[1] = '1';
			break;
		case '\t':
			esc[1] = 't';
			break;
		case '\r':
			esc[1] = 'r';
			break;
		case '\n':
			esc[1] = 'n';
			break;
		default:
			continue;
		}
		str_append_data(dest, src + prev_pos, i - prev_pos);
		str_append_data(dest, esc, 2);
		prev_pos = i + 1;
	}
	str_append_data(dest, src + prev_pos, src_size - prev_pos);
}

void str_append_tabescaped(string_t *dest, const char *src)
{
	size_t pos, prev_pos = 0;
	char esc[2] = { '\001', '\0' };

	for (;;) {
		pos = prev_pos + strcspn(src + prev_pos, "\001\t\r\n");
		str_append_data(dest, src + prev_pos, pos - prev_pos);
		prev_pos = pos + 1;

		switch (src[pos]) {
		case '\000':
			/* end of src string reached */
			return;
		case '\001':
			esc[1] = '1';
			break;
		case '\t':
			esc[1] = 't';
			break;
		case '\r':
			esc[1] = 'r';
			break;
		case '\n':
			esc[1] = 'n';
			break;
		default:
			i_unreached();
		}
		str_append_data(dest, esc, 2);
	}
}


const char *str_tabescape(const char *str)
{
	string_t *tmp;
	const char *p;

	if ((p = strpbrk(str, "\001\t\r\n")) != NULL) {
		tmp = t_str_new(128);
		str_append_data(tmp, str, p-str);
		str_append_tabescaped(tmp, p);
		return str_c(tmp);
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

		str_append_data(dest, src_c + start, i-start);

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

static char *str_tabunescape_from(char *str, char *src)
{
	/* @UNSAFE */
	char *dest, *p;

	dest = src;
	for (;;) {
		switch (src[1]) {
		case '\0':
			/* truncated input */
			*dest = '\0';
			return str;
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
			*dest++ = src[1];
			break;
		}
		src += 2;

		p = strchr(src, '\001');
		if (p == NULL) {
			memmove(dest, src, strlen(src)+1);
			break;
		}

		size_t copy_len = p - src;
		memmove(dest, src, copy_len);
		dest += copy_len;
		src = p;
	}
	return str;
}

char *str_tabunescape(char *str)
{
	char *src = strchr(str, '\001');
	if (src == NULL) {
		/* no unescaping needed */
		return str;
	}
	return str_tabunescape_from(str, src);
}

const char *t_str_tabunescape(const char *str)
{
	const char *p;

	p = strchr(str, '\001');
	if (p == NULL)
		return str;

	char *dest = t_strdup_noconst(str);
	return str_tabunescape_from(dest, dest + (p - str));
}

static char **p_strsplit_tabescaped_inplace(pool_t pool, char *data)
{
	/* @UNSAFE */
	char **array;
	unsigned int count, new_alloc_count, alloc_count;

	if (*data == '\0')
		return p_new(pool, char *, 1);

	alloc_count = 32;
	array = pool == unsafe_data_stack_pool ?
		t_malloc_no0(sizeof(char *) * alloc_count) :
		p_malloc(pool, sizeof(char *) * alloc_count);

	array[0] = data; count = 1;
	char *need_unescape = NULL;
	while ((data = strpbrk(data, "\t\001")) != NULL) {
		/* separator or escape char found */
		if (*data == '\001') {
			if (need_unescape == NULL)
				need_unescape = data;
			data++;
			continue;
		}
		if (count+1 >= alloc_count) {
			new_alloc_count = nearest_power(alloc_count+1);
			array = p_realloc(pool, array,
					  sizeof(char *) * alloc_count,
					  sizeof(char *) *
					  new_alloc_count);
			alloc_count = new_alloc_count;
		}
		*data++ = '\0';
		if (need_unescape != NULL) {
			str_tabunescape_from(array[count-1], need_unescape);
			need_unescape = NULL;
		}
		array[count++] = data;
	}
	if (need_unescape != NULL)
		str_tabunescape_from(array[count-1], need_unescape);
	i_assert(count < alloc_count);
	array[count] = NULL;

	return array;
}

const char *const *t_strsplit_tabescaped_inplace(char *data)
{
	char *const *escaped =
		p_strsplit_tabescaped_inplace(unsafe_data_stack_pool, data);
	return (const char *const *)escaped;
}

char **p_strsplit_tabescaped(pool_t pool, const char *str)
{
	return p_strsplit_tabescaped_inplace(pool, p_strdup(pool, str));
}

const char *const *t_strsplit_tabescaped(const char *str)
{
	return t_strsplit_tabescaped_inplace(t_strdup_noconst(str));
}
