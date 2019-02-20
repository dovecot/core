#ifndef STR_H
#define STR_H

#include "buffer.h"

string_t *str_new(pool_t pool, size_t initial_size);
string_t *t_str_new(size_t initial_size);
/* Allocate a constant string using the given str as the input data.
   str pointer is saved directly, so it must not be freed until the returned
   string is no longer used. len must contain strlen(str). */
string_t *str_new_const(pool_t pool, const char *str, size_t len);
string_t *t_str_new_const(const char *str, size_t len);
void str_free(string_t **str);
char *str_free_without_data(string_t **str);

const char *str_c(string_t *str);
char *str_c_modifiable(string_t *str);
bool str_equals(const string_t *str1, const string_t *str2) ATTR_PURE;

static inline const unsigned char *str_data(const string_t *str)
{
	return (const unsigned char*)str->data;
}
static inline size_t str_len(const string_t *str)
{
	return str->used;
}

/* Append NUL-terminated string. If the trailing NUL isn't found earlier,
   append a maximum of max_len characters. */
void str_append_max(string_t *str, const char *cstr, size_t max_len);
static inline void ATTR_DEPRECATED("Use str_append_max() or str_append_data() instead")
str_append_n(string_t *str, const void *cstr, size_t max_len)
{
	str_append_max(str, cstr, max_len);
}

static inline void str_append(string_t *str, const char *cstr)
{
	buffer_append(str, cstr, strlen(cstr));
}
static inline void str_append_data(string_t *str, const void *data, size_t len)
{
	buffer_append(str, data, len);
}

static inline void str_append_c(string_t *str, unsigned char chr)
{
	buffer_append_c(str, chr);
}

static inline void str_append_str(string_t *dest, const string_t *src)
{
	buffer_append(dest, src->data, src->used);
}

/* Append printf()-like data */
void str_printfa(string_t *str, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
void str_vprintfa(string_t *str, const char *fmt, va_list args)
	ATTR_FORMAT(2, 0);

static inline void str_insert(string_t *str, size_t pos, const char *cstr)
{
	buffer_insert(str, pos, cstr, strlen(cstr));
}

static inline void str_delete(string_t *str, size_t pos, size_t len)
{
	buffer_delete(str, pos, len);
}

/* Truncate the string to specified length. If it's already smaller,
   do nothing. */
static inline void str_truncate(string_t *str, size_t len)
{
	if (str_len(str) > len)
		buffer_set_used_size(str, len);
}

/* Truncate the string to specified length, but also make sure the truncation
   doesn't happen in the middle of an UTF-8 character sequence. In that case,
   the string will end up being up to a few bytes smaller than len. If it's
   already smaller to begin with, do nothing. */
void str_truncate_utf8(string_t *str, size_t len);

#endif
