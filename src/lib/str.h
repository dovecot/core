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
/* This macro ensures we add unsigned char to str to avoid
   implicit casts which cause errors with clang's implicit integer truncation
   sanitizier. Issues caught by these sanitizers are not undefined behavior,
   but are often unintentional.
   We also need to check that the type we are adding is compatible with char,
   so that we don't end up doing a narrowing cast. */
#ifdef HAVE_TYPE_CHECKS
#  define str_append_c(str, chr) \
	str_append_c((str), __builtin_choose_expr( \
		__builtin_types_compatible_p(typeof((chr)), char), \
			(unsigned char)(chr), (chr)))
#endif

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

static inline void str_replace(string_t *str, size_t pos, size_t len,
			       const char *cstr)
{
	buffer_replace(str, pos, len, cstr, strlen(cstr));
}

/* Truncate the string to specified length. If it's already smaller,
   do nothing. */
static inline void str_truncate(string_t *str, size_t len)
{
	if (str_len(str) > len)
		buffer_set_used_size(str, len);
}

/* Clear the string */
static inline void str_clear(string_t *str)
{
	buffer_clear(str);
}
static inline void str_clear_safe(string_t *str)
{
	buffer_clear_safe(str);
}

/* Truncate the string to specified length, but also make sure the truncation
   doesn't happen in the middle of an UTF-8 character sequence. In that case,
   the string will end up being up to a few bytes smaller than len. If it's
   already smaller to begin with, do nothing. */
void str_truncate_utf8(string_t *str, size_t len);

#endif
