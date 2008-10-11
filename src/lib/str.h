#ifndef STR_H
#define STR_H

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
const unsigned char *str_data(const string_t *str) ATTR_PURE;
char *str_c_modifiable(string_t *str);
size_t str_len(const string_t *str) ATTR_PURE;
bool str_equals(const string_t *str1, const string_t *str2) ATTR_PURE;

/* Append string/character */
void str_append(string_t *str, const char *cstr);
void str_append_n(string_t *str, const void *cstr, size_t max_len);
void str_append_c(string_t *str, unsigned char chr);
void str_append_str(string_t *dest, const string_t *src);

/* Append printf()-like data */
void str_printfa(string_t *str, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
void str_vprintfa(string_t *str, const char *fmt, va_list args)
	ATTR_FORMAT(2, 0);

void str_insert(string_t *str, size_t pos, const char *cstr);
void str_delete(string_t *str, size_t pos, size_t len);
void str_truncate(string_t *str, size_t len);

#endif
