#ifndef STRFUNC_H
#define STRFUNC_H

#define MAX_INT_STRLEN ((sizeof(uintmax_t) * CHAR_BIT + 2) / 3 + 1)

extern const unsigned char uchar_nul; /* (const unsigned char *)"" */
extern const unsigned char *uchar_empty_ptr; /* non-NULL pointer that shouldn't be dereferenced. */

/* Returns -1 if dest wasn't large enough, 0 if not. */
int i_snprintf(char *dest, size_t max_chars, const char *format, ...)
	ATTR_FORMAT(3, 4);

char *p_strdup(pool_t pool, const char *str) ATTR_MALLOC;
void *p_memdup(pool_t pool, const void *data, size_t size) ATTR_MALLOC;
/* return NULL if str = "" */
char *p_strdup_empty(pool_t pool, const char *str) ATTR_MALLOC;
/* *end isn't included */
char *p_strdup_until(pool_t pool, const void *start, const void *end)
	ATTR_MALLOC ATTR_RETURNS_NONNULL;
char *p_strndup(pool_t pool, const void *str, size_t max_chars) ATTR_MALLOC;
char *p_strdup_printf(pool_t pool, const char *format, ...)
	ATTR_FORMAT(2, 3) ATTR_MALLOC ATTR_RETURNS_NONNULL;
char *p_strdup_vprintf(pool_t pool, const char *format, va_list args)
	ATTR_FORMAT(2, 0) ATTR_MALLOC ATTR_RETURNS_NONNULL;
char *p_strconcat(pool_t pool, const char *str1, ...)
	ATTR_SENTINEL ATTR_MALLOC;

/* same with temporary memory allocations: */
const char *t_strdup(const char *str) ATTR_MALLOC;
char *t_strdup_noconst(const char *str) ATTR_MALLOC;
/* return NULL if str = "" */
const char *t_strdup_empty(const char *str) ATTR_MALLOC;
/* *end isn't included */
const char *t_strdup_until(const void *start, const void *end)
	ATTR_MALLOC ATTR_RETURNS_NONNULL;
const char *t_strndup(const void *str, size_t max_chars) ATTR_MALLOC;
const char *t_strdup_printf(const char *format, ...)
	ATTR_FORMAT(1, 2) ATTR_MALLOC ATTR_RETURNS_NONNULL;
const char *t_strdup_vprintf(const char *format, va_list args)
	ATTR_FORMAT(1, 0) ATTR_MALLOC ATTR_RETURNS_NONNULL;
const char *t_strconcat(const char *str1, ...)
	ATTR_SENTINEL ATTR_MALLOC;

/* Like t_strdup(), but stop at cutchar. */
const char *t_strcut(const char *str, char cutchar);
/* Replace all from->to chars in the string. */
const char *t_str_replace(const char *str, char from, char to);
/* Put the string on a single line by replacing all newlines with spaces and
   dropping any carriage returns. Sequences of several newlines are merged into
   one space and newlines at the beginning and end of the string are dropped. */
const char *t_str_oneline(const char *str);

/* Like strlcpy(), but return -1 if buffer was overflown, 0 if not. */
int i_strocpy(char *dest, const char *src, size_t dstsize);

char *str_ucase(char *str);
char *str_lcase(char *str);
const char *t_str_lcase(const char *str);
const char *t_str_ucase(const char *str);

/* Return pointer to first matching needle */
const char *i_strstr_arr(const char *haystack, const char *const *needles);

/* Trim matching chars from either side of the string */
const char *t_str_trim(const char *str, const char *chars);
const char *p_str_trim(pool_t pool, const char *str, const char *chars);
const char *str_ltrim(const char *str, const char *chars);
const char *t_str_ltrim(const char *str, const char *chars);
const char *p_str_ltrim(pool_t pool, const char *str, const char *chars);
const char *t_str_rtrim(const char *str, const char *chars);
const char *p_str_rtrim(pool_t pool, const char *str, const char *chars);

int null_strcmp(const char *s1, const char *s2) ATTR_PURE;
int null_strcasecmp(const char *s1, const char *s2) ATTR_PURE;
int i_memcasecmp(const void *p1, const void *p2, size_t size) ATTR_PURE;
int i_strcmp_p(const char *const *p1, const char *const *p2) ATTR_PURE;
int i_strcasecmp_p(const char *const *p1, const char *const *p2) ATTR_PURE;
/* Returns TRUE if the two memory areas are equal. This function is safe
   against timing attacks, so it compares all the bytes every time. */
bool mem_equals_timing_safe(const void *p1, const void *p2, size_t size);

size_t str_match(const char *p1, const char *p2) ATTR_PURE;
static inline ATTR_PURE bool str_begins(const char *haystack, const char *needle)
{
	return needle[str_match(haystack, needle)] == '\0';
}
#if defined(__GNUC__) && (__GNUC__ >= 2)
/* GCC (and Clang) are known to have a compile-time strlen("literal") shortcut, and
   an optimised strncmp(), so use that by default. Macro is multi-evaluation safe. */
# define str_begins(h, n) (__builtin_constant_p(n) ? strncmp((h), (n), strlen(n))==0 : (str_begins)((h), (n)))
#endif

static inline char *i_strchr_to_next(const char *str, char chr)
{
	char *tmp = (char *)strchr(str, chr);
	return tmp == NULL ? NULL : tmp+1;
}

/* separators is an array of separator characters, not a separator string.
   an empty data string results in an array containing only NULL. */
char **p_strsplit(pool_t pool, const char *data, const char *separators)
	ATTR_MALLOC ATTR_RETURNS_NONNULL;
const char **t_strsplit(const char *data, const char *separators)
	ATTR_MALLOC ATTR_RETURNS_NONNULL;
/* like p_strsplit(), but treats multiple adjacent separators as a single
   separator. separators at the beginning or at the end of the string are also
   ignored, so it's not possible for the result to have any empty strings. */
char **p_strsplit_spaces(pool_t pool, const char *data, const char *separators)
	ATTR_MALLOC ATTR_RETURNS_NONNULL;
const char **t_strsplit_spaces(const char *data, const char *separators)
	ATTR_MALLOC ATTR_RETURNS_NONNULL;
void p_strsplit_free(pool_t pool, char **arr);

const char *dec2str(uintmax_t number);
/* Use the given buffer to write out the number. Returns pointer to the
   written number in the buffer. Note that this isn't the same as the beginning
   of the buffer. */
char *dec2str_buf(char buffer[STATIC_ARRAY MAX_INT_STRLEN], uintmax_t number);

/* Return length of NULL-terminated list string array */
unsigned int str_array_length(const char *const *arr) ATTR_PURE;
/* Return all strings from array joined into one string. */
const char *t_strarray_join(const char *const *arr, const char *separator)
	ATTR_MALLOC ATTR_RETURNS_NONNULL;
/* Removes a value from NULL-terminated string array. Returns TRUE if found. */
bool str_array_remove(const char **arr, const char *value);
/* Returns TRUE if value exists in NULL-terminated string array. */
bool str_array_find(const char *const *arr, const char *value);
/* Like str_array_find(), but use strcasecmp(). */
bool str_array_icase_find(const char *const *arr, const char *value);
/* Duplicate array of strings. The memory can be freed by freeing the
   return value. */
const char **p_strarray_dup(pool_t pool, const char *const *arr)
	ATTR_MALLOC ATTR_RETURNS_NONNULL;

/* Join ARRAY_TYPE(const_string) to a string, similar to t_strarray_join() */
char *p_array_const_string_join(pool_t pool, const ARRAY_TYPE(const_string) *arr,
				const char *separator);
#define t_array_const_string_join(arr, separator) \
	((const char *)p_array_const_string_join(unsafe_data_stack_pool, arr, separator))

/* INTERNAL */
char *t_noalloc_strdup_vprintf(const char *format, va_list args,
			       unsigned int *size_r)
	ATTR_FORMAT(1, 0) ATTR_RETURNS_NONNULL;
char *vstrconcat(const char *str1, va_list args, size_t *ret_len) ATTR_MALLOC;

#endif
