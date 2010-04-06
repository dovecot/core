#ifndef STRFUNC_H
#define STRFUNC_H

#define MAX_INT_STRLEN ((sizeof(uintmax_t) * CHAR_BIT + 2) / 3 + 1)

/* Returns -1 if dest wasn't large enough, 0 if not. */
int i_snprintf(char *dest, size_t max_chars, const char *format, ...)
	ATTR_FORMAT(3, 4);

char *p_strdup(pool_t pool, const char *str) ATTR_MALLOC;
/* return NULL if str = "" */
char *p_strdup_empty(pool_t pool, const char *str) ATTR_MALLOC;
/* *end isn't included */
char *p_strdup_until(pool_t pool, const void *start, const void *end)
	ATTR_MALLOC;
char *p_strndup(pool_t pool, const void *str, size_t max_chars) ATTR_MALLOC;
char *p_strdup_printf(pool_t pool, const char *format, ...)
	ATTR_FORMAT(2, 3) ATTR_MALLOC;
char *p_strdup_vprintf(pool_t pool, const char *format, va_list args)
	ATTR_FORMAT(2, 0) ATTR_MALLOC;
char *p_strconcat(pool_t pool, const char *str1, ...)
	ATTR_SENTINEL ATTR_MALLOC;

/* same with temporary memory allocations: */
const char *t_strdup(const char *str) ATTR_MALLOC;
char *t_strdup_noconst(const char *str) ATTR_MALLOC;
/* return NULL if str = "" */
const char *t_strdup_empty(const char *str) ATTR_MALLOC;
/* *end isn't included */
const char *t_strdup_until(const void *start, const void *end) ATTR_MALLOC;
const char *t_strndup(const void *str, size_t max_chars) ATTR_MALLOC;
const char *t_strdup_printf(const char *format, ...)
	ATTR_FORMAT(1, 2) ATTR_MALLOC;
const char *t_strdup_vprintf(const char *format, va_list args)
	ATTR_FORMAT(1, 0) ATTR_MALLOC;
const char *t_strconcat(const char *str1, ...)
	ATTR_SENTINEL ATTR_MALLOC;

/* Like t_strdup(), but stop at cutchar. */
const char *t_strcut(const char *str, char cutchar);

/* Like strlcpy(), but return -1 if buffer was overflown, 0 if not. */
int i_strocpy(char *dest, const char *src, size_t dstsize);

char *str_ucase(char *str);
char *str_lcase(char *str);
const char *t_str_lcase(const char *str);
const char *t_str_ucase(const char *str);

int null_strcmp(const char *s1, const char *s2) ATTR_PURE;
int bsearch_strcmp(const void *p1, const void *p2) ATTR_PURE;
int bsearch_strcasecmp(const void *p1, const void *p2) ATTR_PURE;
int i_memcasecmp(const void *p1, const void *p2, size_t size) ATTR_PURE;
int i_strcmp_p(const void *p1, const void *p2) ATTR_PURE;
int i_strcasecmp_p(const void *p1, const void *p2) ATTR_PURE;

/* separators is an array of separator characters, not a separator string. */
char **p_strsplit(pool_t pool, const char *data, const char *separators)
	ATTR_MALLOC;
const char **t_strsplit(const char *data, const char *separators)
	ATTR_MALLOC;
/* like p_strsplit(), but treats multiple adjacent separators as a single
   separator. */
char **p_strsplit_spaces(pool_t pool, const char *data, const char *separators)
	ATTR_MALLOC;
const char **t_strsplit_spaces(const char *data, const char *separators)
	ATTR_MALLOC;
void p_strsplit_free(pool_t pool, char **arr);

const char *dec2str(uintmax_t number);

/* Return length of NULL-terminated list string array */
unsigned int str_array_length(const char *const *arr) ATTR_PURE;
/* Return all strings from array joined into one string. */
const char *t_strarray_join(const char *const *arr, const char *separator)
	ATTR_MALLOC;
/* Removes a value from NULL-terminated string array. Returns TRUE if found. */
bool str_array_remove(const char **arr, const char *value);
/* Returns TRUE if value exists in NULL-terminated string array. */
bool str_array_find(const char *const *arr, const char *value);
/* Like str_array_find(), but use strcasecmp(). */
bool str_array_icase_find(const char *const *arr, const char *value);
/* Duplicate array of strings. The memory can be freed by freeing the
   return value. */
const char **p_strarray_dup(pool_t pool, const char *const *arr);

/* INTERNAL */
char *t_noalloc_strdup_vprintf(const char *format, va_list args,
			       unsigned int *size_r);
char *vstrconcat(const char *str1, va_list args, size_t *ret_len) ATTR_MALLOC;

#endif
