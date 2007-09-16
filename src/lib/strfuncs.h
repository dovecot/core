#ifndef STRFUNC_H
#define STRFUNC_H

#define is_empty_str(str) \
        ((str) == NULL || (str)[0] == '\0')

#define MAX_INT_STRLEN ((sizeof(uintmax_t) * CHAR_BIT + 2) / 3 + 1)

/* Returns -1 if dest wasn't large enough, 0 if not. */
int i_snprintf(char *dest, size_t max_chars, const char *format, ...)
	__attr_format__(3, 4);

char *p_strdup(pool_t pool, const char *str) __attr_malloc__;
/* return NULL if str = "" */
char *p_strdup_empty(pool_t pool, const char *str) __attr_malloc__;
/* *end isn't included */
char *p_strdup_until(pool_t pool, const void *start, const void *end)
	__attr_malloc__;
char *p_strndup(pool_t pool, const void *str, size_t max_chars) __attr_malloc__;
char *p_strdup_printf(pool_t pool, const char *format, ...)
	__attr_format__(2, 3) __attr_malloc__;
char *p_strdup_vprintf(pool_t pool, const char *format, va_list args)
	__attr_format__(2, 0) __attr_malloc__;
char *p_strconcat(pool_t pool, const char *str1, ...)
	__attr_sentinel__ __attr_malloc__;

/* same with temporary memory allocations: */
const char *t_strdup(const char *str) __attr_malloc__;
char *t_strdup_noconst(const char *str) __attr_malloc__;
/* return NULL if str = "" */
const char *t_strdup_empty(const char *str) __attr_malloc__;
/* *end isn't included */
const char *t_strdup_until(const void *start, const void *end) __attr_malloc__;
const char *t_strndup(const void *str, size_t max_chars) __attr_malloc__;
const char *t_strdup_printf(const char *format, ...)
	__attr_format__(1, 2) __attr_malloc__;
const char *t_strdup_vprintf(const char *format, va_list args)
	__attr_format__(1, 0) __attr_malloc__;
const char *t_strconcat(const char *str1, ...)
	__attr_sentinel__ __attr_malloc__;

/* Like t_strdup(), but stop at cutchar. */
const char *t_strcut(const char *str, char cutchar);

/* Return TRUE if all characters in string are numbers.
   Stop when `end_char' is found from string. */
bool is_numeric(const char *str, char end_char);

/* Like strlcpy(), but return -1 if buffer was overflown, 0 if not. */
int strocpy(char *dest, const char *src, size_t dstsize);

/* Print given directory and file to dest buffer, separated with '/'.
   If destination buffer is too small, it's set to empty string and errno is
   set to ENAMETOOLONG. Retuns -1 if buffer is too small, or 0 if not. */
int str_path(char *dest, size_t dstsize, const char *dir, const char *file);
int str_ppath(char *dest, size_t dstsize, const char *dir,
	      const char *file_prefix, const char *file);

char *str_ucase(char *str);
char *str_lcase(char *str);
const char *t_str_lcase(const char *str);
const char *t_str_ucase(const char *str);

int null_strcmp(const char *s1, const char *s2);
int memcasecmp(const void *p1, const void *p2, size_t size);
int bsearch_strcmp(const void *p1, const void *p2);
int strcmp_p(const void *p1, const void *p2);
int bsearch_strcasecmp(const void *p1, const void *p2);
int strcasecmp_p(const void *p1, const void *p2);

/* separators is an array of separator characters, not a separator string. */
char **p_strsplit(pool_t pool, const char *data, const char *separators)
	__attr_malloc__;
const char **t_strsplit(const char *data, const char *separators)
	__attr_malloc__;
/* like p_strsplit(), but treats multiple adjacent separators as a single
   separator. */
char **p_strsplit_spaces(pool_t pool, const char *data, const char *separators)
	__attr_malloc__;
const char **t_strsplit_spaces(const char *data, const char *separators)
	__attr_malloc__;
void p_strsplit_free(pool_t pool, char **arr);

const char *dec2str(uintmax_t number);

/* Return length of NULL-terminated list string array */
unsigned int strarray_length(const char *const *arr);
/* Return all strings from array joined into one string. */
const char *t_strarray_join(const char *const *arr, const char *separator)
	__attr_malloc__;
/* Removes a value from NULL-terminated string array. Returns TRUE if found. */
bool strarray_remove(const char **arr, const char *value);

/* INTERNAL */
char *t_noalloc_strdup_vprintf(const char *format, va_list args,
			       unsigned int *size_r);
char *_vstrconcat(const char *str1, va_list args, size_t *ret_len)
	__attr_malloc__;

#endif
