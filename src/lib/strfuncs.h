#ifndef __STRFUNC_H
#define __STRFUNC_H

/* max. size for %d and %ld */
#define MAX_INT_STRLEN ((sizeof(int) * CHAR_BIT + 2) / 3 + 1)
#define MAX_LONG_STRLEN ((sizeof(long) * CHAR_BIT + 2) / 3 + 1)

/* `str' should be type char[MAX_INT_STRLEN] or char[MAX_LONG_STRLEN] */
#define itoa(str, num) \
	i_snprintf(str, sizeof(str), "%d", num)
#define ltoa(str, num) \
	i_snprintf(str, sizeof(str), "%ld", num)

#define is_empty_str(str) \
        ((str) == NULL || (str)[0] == '\0')

unsigned int printf_string_upper_bound(const char *format, va_list args);
int i_snprintf(char *str, unsigned int max_chars, const char *format, ...)
	__attr_format__(3, 4);

char *p_strdup(Pool pool, const char *str);
char *p_strdup_empty(Pool pool, const char *str); /* return NULL if str = "" */
char *p_strdup_until(Pool pool, const char *start, const char *end); /* *end isn't included */
char *p_strndup(Pool pool, const char *str, unsigned int max_chars);
char *p_strdup_printf(Pool pool, const char *format, ...) __attr_format__(2, 3);
char *p_strdup_vprintf(Pool pool, const char *format, va_list args);
void p_strdup_replace(Pool pool, char **dest, const char *str);
int *p_intarrdup(Pool pool, const int *arr);

char *p_strconcat(Pool pool, const char *str1, ...); /* NULL terminated */

/* same with temporary memory allocations: */
const char *t_strdup(const char *str);
char *t_strdup_noconst(const char *str);
const char *t_strdup_empty(const char *str); /* return NULL if str = "" */
const char *t_strdup_until(const char *start, const char *end); /* *end isn't included */
const char *t_strndup(const char *str, unsigned int max_chars);
const char *t_strdup_printf(const char *format, ...) __attr_format__(1, 2);
const char *t_strdup_vprintf(const char *format, va_list args);
const int *t_intarrdup(const int *arr);

const char *t_strconcat(const char *str1, ...); /* NULL terminated */
const char *t_strcut(const char *str, char cutchar);

/* Return TRUE if all characters in string are numbers.
   Stop when `end_char' is found from string. */
int is_numeric(const char *str, char end_char);

char *str_ucase(char *str);
char *str_lcase(char *str);
char *i_strtoken(char **str, char delim);
void string_remove_escapes(char *str);

/* returns number of items in array */
int strarray_length(char *const array[]);
/* return index of item in array, or -1 if not found */
int strarray_find(char *const array[], const char *item);

/* seprators is an array of separator characters, not a separator string. */
char * const *t_strsplit(const char *data, const char *separators);

#define t_strjoin(args, separator) \
	t_strjoin_replace(args, separator, -1, NULL)
const char *t_strjoin_replace(char *const args[], char separator,
			      int replacearg, const char *replacedata);

/* INTERNAL */
const char *temp_strconcat(const char *str1, va_list args,
			   unsigned int *ret_len);

#endif
