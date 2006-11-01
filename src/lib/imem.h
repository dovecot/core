#ifndef __IMEM_H
#define __IMEM_H

/* For easy allocation of memory from default memory pool. */

extern pool_t default_pool;

#define i_new(type, count) p_new(default_pool, type, count)

void *i_malloc(size_t size);
void *i_realloc(void *mem, size_t old_size, size_t new_size);

#define i_free(mem) p_free(default_pool, mem)
#define i_free_and_null(mem) p_free_and_null(default_pool, mem)

/* string functions */
char *i_strdup(const char *str);
char *i_strdup_empty(const char *str); /* like i_strdup(), but if str == "", return NULL */
char *i_strdup_until(const void *str, const void *end); /* *end isn't included */
char *i_strndup(const void *str, size_t max_chars);
char *i_strdup_printf(const char *format, ...) __attr_format__(1, 2);
char *i_strdup_vprintf(const char *format, va_list args) __attr_format__(1, 0);

char *i_strconcat(const char *str1, ...)  __attr_sentinel__;

void imem_init(void);

#endif
