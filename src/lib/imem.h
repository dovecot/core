#ifndef IMEM_H
#define IMEM_H

/* For easy allocation of memory from default memory pool. */

extern pool_t default_pool;

#define i_new(type, count) p_new(default_pool, type, count)

void *i_malloc(size_t size) __attr_malloc__;
void *i_realloc(void *mem, size_t old_size, size_t new_size)
	__attr_warn_unused_result__;

#define i_free(mem) p_free(default_pool, mem)
#define i_free_and_null(mem) p_free_and_null(default_pool, mem)

/* string functions */
char *i_strdup(const char *str) __attr_malloc__;
/* like i_strdup(), but if str == "", return NULL */
char *i_strdup_empty(const char *str) __attr_malloc__;
/* *end isn't included */
char *i_strdup_until(const void *str, const void *end) __attr_malloc__;
char *i_strndup(const void *str, size_t max_chars) __attr_malloc__;
char *i_strdup_printf(const char *format, ...)
	__attr_format__(1, 2) __attr_malloc__;
char *i_strdup_vprintf(const char *format, va_list args)
	__attr_format__(1, 0) __attr_malloc__;

char *i_strconcat(const char *str1, ...)  __attr_sentinel__ __attr_malloc__;

#endif
