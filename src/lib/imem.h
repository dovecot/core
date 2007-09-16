#ifndef IMEM_H
#define IMEM_H

/* For easy allocation of memory from default memory pool. */

extern pool_t default_pool;

#define i_new(type, count) p_new(default_pool, type, count)

void *i_malloc(size_t size) ATTR_MALLOC;
void *i_realloc(void *mem, size_t old_size, size_t new_size)
	ATTR_WARN_UNUSED_RESULT;

#define i_free(mem) p_free(default_pool, mem)
#define i_free_and_null(mem) p_free_and_null(default_pool, mem)

/* string functions */
char *i_strdup(const char *str) ATTR_MALLOC;
/* like i_strdup(), but if str == "", return NULL */
char *i_strdup_empty(const char *str) ATTR_MALLOC;
/* *end isn't included */
char *i_strdup_until(const void *str, const void *end) ATTR_MALLOC;
char *i_strndup(const void *str, size_t max_chars) ATTR_MALLOC;
char *i_strdup_printf(const char *format, ...)
	ATTR_FORMAT(1, 2) ATTR_MALLOC;
char *i_strdup_vprintf(const char *format, va_list args)
	ATTR_FORMAT(1, 0) ATTR_MALLOC;

char *i_strconcat(const char *str1, ...)  ATTR_SENTINEL ATTR_MALLOC;

#endif
