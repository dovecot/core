#ifndef __IMEM_H
#define __IMEM_H

extern Pool default_pool;

/* For easy allocation of memory from default memory pool. */
#define i_new(type, count) \
        ((type *) i_malloc(sizeof(type) * (count)))
void *i_malloc(size_t size);
void i_free(void *mem);
void *i_realloc(void *mem, size_t size);

/* string functions */
char *i_strdup(const char *str);
char *i_strdup_empty(const char *str); /* like i_strdup(), but if str == "", return NULL */
char *i_strdup_until(const char *str, const char *end); /* *end isn't included */
char *i_strndup(const char *str, size_t max_chars);
char *i_strdup_printf(const char *format, ...) __attr_format__(1, 2);
char *i_strdup_vprintf(const char *format, va_list args);

char *i_strconcat(const char *str1, ...); /* NULL terminated */

void imem_init(void);
void imem_deinit(void);

#endif
