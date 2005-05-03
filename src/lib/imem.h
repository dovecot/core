#ifndef __IMEM_H
#define __IMEM_H

extern pool_t default_pool;

/* For easy allocation of memory from default memory pool. */
#define i_new(type, count) \
        ((type *) i_malloc(sizeof(type) * (count)))

void *i_malloc(size_t size);
void *i_realloc(void *mem, size_t old_size, size_t new_size);

/* Free the memory. Currently it also sets memory to NULL, but that shouldn't
   be relied on as it's only extra safety check. It might as well be later
   changed to some invalid pointer causing segfault, or removed completely
   in some "optimization".. */
#define i_free(mem) \
	STMT_START { \
          p_free(default_pool, mem); \
          (mem) = NULL; \
	} STMT_END

/* A macro that's guaranteed to set mem = NULL. */
#define i_free_and_null(mem) i_free(mem)

/* string functions */
char *i_strdup(const char *str);
char *i_strdup_empty(const char *str); /* like i_strdup(), but if str == "", return NULL */
char *i_strdup_until(const void *str, const void *end); /* *end isn't included */
char *i_strndup(const void *str, size_t max_chars);
char *i_strdup_printf(const char *format, ...) __attr_format__(1, 2);
char *i_strdup_vprintf(const char *format, va_list args);

char *i_strconcat(const char *str1, ...); /* NULL terminated */

void imem_init(void);
void imem_deinit(void);

#endif
