#ifndef __STR_H
#define __STR_H

String *str_new(Pool pool, size_t initial_size);
String *t_str_new(size_t initial_size);

const char *str_c(String *str);
char *str_c_modifyable(String *str);
size_t str_len(const String *str);

/* Append string/character */
void str_append(String *str, const char *cstr);
void str_append_n(String *str, const char *cstr, size_t max_len);
void str_append_c(String *str, char chr);
void str_append_str(String *dest, const String *src);

/* Append printf()-like data */
void str_printfa(String *str, const char *fmt, ...)
	__attr_format__(2, 3);
void str_vprintfa(String *str, const char *fmt, va_list args);

/* Delete/truncate */
void str_delete(String *str, size_t pos, size_t len);
void str_truncate(String *str, size_t len);

#endif
