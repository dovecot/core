#ifndef __TEMP_STRING_H
#define __TEMP_STRING_H

/* All memory in TempString is allocated from data stack, so it MUST NOT be
   stored permanently. */

struct _TempString {
	char *str;
	size_t len;
};

TempString *t_string_new(size_t initial_size);

/* Append string/character */
void t_string_append(TempString *tstr, const char *str);
void t_string_append_n(TempString *tstr, const char *str, size_t size);
void t_string_append_c(TempString *tstr, char chr);

/* Append printf()-like data */
void t_string_printfa(TempString *tstr, const char *fmt, ...)
	__attr_format__(2, 3);

/* Erase/truncate */
void t_string_erase(TempString *tstr, size_t pos, size_t len);
void t_string_truncate(TempString *tstr, size_t len);

#endif
