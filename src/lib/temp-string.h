#ifndef __TEMP_STRING_H
#define __TEMP_STRING_H

/* All memory in TempString is allocated from temporary memory pool,
   so it can't be stored permanently. */

struct _TempString {
	char *str;
	unsigned int len;
};

TempString *t_string_new(unsigned int initial_size);

/* Append string/character */
void t_string_append(TempString *tstr, const char *str);
void t_string_append_n(TempString *tstr, const char *str, unsigned int size);
void t_string_append_c(TempString *tstr, char chr);

/* Insert string/character (FIXME: not implemented) */
/*void t_string_insert(TempString *tstr, int pos, const char *str);
void t_string_insert_n(TempString *tstr, int pos, const char *str, int size);
void t_string_insert_c(TempString *tstr, int pos, char chr);*/

/* Append printf()-like data */
void t_string_printfa(TempString *tstr, const char *fmt, ...)
	__attr_format__(2, 3);

/* Erase/truncate */
void t_string_erase(TempString *tstr, unsigned int pos, unsigned int len);
void t_string_truncate(TempString *tstr, unsigned int len);

#endif
