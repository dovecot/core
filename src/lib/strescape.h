#ifndef STRESCAPE_H
#define STRESCAPE_H

#define IS_ESCAPED_CHAR(c) ((c) == '"' || (c) == '\\' || (c) == '\'')

/* escape all '\', '"' and "'" characters */
const char *str_escape(const char *str);

/* remove all '\' characters, append to given string */
void str_append_unescaped(string_t *dest, const void *src, size_t src_size);

/* remove all '\' characters */
char *str_unescape(char *str);

/* For Dovecot's internal protocols: Escape \001, \t, \r and \n characters
   using \001. */
const char *str_tabescape(const char *str);
void str_tabescape_write(string_t *dest, const char *src);
void str_append_tabunescaped(string_t *dest, const void *src, size_t src_size);
char *str_tabunescape(char *str);

#endif
