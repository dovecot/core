#ifndef __STRESCAPE_H
#define __STRESCAPE_H

#define IS_ESCAPED_CHAR(c) ((c) == '"' || (c) == '\\')

/* escape all '\' and '"' characters */
const char *str_escape(const char *str);

/* remove all '\' characters, append to given string */
void str_append_unescaped(String *dest, const char *src, size_t src_size);

/* remove all '\' characters */
void str_unescape(char *str);

#endif
