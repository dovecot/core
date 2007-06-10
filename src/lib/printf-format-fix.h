#ifndef __PRINTF_FORMAT_FIX_H
#define __PRINTF_FORMAT_FIX_H

/* Replaces %m in format with strerror(errno) and panics if %n modifier is
   used. Returns TRUE if format was modified. */
bool printf_format_fix(const char **format);

#endif
