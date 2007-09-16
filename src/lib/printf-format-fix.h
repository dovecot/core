#ifndef PRINTF_FORMAT_FIX_H
#define PRINTF_FORMAT_FIX_H

/* Replaces %m in format with strerror(errno) and panics if %n modifier is
   used. If the format string was modified, it's returned from data stack. */
const char *printf_format_fix(const char *format) ATTR_FORMAT_ARG(1);
/* Like printf_format_fix(), except return also the format string's length. */
const char *printf_format_fix_get_len(const char *format, unsigned int *len_r)
	ATTR_FORMAT_ARG(1);
/* Like printf_format_fix(), except the format string is written to data
   stack without actually allocating it. Data stack must not be used until
   format string is no longer needed. */
const char *printf_format_fix_unsafe(const char *format) ATTR_FORMAT_ARG(1);

#endif
