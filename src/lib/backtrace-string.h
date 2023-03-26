#ifndef BACKTRACE_STRING_H
#define BACKTRACE_STRING_H

/* Returns 0 if ok, -1 if failure. */
int backtrace_append(string_t *str, const char **error_r);
int backtrace_get(const char **backtrace_r, const char **error_r);

#endif
