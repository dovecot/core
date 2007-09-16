#ifndef BACKTRACE_STRING_H
#define BACKTRACE_STRING_H

/* Returns 0 if ok, -1 if failure. */
int backtrace_append(string_t *str);
int backtrace_get(const char **backtrace_r);

#endif
