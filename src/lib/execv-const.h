#ifndef EXECV_CONST_H
#define EXECV_CONST_H

/* Just like execv() and execvp(), except argv points to const strings.
   Also if calling execv*() fails, these functions call i_fatal(). */
void execv_const(const char *path, const char *const argv[]) ATTR_NORETURN;
void execvp_const(const char *file, const char *const argv[]) ATTR_NORETURN;

#endif
