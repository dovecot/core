#ifndef EACCES_ERROR_H
#define EACCES_ERROR_H

/* Return a user-friendly error message for EACCES failures. */
const char *eacces_error_get(const char *func, const char *path);
const char *eacces_error_get_creating(const char *func, const char *path);

#endif
