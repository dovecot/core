#ifndef STR_SANITIZE_H
#define STR_SANITIZE_H

/* All control characters in src will be appended as '?'. If src is longer
   than max_len, it's truncated with "..." appended to the end. */
void str_sanitize_append(string_t *dest, const char *src, size_t max_len);
/* Return src sanitized. If there are no changes, src pointer is returned.
   If src is NULL, returns NULL. */
const char *str_sanitize(const char *src, size_t max_len);

#endif
