#ifndef STR_SANITIZE_H
#define STR_SANITIZE_H

/* All control characters in src will be appended as '?'. If src is longer
   than max_bytes, it's truncated with "..." appended to the end. Note that
   src is treated as UTF-8 input, but max_bytes is in bytes instead of
   UTF-8 characters. */
void str_sanitize_append(string_t *dest, const char *src, size_t max_bytes);
/* Return src sanitized. If there are no changes, src pointer is returned.
   If src is NULL, returns NULL. */
const char *str_sanitize(const char *src, size_t max_bytes);

#endif
