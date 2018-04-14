#ifndef STR_SANITIZE_H
#define STR_SANITIZE_H

/* All control characters in src will be appended as '?'. If src is longer
   than max_bytes, it's truncated with "..." appended to the end. Note that
   src is treated as UTF-8 input, but max_bytes is in bytes instead of
   UTF-8 characters. */
void str_sanitize_append(string_t *dest, const char *src, size_t max_bytes);
/* All control characters in src will be appended as the unicode replacement
   character (U+FFFD). If src has more than max_cps unicode code points, it's
   truncated with a horizontal ellipsis character (U+2026) appended to the end.
 */
void str_sanitize_append_utf8(string_t *dest, const char *src,
			      uintmax_t max_cps);
/* Return src sanitized. If there are no changes, src pointer is returned.
   If src is NULL, returns NULL. */
const char *str_sanitize(const char *src, size_t max_bytes);
/* The unicode version of str_sanitize() using str_sanitize_append_utf8()
   internally. */
const char *str_sanitize_utf8(const char *src, uintmax_t max_cps);

#endif
