#ifndef IMAP_UTF7_H
#define IMAP_UTF7_H

/* Convert an UTF-8 string to IMAP-UTF-7. Returns 0 if ok, -1 if src isn't
   valid UTF-8. */
int imap_utf8_to_utf7(const char *src, string_t *dest);
int t_imap_utf8_to_utf7(const char *src, const char **dest_r);
/* Convert IMAP-UTF-7 string to UTF-8. Returns 0 if ok, -1 if src isn't
   valid IMAP-UTF-7. */
int imap_utf7_to_utf8(const char *src, string_t *dest);
/* Returns TRUE if the string is valid IMAP-UTF-7 string. */
bool imap_utf7_is_valid(const char *src);

#endif
