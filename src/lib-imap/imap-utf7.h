#ifndef IMAP_UTF7_H
#define IMAP_UTF7_H

/* Convert an UTF-8 string to IMAP-UTF-7. Returns 0 if ok, -1 if src isn't
   valid UTF-8. */
int imap_utf8_to_utf7(const char *src, string_t *dest);
int t_imap_utf8_to_utf7(const char *src, const char **dest_r);
/* Like imap_utf8_to_utf7(), but decode all <escape_char><hex> instances.
   Returns -1 if src isn't valid UTF-8. Note that invalid <escape_char> content
   isn't treated as an error - it's simply passed through. */
int imap_escaped_utf8_to_utf7(const char *src, char escape_char, string_t *dest);
/* For manually parsing the <hex> after <escape_char>. Returns 0 on success,
   -1 if str doesn't point to valid <hex>. */
int imap_escaped_utf8_hex_to_char(const char *str, unsigned char *chr_r);

/* Convert IMAP-UTF-7 string to UTF-8. Returns 0 if ok, -1 if src isn't
   valid IMAP-UTF-7. */
int imap_utf7_to_utf8(const char *src, string_t *dest);
/* Like imap_utf7_to_utf8(), but write invalid input as <escape_chars[0]><hex>.
   All the characters in escape_chars[] are escaped in the same way. This
   allows converting the escaped output back to the original (broken)
   IMAP-UTF-7 input. */
void imap_utf7_to_utf8_escaped(const char *src, const char *escape_chars,
			       string_t *dest);
/* Returns TRUE if the string is valid IMAP-UTF-7 string. */
bool imap_utf7_is_valid(const char *src);

#endif
