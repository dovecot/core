#ifndef IMAP_QUOTE_H
#define IMAP_QUOTE_H

/* Append to existing string. If fix_text=TRUE, it converts TABs to spaces,
   multiple spaces into a single space and NULs to #128. */
void imap_quote_append(string_t *str, const unsigned char *value,
		       size_t value_len, bool fix_text);

#define imap_quote_append_string(str, value, fix_text) \
	imap_quote_append(str, (const unsigned char *)(value), \
			  (size_t)-1, fix_text)

/* Return value suitable for sending to client, either as quoted-string or
   literal. */
const char *imap_quote(pool_t pool, const unsigned char *value,
		       size_t value_len, bool fix_text);

/* Append "quoted" or literal. */
void imap_append_string(string_t *dest, const char *src);
/* Append atom, "quoted" or literal. */
void imap_append_astring(string_t *dest, const char *src);
/* Append NIL, "quoted" or literal. */
void imap_append_nstring(string_t *dest, const char *src);
/* Append "quoted". If src has 8bit chars, skip over them. */
void imap_append_quoted(string_t *dest, const char *src);

#endif
