#ifndef IMAP_QUOTE_H
#define IMAP_QUOTE_H

/* Append "quoted" or literal. */
void imap_append_string(string_t *dest, const char *src);
/* Append atom, "quoted" or literal. */
void imap_append_astring(string_t *dest, const char *src);
/* Append NIL, "quoted" or literal. */
void imap_append_nstring(string_t *dest, const char *src);
/* Append "quoted". If src has 8bit chars, skip over them. */
void imap_append_quoted(string_t *dest, const char *src);

/* Otherwise the same as imap_append_string(), but cleanup the input data
   so that it's more readable by humans. This includes converting TABs to
   spaces, multiple spaces into a single space and NULs to #0x80. */
void imap_append_string_for_humans(string_t *dest,
				   const unsigned char *src, size_t size);

#endif
