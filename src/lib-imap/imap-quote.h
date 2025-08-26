#ifndef IMAP_QUOTE_H
#define IMAP_QUOTE_H

enum imap_quote_flags {
	/* This flag indicates that UTF-8 is allowed in quoted strings. When
	   generating IMAP string values with the functions below, the
	   production of quoted strings is preferred, unless characters need to
	   be represented that are not allowed therein. In that case, a literal
	   will be produced. This flag extends the allowed characters with valid
	   UTF-8 sequences. In case of invalid UTF-8, a literal will still be
	   emitted instead. */
	IMAP_QUOTE_FLAG_UTF8 = BIT(0),
};

/* Append "quoted" or literal. */
void imap_append_string(string_t *dest, const char *src,
			enum imap_quote_flags flags);
/* Append atom, "quoted" or literal. */
void imap_append_astring(string_t *dest, const char *src,
			 enum imap_quote_flags flags);
/* Append NIL, "quoted" or literal. */
void imap_append_nstring(string_t *dest, const char *src,
			 enum imap_quote_flags flags);
/* Append NIL, "quoted" or literal, CRs and LFs skipped. */
void imap_append_nstring_nolf(string_t *dest, const char *src,
			      enum imap_quote_flags flags);
/* Append "quoted". If src has 8bit chars, skip over them. */
void imap_append_quoted(string_t *dest, const char *src,
			enum imap_quote_flags flags);

/* Otherwise the same as imap_append_string(), but cleanup the input data
   so that it's more readable by humans. This includes converting TABs to
   spaces, multiple spaces into a single space and NULs to #0x80. */
void imap_append_string_for_humans(string_t *dest,
				   const unsigned char *src, size_t size,
				   enum imap_quote_flags flags);

#endif
