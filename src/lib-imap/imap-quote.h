#ifndef IMAP_QUOTE_H
#define IMAP_QUOTE_H

/* Return value suitable for sending to client, either as quoted-string or
   literal. Note that this also converts TABs into spaces, multiple spaces
   into single space and NULs to #128. */
const char *imap_quote(pool_t pool, const unsigned char *value,
		       size_t value_len);

/* Append to existing string. */
void imap_quote_append(string_t *str, const unsigned char *value,
		       size_t value_len, bool compress_lwsp);

#define imap_quote_append_string(str, value, compress_lwsp) \
	imap_quote_append(str, (const unsigned char *)(value), \
			  (size_t)-1, compress_lwsp)

#endif
