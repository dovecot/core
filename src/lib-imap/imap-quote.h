#ifndef __IMAP_QUOTE_H
#define __IMAP_QUOTE_H

/* Return value suitable for sending to client, either as quoted-string or
   literal. */
char *imap_quote(pool_t pool, const unsigned char *value, size_t value_len);

/* Append to existing string. */
void imap_quote_append(string_t *str, const unsigned char *value,
		       size_t value_len);

#define imap_quote_append_string(str, value) \
	imap_quote_append(str, (const unsigned char *) value, (size_t)-1)

#endif
