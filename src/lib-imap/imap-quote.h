#ifndef __IMAP_QUOTE_H
#define __IMAP_QUOTE_H

/* Return value suitable for sending to client, either as quoted-string or
   literal. */
char *imap_quote(pool_t pool, const unsigned char *value, size_t value_len);

/* Append to existing string. */
void imap_quote_append(string_t *str, const unsigned char *value,
		       size_t value_len);

/* If value is NULL, return NIL. */
const char *imap_quote_str_nil(const char *value);

#endif
