#ifndef __IMAP_QUOTE_H
#define __IMAP_QUOTE_H

/* If value is non-NULL, return it "quoted", otherwise return NIL unquoted. */
const char *imap_quote_str_nil(const char *value);

/* Return value quoted and allocated from specified pool. */
char *imap_quote_value(Pool pool, const char *value, size_t value_len);

#endif
