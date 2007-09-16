#ifndef IMAP_UTIL_H
#define IMAP_UTIL_H

/* Write flags as a space separated string. */
void imap_write_flags(string_t *dest, enum mail_flags flags,
		      const char *const *keywords);

#endif
