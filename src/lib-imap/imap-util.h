#ifndef __IMAP_UTIL_H
#define __IMAP_UTIL_H

struct mail_full_flags;

/* Return flags as a space separated string. */
void imap_write_flags(string_t *dest, const struct mail_full_flags *flags);

#endif
