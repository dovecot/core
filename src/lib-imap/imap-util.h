#ifndef __IMAP_UTIL_H
#define __IMAP_UTIL_H

struct mail_full_flags;

/* Return flags as a space separated string. */
const char *imap_write_flags(const struct mail_full_flags *flags);

#endif
