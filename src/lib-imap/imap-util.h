#ifndef __IMAP_UTIL_H
#define __IMAP_UTIL_H

struct mail_full_flags;

/* growing number of flags isn't very easy. biggest problem is that they're
   stored into unsigned int, which is 32bit almost everywhere. another thing
   to remember is that with maildir format, the custom flags are stored into
   file name using 'a'..'z' letters which gets us exactly the needed 26
   flags. if more is added, the current code breaks. */
enum {
	MAIL_CUSTOM_FLAG_1_BIT	= 6,
	MAIL_CUSTOM_FLAGS_COUNT	= 26,

	MAIL_FLAGS_COUNT	= 32
};

/* Return flags as a space separated string. If custom flags don't have entry
   in flags->custom_flags[], or if it's NULL or "" the flag s ignored. */
const char *imap_write_flags(const struct mail_full_flags *flags);

#endif
