#ifndef __IMAP_UTIL_H
#define __IMAP_UTIL_H

typedef enum {
	MAIL_ANSWERED		= 0x0000001,
	MAIL_FLAGGED		= 0x0000002,
	MAIL_DELETED		= 0x0000004,
	MAIL_SEEN		= 0x0000008,
	MAIL_DRAFT		= 0x0000010,
	MAIL_RECENT		= 0x0000020,

	/* rest of the bits are custom flags */
	MAIL_CUSTOM_FLAG_1      = 0x0000040
} MailFlags;

/* growing number of flags isn't very easy. biggest problem is that they're
   stored into unsigned int, which is 32bit almost everywhere. another thing
   to remember is that with maildir format, the custom flags are stored into
   file name using 'a'..'z' letters which gets us exactly the needed 26
   flags. if more is added, the current code breaks. */
enum {
	MAIL_SYSTEM_FLAGS_MASK	= 0x000003f,
	MAIL_CUSTOM_FLAGS_MASK	= 0xfffffc0,

	MAIL_CUSTOM_FLAG_1_BIT	= 6,
	MAIL_CUSTOM_FLAGS_COUNT	= 26,

	MAIL_FLAGS_COUNT	= 32
};

#define IS_ESCAPED_CHAR(c) ((c) == '"' || (c) == '\\')

/* Return flags as a space separated string. custom_flags[] is a list of
   names for custom flags, flags having NULL or "" entry are ignored. */
const char *imap_write_flags(MailFlags flags, const char *custom_flags[]);

/* Escape the string */
const char *imap_escape(const char *str);

#endif
