/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "mail-types.h"
#include "imap-util.h"

void imap_write_flags(string_t *dest, enum mail_flags flags,
		      const char *const *keywords)
{
	size_t size;

	size = str_len(dest);
	if ((flags & MAIL_ANSWERED) != 0)
		str_append(dest, "\\Answered ");
	if ((flags & MAIL_FLAGGED) != 0)
		str_append(dest, "\\Flagged ");
	if ((flags & MAIL_DELETED) != 0)
		str_append(dest, "\\Deleted ");
	if ((flags & MAIL_SEEN) != 0)
		str_append(dest, "\\Seen ");
	if ((flags & MAIL_DRAFT) != 0)
		str_append(dest, "\\Draft ");
	if ((flags & MAIL_RECENT) != 0)
		str_append(dest, "\\Recent ");

	if (keywords != NULL) {
		/* we have keywords too */
		while (*keywords != NULL) {
			str_append(dest, *keywords);
			str_append_c(dest, ' ');
			keywords++;
		}
	}

	if (str_len(dest) != size)
		str_truncate(dest, str_len(dest)-1);
}
