/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "mail-types.h"
#include "imap-util.h"

void imap_write_flags(string_t *dest, const struct mail_full_flags *flags)
{
	unsigned int i;
	size_t size;

	size = str_len(dest);
	if ((flags->flags & MAIL_ANSWERED) != 0)
		str_append(dest, "\\Answered ");
	if ((flags->flags & MAIL_FLAGGED) != 0)
		str_append(dest, "\\Flagged ");
	if ((flags->flags & MAIL_DELETED) != 0)
		str_append(dest, "\\Deleted ");
	if ((flags->flags & MAIL_SEEN) != 0)
		str_append(dest, "\\Seen ");
	if ((flags->flags & MAIL_DRAFT) != 0)
		str_append(dest, "\\Draft ");
	if ((flags->flags & MAIL_RECENT) != 0)
		str_append(dest, "\\Recent ");

	if (flags->keywords_count > 0) {
		/* we have keywords too */
		for (i = 0; i < flags->keywords_count; i++) {
			str_append(dest, flags->keywords[i]);
			str_append_c(dest, ' ');
		}
	}

	if (str_len(dest) != size)
		str_truncate(dest, str_len(dest)-1);
}
