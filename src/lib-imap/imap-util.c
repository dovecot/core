/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "mail-types.h"
#include "imap-util.h"

const char *imap_write_flags(const struct mail_full_flags *flags)
{
	string_t *str;
	const char *sysflags;
	unsigned int i;

	if (flags == 0)
		return "";

	sysflags = t_strconcat(
		(flags->flags & MAIL_ANSWERED) ? " \\Answered" : "",
		(flags->flags & MAIL_FLAGGED) ? " \\Flagged" : "",
		(flags->flags & MAIL_DELETED) ? " \\Deleted" : "",
		(flags->flags & MAIL_SEEN) ? " \\Seen" : "",
		(flags->flags & MAIL_DRAFT) ? " \\Draft" : "",
		(flags->flags & MAIL_RECENT)  ? " \\Recent" : "",
		NULL);

	if (*sysflags != '\0')
		sysflags++;

	if (flags->keywords_count == 0)
		return sysflags;

	/* we have keywords too */
	str = t_str_new(256);
	str_append(str, sysflags);

	for (i = 0; i < flags->keywords_count; i++) {
		if (str_len(str) > 0)
			str_append_c(str, ' ');
		str_append(str, flags->keywords[i]);
	}
	return str_c(str);
}
