/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "imap-util.h"

const char *imap_write_flags(const struct mail_full_flags *flags)
{
	string_t *str;
	const char *sysflags, *name;
	unsigned int i;

	i_assert(flags->custom_flags_count <= MAIL_CUSTOM_FLAGS_COUNT);

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

	if ((flags->flags & MAIL_CUSTOM_FLAGS_MASK) == 0)
		return sysflags;

	/* we have custom flags too */
	str = t_str_new(256);
	str_append(str, sysflags);

	for (i = 0; i < flags->custom_flags_count; i++) {
		if (flags->flags & (1 << (i + MAIL_CUSTOM_FLAG_1_BIT))) {
			name = flags->custom_flags[i];
			if (name != NULL && *name != '\0') {
				if (str_len(str) > 0)
					str_append_c(str, ' ');
				str_append(str, name);
			}
		}
	}

	return str_c(str);
}
