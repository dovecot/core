/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "imap-util.h"

const char *imap_write_flags(MailFlags flags, const char *custom_flags[],
			     unsigned int custom_flags_count)
{
	String *str;
	const char *sysflags, *name;
	unsigned int i;

	i_assert(custom_flags_count <= MAIL_CUSTOM_FLAGS_COUNT);

	if (flags == 0)
		return "";

	sysflags = t_strconcat((flags & MAIL_ANSWERED) ? " \\Answered" : "",
			       (flags & MAIL_FLAGGED) ? " \\Flagged" : "",
			       (flags & MAIL_DELETED) ? " \\Deleted" : "",
			       (flags & MAIL_SEEN) ? " \\Seen" : "",
			       (flags & MAIL_DRAFT) ? " \\Draft" : "",
			       (flags & MAIL_RECENT)  ? " \\Recent" : "",
			       NULL);

	if (*sysflags != '\0')
		sysflags++;

	if ((flags & MAIL_CUSTOM_FLAGS_MASK) == 0)
		return sysflags;

	/* we have custom flags too */
	str = t_str_new(256);
	str_append(str, sysflags);

	for (i = 0; i < custom_flags_count; i++) {
		if (flags & (1 << (i + MAIL_CUSTOM_FLAG_1_BIT))) {
			name = custom_flags[i];
			if (name != NULL && *name != '\0') {
				if (str_len(str) > 0)
					str_append_c(str, ' ');
				str_append(str, name);
			}
		}
	}

	return str_c(str);
}

const char *imap_escape(const char *str)
{
	char *ret, *p;
	size_t i, esc;

	/* get length of string and number of chars to escape */
	esc = 0;
	for (i = 0; str[i] != '\0'; i++) {
		if (IS_ESCAPED_CHAR(str[i]))
			esc++;
	}

	if (esc == 0)
		return str;

	/* @UNSAFE: escape them */
	p = ret = t_malloc(i + esc + 1);
	for (; *str != '\0'; str++) {
		if (IS_ESCAPED_CHAR(str[i]))
			*p++ = '\\';
		*p++ = *str;
	}
	*p = '\0';
	return ret;
}
