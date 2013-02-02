/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "imap-list.h"

bool imap_mailbox_flags2str(string_t *str, enum mailbox_info_flags flags)
{
	unsigned int orig_len = str_len(str);

	if ((flags & MAILBOX_SUBSCRIBED) != 0)
		str_append(str, "\\Subscribed ");

	if ((flags & MAILBOX_NOSELECT) != 0)
		str_append(str, "\\Noselect ");
	if ((flags & MAILBOX_NONEXISTENT) != 0)
		str_append(str, "\\NonExistent ");

	if ((flags & MAILBOX_CHILDREN) != 0)
		str_append(str, "\\HasChildren ");
	else if ((flags & MAILBOX_NOINFERIORS) != 0)
		str_append(str, "\\NoInferiors ");
	else if ((flags & MAILBOX_NOCHILDREN) != 0)
		str_append(str, "\\HasNoChildren ");

	if ((flags & MAILBOX_MARKED) != 0)
		str_append(str, "\\Marked ");
	if ((flags & MAILBOX_UNMARKED) != 0)
		str_append(str, "\\UnMarked ");

	if (str_len(str) == orig_len)
		return FALSE;
	str_truncate(str, str_len(str)-1);
	return TRUE;
}
