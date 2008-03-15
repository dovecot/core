/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
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

void imap_write_seq_range(string_t *dest, const ARRAY_TYPE(seq_range) *array)
{
	const struct seq_range *range;
	unsigned int i, count;

	range = array_get(array, &count);
	for (i = 0; i < count; i++) {
		if (i > 0)
			str_append_c(dest, ',');
		str_printfa(dest, "%u", range[i].seq1);
		if (range[i].seq1 != range[i].seq2)
			str_printfa(dest, ":%u", range[i].seq2);
	}
}
