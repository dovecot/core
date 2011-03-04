/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "mail-types.h"
#include "imap-parser.h"
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

enum mail_flags imap_parse_system_flag(const char *str)
{
	if (strcasecmp(str, "\\Answered") == 0)
		return MAIL_ANSWERED;
	else if (strcasecmp(str, "\\Flagged") == 0)
		return MAIL_FLAGGED;
	else if (strcasecmp(str, "\\Deleted") == 0)
		return MAIL_DELETED;
	else if (strcasecmp(str, "\\Seen") == 0)
		return MAIL_SEEN;
	else if (strcasecmp(str, "\\Draft") == 0)
		return MAIL_DRAFT;
	else if (strcasecmp(str, "\\Recent") == 0)
		return MAIL_RECENT;
	else
		return 0;
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

void imap_write_args(string_t *dest, const struct imap_arg *args)
{
	bool first = TRUE;

	for (; !IMAP_ARG_IS_EOL(args); args++) {
		if (first)
			first = FALSE;
		else
			str_append_c(dest, ' ');

		switch (args->type) {
		case IMAP_ARG_NIL:
			str_append(dest, "NIL");
			break;
		case IMAP_ARG_ATOM:
			str_append(dest, imap_arg_as_astring(args));
			break;
		case IMAP_ARG_STRING:
			str_append_c(dest, '"');
			str_append(dest, str_escape(imap_arg_as_astring(args)));
			str_append_c(dest, '"');
			break;
		case IMAP_ARG_LITERAL: {
			const char *strarg = imap_arg_as_astring(args);
			str_printfa(dest, "{%"PRIuSIZE_T"}\r\n",
				    strlen(strarg));
			str_append(dest, strarg);
			break;
		}
		case IMAP_ARG_LIST:
			str_append_c(dest, '(');
			imap_write_args(dest, imap_arg_as_list(args));
			str_append_c(dest, ')');
			break;
		case IMAP_ARG_LITERAL_SIZE:
		case IMAP_ARG_LITERAL_SIZE_NONSYNC:
			str_printfa(dest, "{%"PRIuUOFF_T"}\r\n",
				    imap_arg_as_literal_size(args));
			str_append(dest, "<too large>");
			break;
		case IMAP_ARG_EOL:
			i_unreached();
		}
	}
}

const char *imap_args_to_str(const struct imap_arg *args)
{
	string_t *str;

	str = t_str_new(128);
	imap_write_args(str, args);
	return str_c(str);
}
