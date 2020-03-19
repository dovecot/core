/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-quote.h"
#include "mail-search.h"

static void
mail_search_arg_to_cmdline(string_t *dest, const struct mail_search_arg *arg);

static void
mail_search_subargs_to_cmdline(string_t *dest, const struct mail_search_arg *args,
			       const char *middle)
{
	const struct mail_search_arg *arg;

	str_append(dest, "( ");
	for (arg = args; arg != NULL; arg = arg->next) {
		mail_search_arg_to_cmdline(dest, arg);
		if (arg->next != NULL)
			str_append(dest, middle);
	}
	str_append(dest, " )");
}

static void
mail_search_arg_to_cmdline(string_t *dest, const struct mail_search_arg *arg)
{
	struct mail_search_arg new_arg;
	const char *error;

	if (arg->match_not)
		str_append(dest, "NOT ");
	switch (arg->type) {
	case SEARCH_OR:
		mail_search_subargs_to_cmdline(dest, arg->value.subargs, " OR ");
		return;
	case SEARCH_SUB:
		mail_search_subargs_to_cmdline(dest, arg->value.subargs, " ");
		return;
	case SEARCH_FLAGS:
	case SEARCH_KEYWORDS: {
		size_t pos = str_len(dest);

		new_arg = *arg;
		new_arg.match_not = FALSE;
		if (!mail_search_arg_to_imap(dest, &new_arg, &error))
			i_unreached();
		if (str_c(dest)[pos] == '(') {
			str_insert(dest, pos+1, " ");
			str_insert(dest, str_len(dest)-1, " ");
		}
		return;
	}
	case SEARCH_INTHREAD:
		str_append(dest, "INTHREAD ");
		imap_append_astring(dest, mail_thread_type_to_str(arg->value.thread_type));
		str_append_c(dest, ' ');
		mail_search_subargs_to_cmdline(dest, arg->value.subargs, " ");
		break;
	case SEARCH_MAILBOX:
	case SEARCH_MAILBOX_GLOB:
		str_append(dest, "MAILBOX ");
		imap_append_astring(dest, arg->value.str);
		return;
	case SEARCH_MAILBOX_GUID:
		str_append(dest, "MAILBOX-GUID ");
		imap_append_astring(dest, arg->value.str);
		return;
	case SEARCH_ALL:
	case SEARCH_SEQSET:
	case SEARCH_UIDSET:
	case SEARCH_BEFORE:
	case SEARCH_ON:
	case SEARCH_SINCE:
	case SEARCH_SMALLER:
	case SEARCH_LARGER:
	case SEARCH_HEADER:
	case SEARCH_HEADER_ADDRESS:
	case SEARCH_HEADER_COMPRESS_LWSP:
	case SEARCH_BODY:
	case SEARCH_TEXT:
	case SEARCH_MODSEQ:
	case SEARCH_SAVEDATESUPPORTED:
	case SEARCH_GUID:
	case SEARCH_REAL_UID:
	case SEARCH_MIMEPART:
		break;
	}
	new_arg = *arg;
	new_arg.match_not = FALSE;
	if (!mail_search_arg_to_imap(dest, &new_arg, &error))
		i_panic("mail_search_args_to_cmdline(): Missing handler: %s", error);
}

void mail_search_args_to_cmdline(string_t *dest,
				 const struct mail_search_arg *args)
{
	const struct mail_search_arg *arg;

	for (arg = args; arg != NULL; arg = arg->next) {
		mail_search_arg_to_cmdline(dest, arg);
		if (arg->next != NULL)
			str_append_c(dest, ' ');
	}
}
