/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "imap-list.h"

static ARRAY(const struct imap_list_return_flag *) return_flags;

void imap_list_return_flag_register(const struct imap_list_return_flag *rflag)
{
	array_push_back(&return_flags, &rflag);
}

void imap_list_return_flag_unregister(const struct imap_list_return_flag *rflag)
{
	unsigned int i;

	if (array_lsearch_ptr_idx(&return_flags, rflag, &i)) {
		array_delete(&return_flags, i, 1);
		return;
	}

	i_panic("Trying to unregister unknown IMAP LIST RETURN flag '%s'",
		rflag->identifier);
}

int imap_list_return_flag_parse(struct client_command_context *cmd,
				const char *flag, const struct imap_arg **args,
				const struct imap_list_return_flag **rflag_r,
				void **context_r)
{
	const struct imap_list_return_flag *const *rflags;
	unsigned int i, count;

	rflags = array_get(&return_flags, &count);
	for (i = 0; i < count; i++) {
		if (strcasecmp(rflags[i]->identifier, flag) == 0)
			break;
	}

	if (i == count)
		return 0;

	*context_r = NULL;
	if (rflags[i]->parse != NULL) {
		const struct imap_arg *list_args = NULL;

		if (imap_arg_get_list(*args, &list_args))
			(*args)++;
		if (rflags[i]->parse(cmd, list_args, context_r) < 0)
			return -1;
	}

	*rflag_r = rflags[i];
	return 1;
}

void imap_list_return_flag_send(
	struct client_command_context *cmd,
	const struct imap_list_return_flag *rflag, void *context,
	const struct imap_list_return_flag_params *params)
{
	rflag->send(cmd, context, params);
}

bool imap_mailbox_flags2str(string_t *str, enum mailbox_info_flags flags)
{
	size_t orig_len = str_len(str);

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

void imap_list_init(void)
{
	i_array_init(&return_flags, 8);
}

void imap_list_deinit(void)
{
	array_free(&return_flags);
}
