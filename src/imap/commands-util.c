/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands-util.h"
#include "imap-util.h"

int client_verify_mailbox_name(Client *client, const char *mailbox,
			       int should_exist)
{
	MailboxNameStatus mailbox_status;
	const char *p;
	char sep;

	/* make sure it even looks valid */
	sep = client->storage->hierarchy_sep;
	if (*mailbox == '\0' || *mailbox == sep ||
	    strspn(mailbox, "\r\n*%?") != 0) {
		client_send_tagline(client, "NO Invalid mailbox name.");
		return FALSE;
	}

	/* make sure two hierarchy separators aren't next to each others */
	for (p = mailbox+1; *p != '\0'; p++) {
		if (p[0] == sep && p[1] == sep) {
			client_send_tagline(client, "NO Invalid mailbox name.");
			return FALSE;
		}
	}

	/* check what our storage thinks of it */
	if (!client->storage->get_mailbox_name_status(client->storage, mailbox,
						      &mailbox_status)) {
		client_send_storage_error(client);
		return FALSE;
	}

	switch (mailbox_status) {
	case MAILBOX_NAME_VALID:
		if (!should_exist)
			return TRUE;

		client_send_tagline(client, "NO [TRYCREATE] "
				    "Mailbox doesn't exist.");
		break;

	case MAILBOX_NAME_INVALID:
		client_send_tagline(client, "NO Invalid mailbox name.");
		break;

	case MAILBOX_NAME_EXISTS:
		if (should_exist)
			return TRUE;

		client_send_tagline(client, "NO Mailbox exists.");
		break;
	default:
		i_assert(0);
	}

	return FALSE;
}

int client_verify_open_mailbox(Client *client)
{
	if (client->mailbox != NULL)
		return TRUE;
	else {
		client_send_tagline(client, "NO No mailbox selected.");
		return FALSE;
	}
}

static void sync_expunge_func(Mailbox *mailbox __attr_unused__,
			      unsigned int seq,
			      unsigned int uid __attr_unused__, void *user_data)
{
	Client *client = user_data;
	char str[MAX_INT_STRLEN+20];

	i_snprintf(str, sizeof(str), "* %u EXPUNGE", seq);
	client_send_line(client, str);
}

static void sync_flags_func(Mailbox *mailbox __attr_unused__, unsigned int seq,
			    unsigned int uid __attr_unused__, MailFlags flags,
			    const char *custom_flags[], void *user_data)
{
	Client *client = user_data;
	const char *str;

	t_push();
	str = imap_write_flags(flags, custom_flags);
	client_send_line(client,
			 t_strdup_printf("* %u FETCH (FLAGS (%s))", seq, str));
	t_pop();
}

static int client_sync_full(Client *client, int expunge)
{
	unsigned int messages;
	char str[MAX_INT_STRLEN+20];

	if (client->mailbox == NULL)
		return TRUE;

	if (!client->mailbox->sync(client->mailbox, &messages, expunge,
				   sync_expunge_func, sync_flags_func, client))
		return FALSE;

	if (messages != 0) {
		i_snprintf(str, sizeof(str), "* %u EXISTS", messages);
		client_send_line(client, str);
	}

	return TRUE;
}

void client_sync_mailbox(Client *client)
{
	(void)client_sync_full(client, FALSE);
}

int client_sync_and_expunge_mailbox(Client *client)
{
	return client_sync_full(client, TRUE);
}

void client_send_storage_error(Client *client)
{
	if (client->mailbox != NULL &&
	    client->mailbox->is_inconsistency_error(client->mailbox)) {
		/* we can't do forced CLOSE, so have to disconnect */
		client_send_line(client, "* BYE Mailbox is in inconsistent "
				 "state, please relogin.");
		client_disconnect(client);
		return;
	}

	client_send_tagline(client, t_strconcat("NO ",
		client->storage->get_last_error(client->storage), NULL));
}

int client_parse_mail_flags(Client *client, ImapArgList *list, MailFlags *flags,
			    const char *custflags[MAIL_CUSTOM_FLAGS_COUNT])
{
	char *atom;
	int i, custpos;

	memset(custflags, 0, sizeof(const char *) * MAIL_CUSTOM_FLAGS_COUNT);

	*flags = 0; custpos = 0;
	while (list != NULL) {
		if (list->arg.type != IMAP_ARG_ATOM) {
			client_send_command_error(client, "Flags list "
						  "contains non-atoms.");
			return FALSE;
		}

		atom = list->arg.data.str;
		if (*atom == '\\') {
			/* system flag */
			str_ucase(atom);
			if (strcmp(atom, "\\ANSWERED") == 0)
				*flags |= MAIL_ANSWERED;
			else if (strcmp(atom, "\\FLAGGED") == 0)
				*flags |= MAIL_FLAGGED;
			else if (strcmp(atom, "\\DELETED") == 0)
				*flags |= MAIL_DELETED;
			else if (strcmp(atom, "\\SEEN") == 0)
				*flags |= MAIL_SEEN;
			else if (strcmp(atom, "\\DRAFT") == 0)
				*flags |= MAIL_DRAFT;
			else {
				client_send_tagline(client, t_strconcat(
					"BAD Invalid system flag ", atom, NULL));
				return FALSE;
			}
		} else {
			/* custom flag - first make sure it's not a duplicate */
			for (i = 0; i < custpos; i++) {
				if (strcasecmp(custflags[i], atom) == 0)
					break;
			}

			if (i == MAIL_CUSTOM_FLAGS_COUNT) {
				client_send_tagline(client,
					"Maximum number of different custom "
					"flags exceeded");
				return FALSE;
			}

			if (i == custpos) {
				*flags |= 1 << (custpos +
						MAIL_CUSTOM_FLAG_1_BIT);
				custflags[custpos++] = atom;
			}
		}

		list = list->next;
	}
	return TRUE;
}
