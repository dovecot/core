/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "commands-util.h"
#include "imap-util.h"
#include "mail-storage.h"
#include "imap-parser.h"

/* Maximum length for mailbox name, including it's path. This isn't fully
   exact since the user can create folder hierarchy with small names, then
   rename them to larger names. Mail storages should set more strict limits
   to them, mbox/maildir currently allow paths only up to PATH_MAX. */
#define MAILBOX_MAX_NAME_LEN 512

int client_verify_mailbox_name(struct client *client, const char *mailbox,
			       int should_exist, int should_not_exist)
{
	enum mailbox_name_status mailbox_status;
	const char *p;
	char sep;

	/* make sure it even looks valid */
	sep = client->storage->hierarchy_sep;
	if (*mailbox == '\0' || strspn(mailbox, "\r\n*%?") != 0) {
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

	if (strlen(mailbox) > MAILBOX_MAX_NAME_LEN) {
		client_send_tagline(client, "NO Mailbox name too long.");
		return FALSE;
	}

	/* check what our storage thinks of it */
	if (!client->storage->get_mailbox_name_status(client->storage, mailbox,
						      &mailbox_status)) {
		client_send_storage_error(client);
		return FALSE;
	}

	switch (mailbox_status) {
	case MAILBOX_NAME_EXISTS:
		if (should_exist || !should_not_exist)
			return TRUE;

		client_send_tagline(client, "NO Mailbox exists.");
		break;

	case MAILBOX_NAME_VALID:
		if (!should_exist)
			return TRUE;

		client_send_tagline(client, t_strconcat(
			"NO [TRYCREATE] Mailbox doesn't exist: ",
			mailbox, NULL));
		break;

	case MAILBOX_NAME_INVALID:
		client_send_tagline(client, t_strconcat(
			"NO Invalid mailbox name: ", mailbox, NULL));
		break;

	case MAILBOX_NAME_NOINFERIORS:
		client_send_tagline(client,
			"NO Mailbox parent doesn't allow inferior mailboxes.");
		break;

	default:
                i_unreached();
	}

	return FALSE;
}

int client_verify_open_mailbox(struct client *client)
{
	if (client->mailbox != NULL)
		return TRUE;
	else {
		client_send_tagline(client, "BAD No mailbox selected.");
		return FALSE;
	}
}

void client_sync_full(struct client *client)
{
	if (client->mailbox != NULL) {
		if (!client->mailbox->sync(client->mailbox, 0))
                        client_send_untagged_storage_error(client);
	}
}

void client_sync_full_fast(struct client *client)
{
	if (client->mailbox != NULL) {
		if (!client->mailbox->sync(client->mailbox,
					   MAIL_SYNC_FLAG_FAST))
                        client_send_untagged_storage_error(client);
	}
}

void client_sync_without_expunges(struct client *client)
{
	if (client->mailbox != NULL) {
		if (!client->mailbox->sync(client->mailbox,
                                           MAIL_SYNC_FLAG_NO_EXPUNGES |
					   MAIL_SYNC_FLAG_FAST))
			client_send_untagged_storage_error(client);
	}
}

void client_send_storage_error(struct client *client)
{
	const char *error;
	int syntax;

	if (client->mailbox != NULL &&
	    client->mailbox->is_inconsistency_error(client->mailbox)) {
		/* we can't do forced CLOSE, so have to disconnect */
		client_disconnect_with_error(client,
			"Mailbox is in inconsistent state, please relogin.");
		return;
	}

	error = client->storage->get_last_error(client->storage, &syntax);
	client_send_tagline(client, t_strconcat(syntax ? "BAD " : "NO ",
						error, NULL));
}

void client_send_untagged_storage_error(struct client *client)
{
	const char *error;
	int syntax;

	if (client->mailbox != NULL &&
	    client->mailbox->is_inconsistency_error(client->mailbox)) {
		/* we can't do forced CLOSE, so have to disconnect */
		client_disconnect_with_error(client,
			"Mailbox is in inconsistent state, please relogin.");
		return;
	}

	error = client->storage->get_last_error(client->storage, &syntax);
	client_send_line(client,
			 t_strconcat(syntax ? "* BAD " : "* NO ", error, NULL));
}

static int is_valid_custom_flag(struct client *client,
                                const struct mailbox_custom_flags *old_flags,
				const char *flag)
{
	size_t i;

	/* if it already exists, skip validity checks */
	for (i = 0; i < old_flags->custom_flags_count; i++) {
		if (old_flags->custom_flags[i] != NULL &&
		    strcasecmp(old_flags->custom_flags[i], flag) == 0)
			return TRUE;
	}

	if (strlen(flag) > max_custom_flag_length) {
		client_send_tagline(client,
			t_strdup_printf("BAD Invalid flag name '%s': "
					"Maximum length is %u characters",
					flag, max_custom_flag_length));
		return FALSE;
	}

	return TRUE;
}

int client_parse_mail_flags(struct client *client, struct imap_arg *args,
                            const struct mailbox_custom_flags *old_flags,
			    struct mail_full_flags *flags)
{
	/* @UNSAFE */
	char *atom;
	size_t max_flags, flag_pos, i;

	max_flags = MAIL_CUSTOM_FLAGS_COUNT;

	memset(flags, 0, sizeof(*flags));
	flags->custom_flags = t_new(const char *, max_flags);

	flag_pos = 0;
	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_send_command_error(client,
				"Flags list contains non-atoms.");
			return FALSE;
		}

		atom = IMAP_ARG_STR(args);
		if (*atom == '\\') {
			/* system flag */
			str_ucase(atom);
			if (strcmp(atom, "\\ANSWERED") == 0)
				flags->flags |= MAIL_ANSWERED;
			else if (strcmp(atom, "\\FLAGGED") == 0)
				flags->flags |= MAIL_FLAGGED;
			else if (strcmp(atom, "\\DELETED") == 0)
				flags->flags |= MAIL_DELETED;
			else if (strcmp(atom, "\\SEEN") == 0)
				flags->flags |= MAIL_SEEN;
			else if (strcmp(atom, "\\DRAFT") == 0)
				flags->flags |= MAIL_DRAFT;
			else {
				client_send_tagline(client, t_strconcat(
					"BAD Invalid system flag ",
					atom, NULL));
				return FALSE;
			}
		} else {
			/* custom flag - first make sure it's not a duplicate */
			for (i = 0; i < flag_pos; i++) {
				if (strcasecmp(flags->custom_flags[i],
					       atom) == 0)
					break;
			}

			if (i == max_flags) {
				client_send_tagline(client,
					"Maximum number of different custom "
					"flags exceeded");
				return FALSE;
			}

			if (i == flags->custom_flags_count) {
				if (!is_valid_custom_flag(client, old_flags,
							  atom))
					return FALSE;
				flags->flags |= 1 << (flag_pos +
						      MAIL_CUSTOM_FLAG_1_BIT);
				flags->custom_flags[flag_pos++] = atom;
			}
		}

		args++;
	}

	flags->custom_flags_count = flag_pos;
	return TRUE;
}

static const char *get_custom_flags_string(const char *custom_flags[],
					   unsigned int custom_flags_count)
{
	string_t *str;
	unsigned int i;

	/* first see if there even is custom flags */
	for (i = 0; i < custom_flags_count; i++) {
		if (custom_flags[i] != NULL)
			break;
	}

	if (i == custom_flags_count)
		return "";

	str = t_str_new(256);
	for (; i < custom_flags_count; i++) {
		if (custom_flags[i] != NULL) {
			str_append_c(str, ' ');
			str_append(str, custom_flags[i]);
		}
	}
	return str_c(str);
}

#define SYSTEM_FLAGS "\\Answered \\Flagged \\Deleted \\Seen \\Draft"

void client_send_mailbox_flags(struct client *client, struct mailbox *box,
			       const char *custom_flags[],
			       unsigned int custom_flags_count)
{
	const char *str;

	str = get_custom_flags_string(custom_flags, custom_flags_count);
	client_send_line(client,
		t_strconcat("* FLAGS ("SYSTEM_FLAGS, str, ")", NULL));

	if (box->readonly) {
		client_send_line(client, "* OK [PERMANENTFLAGS ()] "
				 "Read-only mailbox.");
	} else {
		client_send_line(client,
			t_strconcat("* OK [PERMANENTFLAGS ("SYSTEM_FLAGS, str,
				    box->allow_custom_flags ? " \\*" : "",
				    ")] Flags permitted.", NULL));
	}
}

void client_save_custom_flags(struct mailbox_custom_flags *dest,
			      const char *custom_flags[],
			      unsigned int custom_flags_count)
{
	unsigned int i;

	p_clear(dest->pool);

	if (custom_flags_count == 0) {
		dest->custom_flags = NULL;
		dest->custom_flags_count = 0;
		return;
	}

	dest->custom_flags =
		p_new(dest->pool, char *, custom_flags_count);
	dest->custom_flags_count = custom_flags_count;

	for (i = 0; i < custom_flags_count; i++)
		dest->custom_flags[i] = p_strdup(dest->pool, custom_flags[i]);
}
