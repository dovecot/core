/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "temp-string.h"
#include "commands.h"

#define SYSTEM_PERMANENT_FLAGS \
	"\\* \\Answered \\Flagged \\Deleted \\Seen \\Draft"
#define SYSTEM_FLAGS SYSTEM_PERMANENT_FLAGS " \\Recent"

static const char *
get_custom_flags_string(const char *custom_flags[MAIL_CUSTOM_FLAGS_COUNT])
{
	TempString *str;
	int i;

	/* first see if there even is custom flags */
	for (i = 0; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if (custom_flags[i] != NULL)
			break;
	}

	if (i == MAIL_CUSTOM_FLAGS_COUNT)
		return "";

	str = t_string_new(256);
	for (; i < MAIL_CUSTOM_FLAGS_COUNT; i++) {
		if (custom_flags[i] != NULL) {
			t_string_append_c(str, ' ');
			t_string_append(str, custom_flags[i]);
		}
	}
	return str->str;
}

int cmd_select_full(Client *client, int readonly)
{
	Mailbox *box;
	MailboxStatus status;
	const char *mailbox, *custom_flags;

	/* <mailbox> */
	if (!client_read_string_args(client, 1, &mailbox))
		return FALSE;

	if (client->mailbox != NULL)
		client->mailbox->close(client->mailbox);

	client->mailbox = client->storage->open_mailbox(client->storage,
							mailbox, readonly,
							FALSE);
	if (client->mailbox == NULL) {
		client_send_storage_error(client);
		return TRUE;
	}

	box = client->mailbox;
	if (!box->get_status(box, STATUS_MESSAGES | STATUS_RECENT |
			     STATUS_FIRST_UNSEEN_SEQ | STATUS_UIDVALIDITY |
			     STATUS_CUSTOM_FLAGS, &status)) {
		client_send_storage_error(client);
		return TRUE;
	}

	custom_flags = get_custom_flags_string(status.custom_flags);

	client_send_line(client, t_strconcat("* FLAGS ("SYSTEM_FLAGS,
					     custom_flags, ")", NULL));
	if (box->readonly) {
		client_send_line(client, "* OK [PERMANENTFLAGS ()] "
				 "Read-only mailbox.");
	} else {
		client_send_line(client, t_strconcat("* OK [PERMANENTFLAGS ("
						     SYSTEM_PERMANENT_FLAGS,
						     custom_flags, ")] "
						     "Flags permitted.", NULL));
	}

	client_send_line(client,
		t_strdup_printf("* %u EXISTS", status.messages));
	client_send_line(client,
		t_strdup_printf("* %u RECENT", status.recent));

	if (status.first_unseen_seq != 0) {
		client_send_line(client,
			t_strdup_printf("* OK [UNSEEN %u] First unseen.",
					status.first_unseen_seq));
	}

	client_send_line(client,
		t_strdup_printf("* OK [UIDVALIDITY %u] UIDs valid",
				status.uidvalidity));

	if (status.diskspace_full) {
		client_send_line(client, "* OK [ALERT] Disk space is full, "
				 "delete some messages.");
	}

	client_send_tagline(client, box->readonly ?
			    "OK [READ-ONLY] Select completed." :
			    "OK [READ-WRITE] Select completed.");
	return TRUE;
}

int cmd_select(Client *client)
{
	return cmd_select_full(client, FALSE);
}
