/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_select_full(Client *client, int readonly)
{
	Mailbox *box;
	MailboxStatus status;
	const char *mailbox;

	/* <mailbox> */
	if (!client_read_string_args(client, 1, &mailbox))
		return FALSE;

	if (client->mailbox != NULL)
		client->mailbox->close(client->mailbox);

	client->mailbox = client->storage->open_mailbox(client->storage,
							mailbox, readonly);
	if (client->mailbox == NULL) {
		client_send_storage_error(client);
		return TRUE;
	}

	box = client->mailbox;
	if (!box->get_status(box, STATUS_MESSAGES | STATUS_RECENT |
			     STATUS_FIRST_UNSEEN_SEQ | STATUS_UIDVALIDITY,
			     &status)) {
		client_send_storage_error(client);
		return TRUE;
	}

	client_send_line(client, "* FLAGS (\\Answered \\Flagged "
			 "\\Deleted \\Seen \\Draft \\Recent)");
	if (box->readonly) {
		client_send_line(client, "* OK [PERMANENTFLAGS ()] "
				 "Read-only mailbox.");
	} else {
		client_send_line(client, "* OK [PERMANENTFLAGS (\\Answered "
				 "\\Flagged \\Deleted \\Seen \\Draft)] "
				 "Flags permitted.");
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

	client_send_tagline(client, box->readonly ?
			    "OK [READ-ONLY] Select completed." :
			    "OK [READ-WRITE] Select completed.");
	return TRUE;
}

int cmd_select(Client *client)
{
	return cmd_select_full(client, FALSE);
}
