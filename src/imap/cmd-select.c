/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int _cmd_select_full(struct client *client, int readonly)
{
	struct mailbox *box;
	struct mailbox_status status;
	const char *mailbox;

	/* <mailbox> */
	if (!client_read_string_args(client, 1, &mailbox))
		return FALSE;

	if (client->mailbox != NULL) {
		if (!client->mailbox->close(client->mailbox))
                        client_send_closing_mailbox_error(client);
		client->mailbox = NULL;
	}

	box = client->storage->open_mailbox(client->storage, mailbox,
					    readonly, FALSE);
	if (box == NULL) {
		client_send_storage_error(client);
		return TRUE;
	}

	if (!box->get_status(box, STATUS_MESSAGES | STATUS_RECENT |
			     STATUS_FIRST_UNSEEN_SEQ | STATUS_UIDVALIDITY |
			     STATUS_UIDNEXT | STATUS_CUSTOM_FLAGS, &status)) {
		client_send_storage_error(client);
		box->close(box);
		return TRUE;
	}

	client_save_custom_flags(&client->mailbox_flags, status.custom_flags,
				 status.custom_flags_count);

	/* set client's mailbox only after getting status to make sure
	   we're not sending any expunge/exists replies too early to client */
	client->mailbox = box;
	client->select_counter++;

	client_send_mailbox_flags(client, box, status.custom_flags,
				  status.custom_flags_count);

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

	client_send_line(client,
			 t_strdup_printf("* OK [UIDNEXT %u] Predicted next UID",
					 status.uidnext));

	if (status.diskspace_full) {
		client_send_line(client, "* OK [ALERT] "
				 "Disk space is full, delete some messages.");
	}

	client_send_tagline(client, box->readonly ?
			    "OK [READ-ONLY] Select completed." :
			    "OK [READ-WRITE] Select completed.");

	return TRUE;
}

int cmd_select(struct client *client)
{
	return _cmd_select_full(client, FALSE);
}
