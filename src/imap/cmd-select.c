/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "imap-sync.h"

bool _cmd_select_full(struct client_command_context *cmd, bool readonly)
{
	struct client *client = cmd->client;
	struct mail_storage *storage;
	struct mailbox *box;
	struct mailbox_status status;
	const char *mailbox;

	/* <mailbox> */
	if (!client_read_string_args(cmd, 1, &mailbox))
		return FALSE;

	if (client->mailbox != NULL) {
		box = client->mailbox;
		client->mailbox = NULL;

                storage = mailbox_get_storage(box);
		if (mailbox_close(&box) < 0)
			client_send_untagged_storage_error(client, storage);
	}

	storage = client_find_storage(cmd, &mailbox);
	if (storage == NULL)
		return TRUE;

	box = mailbox_open(storage, mailbox, NULL, !readonly ? 0 :
			   (MAILBOX_OPEN_READONLY | MAILBOX_OPEN_KEEP_RECENT));
	if (box == NULL) {
		client_send_storage_error(cmd, storage);
		return TRUE;
	}

	if (imap_sync_nonselected(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		client_send_storage_error(cmd, storage);
		mailbox_close(&box);
		return TRUE;
	}

	if (mailbox_get_status(box, STATUS_MESSAGES | STATUS_RECENT |
			       STATUS_FIRST_UNSEEN_SEQ | STATUS_UIDVALIDITY |
			       STATUS_UIDNEXT | STATUS_KEYWORDS,
			       &status) < 0) {
		client_send_storage_error(cmd, storage);
		mailbox_close(&box);
		return TRUE;
	}

	client_save_keywords(&client->keywords, status.keywords);
	client->messages_count = status.messages;
	client->recent_count = status.recent;
	client->uidvalidity = status.uidvalidity;

	/* set client's mailbox only after getting status to make sure
	   we're not sending any expunge/exists replies too early to client */
	client->mailbox = box;
	client->select_counter++;

	client_send_mailbox_flags(client, box, status.keywords);

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

	client_send_tagline(cmd, mailbox_is_readonly(box) ?
			    "OK [READ-ONLY] Select completed." :
			    "OK [READ-WRITE] Select completed.");
	return TRUE;
}

bool cmd_select(struct client_command_context *cmd)
{
	return _cmd_select_full(cmd, FALSE);
}
