/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "imap-sync.h"

int _cmd_select_full(struct client_command_context *cmd, int readonly)
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
		if (mailbox_close(box) < 0) {
			client_send_untagged_storage_error(client,
				mailbox_get_storage(box));
		}
	}

	storage = client_find_storage(cmd, &mailbox);
	if (storage == NULL)
		return TRUE;

	box = mailbox_open(storage, mailbox, !readonly ? 0 :
			   (MAILBOX_OPEN_READONLY | MAILBOX_OPEN_KEEP_RECENT));
	if (box == NULL) {
		client_send_storage_error(cmd, storage);
		return TRUE;
	}

	if (imap_sync_nonselected(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		client_send_storage_error(cmd, storage);
		mailbox_close(box);
		return TRUE;
	}

	if (mailbox_get_status(box, STATUS_MESSAGES | STATUS_RECENT |
			       STATUS_FIRST_UNSEEN_SEQ | STATUS_UIDVALIDITY |
			       STATUS_UIDNEXT | STATUS_KEYWORDS,
			       &status) < 0) {
		client_send_storage_error(cmd, storage);
		mailbox_close(box);
		return TRUE;
	}

	client_save_keywords(&client->keywords,
			     status.keywords, status.keywords_count);
	client->messages_count = status.messages;
	client->recent_count = status.recent;

	/* set client's mailbox only after getting status to make sure
	   we're not sending any expunge/exists replies too early to client */
	client->mailbox = box;
	client->select_counter++;

	client_send_mailbox_flags(client, box, status.keywords,
				  status.keywords_count);

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

	client_send_tagline(cmd, mailbox_is_readonly(box) ?
			    "OK [READ-ONLY] Select completed." :
			    "OK [READ-WRITE] Select completed.");
	return TRUE;
}

int cmd_select(struct client_command_context *cmd)
{
	return _cmd_select_full(cmd, FALSE);
}
