/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "commands.h"
#include "imap-sync.h"

bool cmd_select_full(struct client_command_context *cmd, bool readonly)
{
	struct client *client = cmd->client;
	struct mail_storage *storage;
	struct mailbox *box;
	struct mailbox_status status;
	enum mailbox_open_flags open_flags = 0;
	const struct imap_arg *args, *list_args;
	const char *mailbox, *str;

	/* <mailbox> [(CONDSTORE)] */
	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!IMAP_ARG_TYPE_IS_STRING(args[0].type)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return FALSE;
	}
	mailbox = IMAP_ARG_STR(&args[0]);

	if (args[1].type == IMAP_ARG_LIST) {
		list_args = IMAP_ARG_LIST_ARGS(&args[1]);
		for (; list_args->type != IMAP_ARG_EOL; list_args++) {
			str = imap_arg_string(list_args);
			if (str != NULL && strcasecmp(str, "CONDSTORE") == 0) {
				client_enable(client,
					      MAILBOX_FEATURE_CONDSTORE);
			}
		}
	}

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

	if (readonly)
		open_flags |= MAILBOX_OPEN_READONLY | MAILBOX_OPEN_KEEP_RECENT;

	box = mailbox_open(storage, mailbox, NULL, open_flags);
	if (box == NULL) {
		client_send_storage_error(cmd, storage);
		return TRUE;
	}

	if (client->enabled_features != 0)
		mailbox_enable(box, client->enabled_features);
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ,
			 STATUS_MESSAGES | STATUS_RECENT |
			 STATUS_FIRST_UNSEEN_SEQ | STATUS_UIDVALIDITY |
			 STATUS_UIDNEXT | STATUS_KEYWORDS |
			 STATUS_HIGHESTMODSEQ, &status) < 0) {
		client_send_storage_error(cmd, storage);
		mailbox_close(&box);
		return TRUE;
	}

	/* set client's mailbox only after getting status to make sure
	   we're not sending any expunge/exists replies too early to client */
	client->mailbox = box;
	client->select_counter++;

	client->messages_count = status.messages;
	client->recent_count = status.recent;
	client->uidvalidity = status.uidvalidity;

	client_update_mailbox_flags(client, status.keywords);
	client_send_mailbox_flags(client, TRUE);

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

	if (status.highest_modseq == 0) {
		client_send_line(client,
				 "* OK [NOMODSEQ] No permanent modsequences");
	} else {
		client_send_line(client,
			t_strdup_printf("* OK [HIGHESTMODSEQ %llu]",
				(unsigned long long)status.highest_modseq));
	}

	client_send_tagline(cmd, mailbox_is_readonly(box) ?
			    "OK [READ-ONLY] Select completed." :
			    "OK [READ-WRITE] Select completed.");
	return TRUE;
}

bool cmd_select(struct client_command_context *cmd)
{
	return cmd_select_full(cmd, FALSE);
}
