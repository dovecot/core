/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "buffer.h"
#include "commands.h"
#include "mail-search.h"
#include "mail-sort.h"

int cmd_thread(struct client *client)
{
	enum mail_thread_type threading;
	struct mail_search_arg *sargs;
	struct imap_arg *args;
	int args_count;
	pool_t pool;
	const char *error, *charset, *str;

	args_count = imap_parser_read_args(client->parser, 0, 0, &args);
	if (args_count == -2)
		return FALSE;

	if (args_count < 3) {
		client_send_command_error(client, args_count < 0 ? NULL :
					  "Missing or invalid arguments.");
		return TRUE;
	}

	if (!client_verify_open_mailbox(client))
		return TRUE;

	if (args->type != IMAP_ARG_ATOM && args->type != IMAP_ARG_STRING) {
		client_send_command_error(client,
					  "Invalid thread algorithm argument.");
		return TRUE;
	}

	str = IMAP_ARG_STR(args);
	if (strcasecmp(str, "REFERENCES") == 0)
		threading = MAIL_THREAD_REFERENCES;
	else if (strcasecmp(str, "ORDEREDSUBJECT") == 0) {
		client_send_command_error(client,
			"ORDEREDSUBJECT threading is currently not supported.");
		return TRUE;
	} else {
		client_send_command_error(client, "Unknown thread algorithm.");
		return TRUE;
	}
	args++;

	/* charset */
	if (args->type != IMAP_ARG_ATOM && args->type != IMAP_ARG_STRING) {
		client_send_command_error(client,
					  "Invalid charset argument.");
		return TRUE;
	}
	charset = IMAP_ARG_STR(args);
	args++;

	pool = pool_alloconly_create("mail_search_args", 2048);

	sargs = mail_search_args_build(pool, args, &error);
	if (sargs == NULL) {
		/* error in search arguments */
		client_send_tagline(client, t_strconcat("NO ", error, NULL));
	} else {
		if (client->mailbox->search(client->mailbox, charset,
					    sargs, NULL, threading,
					    client->output, client->cmd_uid)) {
			/* NOTE: syncing is allowed when returning UIDs */
			if (client->cmd_uid)
				client_sync_full(client);
			else
				client_sync_without_expunges(client);
			client_send_tagline(client, "OK Search completed.");
		} else {
			client_send_storage_error(client);
		}
	}

	pool_unref(pool);
	return TRUE;
}
