/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"
#include "mail-search.h"

int cmd_search(Client *client)
{
	MailSearchArg *sargs;
	ImapArg *args;
	int args_count;
	Pool pool;
	const char *error, *charset;

	args_count = imap_parser_read_args(client->parser, 0, 0, &args);
	if (args_count < 1) {
		if (args_count == -2)
			return FALSE;

		client_send_command_error(client, args_count < 0 ? NULL :
					  "Missing SEARCH arguments.");
		return TRUE;
	}

	if (!client_verify_open_mailbox(client))
		return TRUE;

	if (args->type == IMAP_ARG_ATOM &&
	    strcasecmp(IMAP_ARG_STR(args), "CHARSET") == 0) {
		/* CHARSET specified */
		args++;
		if (args->type != IMAP_ARG_ATOM &&
		    args->type != IMAP_ARG_STRING) {
			client_send_command_error(client,
						  "Invalid charset argument.");
			return TRUE;
		}

		charset = IMAP_ARG_STR(args);
		args++;
	} else {
		charset = NULL;
	}

	pool = pool_alloconly_create("MailSearchArgs", 2048);

	sargs = mail_search_args_build(pool, args, &error);
	if (sargs == NULL) {
		/* error in search arguments */
		client_send_tagline(client, t_strconcat("NO ", error, NULL));
	} else {
		if (client->mailbox->search(client->mailbox, charset,
					    sargs, NULL,
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
