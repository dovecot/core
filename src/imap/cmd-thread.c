/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "buffer.h"
#include "commands.h"
#include "imap-search.h"
#include "imap-thread.h"

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

	sargs = imap_search_args_build(pool, client->mailbox, args, &error);
	if (sargs == NULL) {
		/* error in search arguments */
		client_send_tagline(client, t_strconcat("NO ", error, NULL));
	} else if (imap_thread(client, charset, sargs, threading) == 0) {
		pool_unref(pool);
		return cmd_sync(client, MAILBOX_SYNC_FLAG_FAST |
				(client->cmd_uid ?
				 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES),
				"OK Thread completed.");
	} else {
		client_send_storage_error(client,
					  mailbox_get_storage(client->mailbox));
	}

	pool_unref(pool);
	return TRUE;
}
