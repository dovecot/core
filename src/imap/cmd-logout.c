/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "imap-common.h"
#include "ostream.h"
#include "imap-reply.h"
#include "imap-commands.h"

bool cmd_logout(struct client_command_context *cmd)
{
	struct client *client = cmd->client;

	client->logged_out = TRUE;
	client_send_line(client, IMAP_REPLY_LOGOUT_BYE);

	if (client->mailbox != NULL) {
		/* this could be done at client_disconnect() as well,
		   but eg. mbox rewrite takes a while so the waiting is
		   better to happen before "OK" message. */
		imap_client_close_mailbox(client);
	}

	client_send_tagline(cmd, IMAP_REPLY_LOGOUT_COMPLETED);
	client_disconnect(client, "Logged out");
	return TRUE;
}
