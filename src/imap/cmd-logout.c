/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

int cmd_logout(struct client *client)
{
	client_send_line(client, "* BYE Logging out");

	if (client->mailbox != NULL) {
		/* this could be done at client_disconnect() as well,
		   but eg. mbox rewrite takes a while so the waiting is
		   better to happen before "OK" message. */
		if (imap_sync_nonselected(client->mailbox,
					  MAILBOX_SYNC_FLAG_FULL) < 0) {
			client_send_storage_error(client,
				mailbox_get_storage(client->mailbox));
			mailbox_close(client->mailbox);
			return TRUE;
		}

		mailbox_close(client->mailbox);
		client->mailbox = NULL;
	}

	client_send_tagline(client, "OK Logout completed.");
	client_disconnect(client);
	return TRUE;
}
