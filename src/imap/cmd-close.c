/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "commands.h"

static void client_send_untagged_storage_error(Client *client)
{
	const char *error;
	int syntax;

	error = client->storage->get_last_error(client->storage, &syntax);
	client_send_line(client,
			 t_strconcat(syntax ? "* BAD " : "* NO ", error, NULL));
}

int cmd_close(Client *client)
{
	if (!client_verify_open_mailbox(client))
		return TRUE;

	if (!client->mailbox->expunge(client->mailbox, FALSE))
                client_send_untagged_storage_error(client);

	if (!client->mailbox->close(client->mailbox))
                client_send_untagged_storage_error(client);

	client->mailbox = NULL;

	client_send_tagline(client, "OK Close completed.");
	return TRUE;
}
