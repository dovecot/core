/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "commands.h"

#include <stdlib.h>

#define DEFAULT_IDLE_CHECK_INTERVAL 30

static void idle_finish(struct client *client)
{
	if (client->idle_to != NULL) {
		timeout_remove(client->idle_to);
		client->idle_to = NULL;
	}

	if (client->idle_expunge) {
		client_send_line(client,
			t_strdup_printf("* %u EXPUNGE", client->idle_expunge));
	}

	io_remove(client->io);
	client->io = io_add(i_stream_get_fd(client->input),
			    IO_READ, _client_input, client);

	_client_reset_command(client);
	client->bad_counter = 0;

	client->mailbox->auto_sync(client->mailbox,
				   mailbox_check_interval != 0 ?
				   MAILBOX_SYNC_NO_EXPUNGES : MAILBOX_SYNC_NONE,
				   mailbox_check_interval);

	client_sync_full(client);
	client_send_tagline(client, "OK Idle completed.");
}

static void idle_client_input(void *context)
{
	struct client *client = context;
	char *line;

	client->last_input = ioloop_time;

	switch (i_stream_read(client->input)) {
	case -1:
		/* disconnected */
		client_destroy(client);
		return;
	case -2:
		client->input_skip_line = TRUE;
		client_send_line(client, "* BAD Expected DONE.");
		idle_finish(client);
		break;
	}

	while ((line = i_stream_next_line(client->input)) != NULL) {
		if (client->input_skip_line)
			client->input_skip_line = FALSE;
		else {
			if (strcmp(line, "DONE") != 0) {
				client_send_line(client,
						 "* BAD Expected DONE.");
			}
			idle_finish(client);
			break;
		}
	}
}

static void idle_timeout(void *context)
{
	struct client *client = context;
	struct mailbox_status status;

	timeout_remove(client->idle_to);
	client->idle_to = NULL;

	if (!client->mailbox->get_status(client->mailbox, STATUS_MESSAGES,
					 &status)) {
		client_send_untagged_storage_error(client);
		idle_finish(client);
	} else {
                client->idle_expunge = status.messages+1;
		client_send_line(client,
			t_strdup_printf("* %u EXISTS", client->idle_expunge));

		client->mailbox->auto_sync(client->mailbox,
					   MAILBOX_SYNC_NONE, 0);
	}
}

int cmd_idle(struct client *client)
{
	const char *str;
	unsigned int interval;

	if (!client_verify_open_mailbox(client))
		return TRUE;

        client->idle_expunge = 0;
	if ((client_workarounds & WORKAROUND_OUTLOOK_IDLE) != 0) {
		client->idle_to = timeout_add((CLIENT_IDLE_TIMEOUT - 60) * 1000,
					      idle_timeout, client);
	}

	str = getenv("MAILBOX_IDLE_CHECK_INTERVAL");
	interval = str == NULL ? 0 : (unsigned int)strtoul(str, NULL, 10);
	if (interval == 0)
		interval = DEFAULT_IDLE_CHECK_INTERVAL;

	client->mailbox->auto_sync(client->mailbox, MAILBOX_SYNC_ALL, interval);

	client_send_line(client, "+ idling");

	io_remove(client->io);
	client->io = io_add(i_stream_get_fd(client->input),
			    IO_READ, idle_client_input, client);
	return FALSE;
}
