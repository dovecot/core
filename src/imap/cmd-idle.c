/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "commands.h"

#include <stdlib.h>

#define DEFAULT_IDLE_CHECK_INTERVAL 30

#include "imap-fetch.h"
static void idle_finish(struct client *client, int done_ok)
{
	if (client->idle_to != NULL) {
		timeout_remove(client->idle_to);
		client->idle_to = NULL;
	}

	o_stream_cork(client->output);

	if (client->idle_expunge) {
		client_send_line(client,
			t_strdup_printf("* %u EXPUNGE", client->idle_expunge));
	}

	io_remove(client->io);
	client->io = io_add(i_stream_get_fd(client->input),
			    IO_READ, _client_input, client);

	if (client->mailbox != NULL) {
		client->mailbox->auto_sync(client->mailbox,
					   mailbox_check_interval != 0 ?
					   MAILBOX_SYNC_FLAG_NO_EXPUNGES :
					   MAILBOX_SYNC_NONE,
					   mailbox_check_interval);
	}

	client_sync_full(client);
	if (done_ok)
		client_send_tagline(client, "OK Idle completed.");
	else
		client_send_tagline(client, "BAD Expected DONE.");

	o_stream_flush(client->output);

	_client_reset_command(client);
	client->bad_counter = 0;
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
		idle_finish(client, FALSE);
		return;
	}

	while ((line = i_stream_next_line(client->input)) != NULL) {
		if (client->input_skip_line)
			client->input_skip_line = FALSE;
		else {
			idle_finish(client, strcmp(line, "DONE") == 0);
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
		client_send_untagged_storage_error(client,
						   client->mailbox->storage);
		idle_finish(client, TRUE);
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

        client->idle_expunge = 0;
	if ((client_workarounds & WORKAROUND_OUTLOOK_IDLE) != 0 &&
	    client->mailbox != NULL) {
		client->idle_to = timeout_add((CLIENT_IDLE_TIMEOUT - 60) * 1000,
					      idle_timeout, client);
	}

	str = getenv("MAILBOX_IDLE_CHECK_INTERVAL");
	interval = str == NULL ? 0 : (unsigned int)strtoul(str, NULL, 10);
	if (interval == 0)
		interval = DEFAULT_IDLE_CHECK_INTERVAL;

	if (client->mailbox != NULL) {
		client->mailbox->auto_sync(client->mailbox,
					   MAILBOX_SYNC_FULL, interval);
	}

	client_send_line(client, "+ idling");

	io_remove(client->io);
	client->io = io_add(i_stream_get_fd(client->input),
			    IO_READ, idle_client_input, client);
	return FALSE;
}
