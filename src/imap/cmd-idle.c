/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "commands.h"
#include "imap-sync.h"

#include <stdlib.h>

#define DEFAULT_IDLE_CHECK_INTERVAL 30

static void idle_finish(struct client *client, int done_ok)
{
	if (client->idle_to != NULL) {
		timeout_remove(client->idle_to);
		client->idle_to = NULL;
	}

	o_stream_cork(client->output);

	if (client->idle_expunge != 0) {
		client_send_line(client,
			t_strdup_printf("* %u EXPUNGE", client->idle_expunge));
	}

	io_remove(client->io);
	client->io = io_add(i_stream_get_fd(client->input),
			    IO_READ, _client_input, client);

	if (client->mailbox != NULL)
		mailbox_notify_changes(client->mailbox, 0, NULL, NULL);

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

	/* outlook workaround - it hasn't sent anything for a long time and
	   we're about to disconnect unless it does something. send a fake
	   EXISTS to see if it responds. it's expunged later. */

	timeout_remove(client->idle_to);
	client->idle_to = NULL;

	client->idle_expunge = client->messages_count+1;
	client_send_line(client,
			 t_strdup_printf("* %u EXISTS", client->idle_expunge));
	mailbox_notify_changes(client->mailbox, 0, NULL, NULL);
}

static void idle_callback(struct mailbox *box, void *context)
{
	struct client *client = context;

	if (imap_sync(client, box, 0) < 0) {
		client_send_untagged_storage_error(client,
			mailbox_get_storage(client->mailbox));
		mailbox_notify_changes(client->mailbox, 0, NULL, NULL);
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
		mailbox_notify_changes(client->mailbox, interval,
				       idle_callback, client);
	}
	client_send_line(client, "+ idling");

	io_remove(client->io);
	client->io = io_add(i_stream_get_fd(client->input),
			    IO_READ, idle_client_input, client);
	return FALSE;
}
