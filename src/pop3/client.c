/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "mail-storage.h"
#include "commands.h"

#include <stdlib.h>

/* max. size of one parameter in line */
#define MAX_INBUF_SIZE 8192

/* If we can't send a buffer in a minute, disconnect the client */
#define CLIENT_OUTPUT_TIMEOUT (60*1000)

/* Disconnect client when it sends too many bad commands in a row */
#define CLIENT_MAX_BAD_COMMANDS 20

/* Disconnect client after idling this many seconds */
#define CLIENT_IDLE_TIMEOUT (60*30)

extern struct mail_storage_callbacks mail_storage_callbacks;

static struct client *my_client; /* we don't need more than one currently */
static struct timeout *to_idle;

static void client_input(void *context);

static void client_output_timeout(void *context)
{
	struct client *client = context;

	i_stream_close(client->input);
	o_stream_close(client->output);
}

struct client *client_create(int hin, int hout, struct mailbox *mailbox)
{
	struct client *client;
	struct mailbox_status status;

	client = i_new(struct client, 1);
	client->input = i_stream_create_file(hin, default_pool,
					     MAX_INBUF_SIZE, FALSE);
	client->output = o_stream_create_file(hout, default_pool, 4096,
					      IO_PRIORITY_DEFAULT, FALSE);

	/* set timeout for sending data */
	o_stream_set_blocking(client->output, CLIENT_OUTPUT_TIMEOUT,
			      client_output_timeout, client);

	client->io = io_add(hin, IO_READ, client_input, client);
        client->last_input = ioloop_time;

	client->storage = mailbox->storage;
	client->mailbox = mailbox;

	mailbox->storage->set_callbacks(mailbox->storage,
					&mail_storage_callbacks, client);

	i_assert(my_client == NULL);
	my_client = client;

	if (!mailbox->get_status(mailbox, STATUS_MESSAGES, &status)) {
		client_destroy(client);
		return NULL;
	}
	client->messages_count = status.messages;

	return client;
}

void client_destroy(struct client *client)
{
	o_stream_flush(client->output);

	if (client->mailbox != NULL)
		client->mailbox->close(client->mailbox);
	mail_storage_destroy(client->storage);

	if (client->deleted_bitmask != NULL)
		i_free(client->deleted_bitmask);

	io_remove(client->io);

	i_stream_unref(client->input);
	o_stream_unref(client->output);

	i_free(client);

	/* quit the program */
	my_client = NULL;
	io_loop_stop(ioloop);
}

void client_disconnect(struct client *client)
{
	o_stream_flush(client->output);

	i_stream_close(client->input);
	o_stream_close(client->output);
}

void client_send_line(struct client *client, const char *fmt, ...)
{
	va_list va;

	if (client->output->closed)
		return;

	va_start(va, fmt);
	(void)o_stream_send_str(client->output, t_strdup_vprintf(fmt, va));
	(void)o_stream_send(client->output, "\r\n", 2);
	va_end(va);
}

static void client_input(void *context)
{
	struct client *client = context;
	char *line, *args;

	client->last_input = ioloop_time;

	switch (i_stream_read(client->input)) {
	case -1:
		/* disconnected */
		client_destroy(client);
		return;
	case -2:
		/* line too long, kill it */
		client_send_line(client, "-ERR Input line too long.");
		client_destroy(client);
		return;
	}

	o_stream_cork(client->output);
	while (!client->output->closed &&
	       (line = i_stream_next_line(client->input)) != NULL) {
		args = strchr(line, ' ');
		if (args == NULL)
			args = "";
		else
			*args++ = '\0';

		client_command_execute(client, line, args);
	}
	o_stream_flush(client->output);

	if (client->output->closed)
		client_destroy(client);
}

static void idle_timeout(void *context __attr_unused__)
{
	if (my_client == NULL)
		return;

	if (ioloop_time - my_client->last_input >= CLIENT_IDLE_TIMEOUT) {
		client_send_line(my_client,
				 "-ERR Disconnected for inactivity.");
		client_destroy(my_client);
	}
}

void clients_init(void)
{
	my_client = NULL;
	to_idle = timeout_add(10000, idle_timeout, NULL);
}

void clients_deinit(void)
{
	if (my_client != NULL) {
		client_send_line(my_client, "-ERR Server shutting down.");
		client_destroy(my_client);
	}

	timeout_remove(to_idle);
}
