/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "mail-storage.h"
#include "commands.h"
#include "mail-search.h"

#include <stdlib.h>

/* max. length of input command line (spec says 512) */
#define MAX_INBUF_SIZE 2048

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

static int init_mailbox(struct client *client)
{
	struct mail_search_arg search_arg;
        struct mailbox_transaction_context *t;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct mailbox_status status;
	int i, failed;

	if (mailbox_get_status(client->mailbox,
			       STATUS_MESSAGES | STATUS_UIDVALIDITY,
			       &status) < 0) {
		client_send_storage_error(client);
		return FALSE;
	}

	client->messages_count = status.messages;
	client->deleted_size = 0;
	client->uidvalidity = status.uidvalidity;

	if (client->messages_count == 0)
		return TRUE;

	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_ALL;

	client->message_sizes = i_new(uoff_t, client->messages_count);
	for (i = 0; i < 2; i++) {
		t = mailbox_transaction_begin(client->mailbox, FALSE);
		ctx = mailbox_search_init(t, NULL, &search_arg, NULL,
					  MAIL_FETCH_SIZE, NULL);
		if (ctx == NULL) {
			client_send_storage_error(client);
                        mailbox_transaction_rollback(t);
			return FALSE;
		}

		client->total_size = 0;
		client->deleted_size = 0;
		failed = FALSE;
		while ((mail = mailbox_search_next(ctx)) != NULL) {
			uoff_t size = mail->get_size(mail);

			if (size == (uoff_t)-1) {
				failed = TRUE;
				break;
			}
                        client->total_size += size;

			i_assert(mail->seq <= client->messages_count);
			client->message_sizes[mail->seq-1] = size;
		}

		if (mailbox_search_deinit(ctx) < 0) {
			client_send_storage_error(client);
                        mailbox_transaction_rollback(t);
			return FALSE;
		}

		if (!failed) {
			mailbox_transaction_commit(t);
			return TRUE;
		}

		/* well, sync and try again */
		mailbox_transaction_rollback(t);
		if (mailbox_sync(client->mailbox, 0) < 0) {
			client_send_storage_error(client);
                        mailbox_transaction_rollback(t);
			return FALSE;
		}
	}

	client_send_line(client, "-ERR [IN-USE] Couldn't sync mailbox.");
	return FALSE;
}

struct client *client_create(int hin, int hout, struct mail_storage *storage)
{
	struct client *client;

	client = i_new(struct client, 1);
	client->input = i_stream_create_file(hin, default_pool,
					     MAX_INBUF_SIZE, FALSE);
	client->output = o_stream_create_file(hout, default_pool, 4096, FALSE);

	/* set timeout for sending data */
	o_stream_set_blocking(client->output, CLIENT_OUTPUT_TIMEOUT,
			      client_output_timeout, client);

	client->io = io_add(hin, IO_READ, client_input, client);
        client->last_input = ioloop_time;
	client->storage = storage;

	mail_storage_set_callbacks(storage, &mail_storage_callbacks, client);

	client->mailbox = mailbox_open(storage, "INBOX", 0);
	if (client->mailbox == NULL) {
		client_send_line(client, "-ERR No INBOX for user.");
		client_destroy(client);
		return NULL;
	}

	if (!init_mailbox(client)) {
		client_destroy(client);
		return NULL;
	}

	i_assert(my_client == NULL);
	my_client = client;

	if (hook_client_created != NULL)
		hook_client_created(&client);
	return client;
}

void client_destroy(struct client *client)
{
	o_stream_flush(client->output);

	if (client->mailbox != NULL)
		mailbox_close(client->mailbox);
	mail_storage_destroy(client->storage);

	i_free(client->message_sizes);
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

	t_push();
	va_start(va, fmt);
	(void)o_stream_send_str(client->output, t_strdup_vprintf(fmt, va));
	(void)o_stream_send(client->output, "\r\n", 2);
	va_end(va);
	t_pop();
}

void client_send_storage_error(struct client *client)
{
	const char *error;
	int syntax;

	if (mailbox_is_inconsistent(client->mailbox)) {
		client_send_line(client, "-ERR Mailbox is in inconsistent "
				 "state, please relogin.");
		client_disconnect(client);
		return;
	}

	error = mail_storage_get_last_error(client->storage, &syntax);
	client_send_line(client, "-ERR %s", error != NULL ? error :
			 "BUG: Unknown error");
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

		if (client_command_execute(client, line, args))
			client->bad_counter = 0;
		else if (++client->bad_counter > CLIENT_MAX_BAD_COMMANDS) {
			client_send_line(client, "-ERR Too many bad commands.");
			client_disconnect(client);
		}
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
