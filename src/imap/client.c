/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "commands.h"

#include <stdlib.h>

/* max. size of one parameter in line */
#define MAX_INBUF_SIZE 8192

/* If we can't send a buffer in a minute, disconnect the client */
#define CLIENT_OUTPUT_TIMEOUT (60*1000)

/* If we don't soon receive expected data from client while processing
   a command, disconnect the client */
#define CLIENT_CMDINPUT_TIMEOUT CLIENT_OUTPUT_TIMEOUT

/* Disconnect client when it sends too many bad commands in a row */
#define CLIENT_MAX_BAD_COMMANDS 20

extern struct mail_storage_callbacks mail_storage_callbacks;

static struct client *my_client; /* we don't need more than one currently */
static struct timeout *to_idle;

static void client_output_timeout(void *context)
{
	struct client *client = context;

	i_stream_close(client->input);
	o_stream_close(client->output);
}

static void client_input_timeout(void *context)
{
	struct client *client = context;

	client_disconnect_with_error(client,
		"Disconnected for inactivity while waiting for command data.");
}

struct client *client_create(int hin, int hout, struct mail_storage *storage)
{
	struct client *client;

	client = i_new(struct client, 1);
	client->input = i_stream_create_file(hin, default_pool,
					     MAX_INBUF_SIZE, FALSE);
	client->output = o_stream_create_file(hout, default_pool, 4096, FALSE);

	/* set timeout for reading expected data (eg. APPEND). This is
	   different from the actual idle time. */
	i_stream_set_blocking(client->input, CLIENT_CMDINPUT_TIMEOUT,
			      client_input_timeout, client);

	/* set timeout for sending data */
	o_stream_set_blocking(client->output, CLIENT_OUTPUT_TIMEOUT,
			      client_output_timeout, client);

	client->io = io_add(hin, IO_READ, _client_input, client);
	client->parser = imap_parser_create(client->input, client->output,
					    MAX_INBUF_SIZE,
					    MAX_IMAP_ARG_ELEMENTS);
        client->last_input = ioloop_time;

	client->mailbox_flags.pool =
		pool_alloconly_create("mailbox_custom_flags", 512);
	client->storage = storage;
	storage->set_callbacks(storage, &mail_storage_callbacks, client);

	i_assert(my_client == NULL);
	my_client = client;
	return client;
}

void client_destroy(struct client *client)
{
	o_stream_flush(client->output);

	if (client->mailbox != NULL)
		client->mailbox->close(client->mailbox);
	mail_storage_destroy(client->storage);

	imap_parser_destroy(client->parser);
	io_remove(client->io);

	if (client->idle_to != NULL)
		timeout_remove(client->idle_to);

	i_stream_unref(client->input);
	o_stream_unref(client->output);

	pool_unref(client->mailbox_flags.pool);
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

void client_disconnect_with_error(struct client *client, const char *msg)
{
	client_send_line(client, t_strconcat("* BYE ", msg, NULL));
	client_disconnect(client);
}

void client_send_line(struct client *client, const char *data)
{
	if (client->output->closed)
		return;

	(void)o_stream_send_str(client->output, data);
	(void)o_stream_send(client->output, "\r\n", 2);
}

void client_send_tagline(struct client *client, const char *data)
{
	const char *tag = client->cmd_tag;

	if (client->output->closed)
		return;

	if (tag == NULL || *tag == '\0')
		tag = "*";

	(void)o_stream_send_str(client->output, tag);
	(void)o_stream_send(client->output, " ", 1);
	(void)o_stream_send_str(client->output, data);
	(void)o_stream_send(client->output, "\r\n", 2);
}

void client_send_command_error(struct client *client, const char *msg)
{
	const char *error, *cmd;
	int fatal;

	if (msg == NULL) {
		msg = imap_parser_get_error(client->parser, &fatal);
		if (fatal) {
			client_disconnect_with_error(client, msg);
			return;
		}
	}

	if (client->cmd_tag == NULL)
		error = t_strconcat("BAD Error in IMAP tag: ", msg, NULL);
	else if (client->cmd_name == NULL)
		error = t_strconcat("BAD Error in IMAP command: ", msg, NULL);
	else {
		cmd = str_ucase(t_strdup_noconst(client->cmd_name));
		error = t_strconcat("BAD Error in IMAP command ",
				    cmd, ": ", msg, NULL);
	}

	client->cmd_error = TRUE;
	client_send_tagline(client, error);

	if (++client->bad_counter >= CLIENT_MAX_BAD_COMMANDS) {
		client_disconnect_with_error(client,
			"Too many invalid IMAP commands.");
	}
}

int client_read_args(struct client *client, unsigned int count,
		     unsigned int flags, struct imap_arg **args)
{
	int ret;

	i_assert(count <= INT_MAX);

	ret = imap_parser_read_args(client->parser, count, flags, args);
	if (ret >= (int)count) {
		/* all parameters read successfully */
		return TRUE;
	} else if (ret == -2) {
		/* need more data */
		return FALSE;
	} else {
		/* error, or missing arguments */
		client_send_command_error(client, ret < 0 ? NULL :
					  "Missing arguments");
		return FALSE;
	}
}

int client_read_string_args(struct client *client, unsigned int count, ...)
{
	struct imap_arg *imap_args;
	va_list va;
	const char *str;
	unsigned int i;

	if (!client_read_args(client, count, 0, &imap_args))
		return FALSE;

	va_start(va, count);
	for (i = 0; i < count; i++) {
		const char **ret = va_arg(va, const char **);

		if (imap_args[i].type == IMAP_ARG_EOL) {
			client_send_command_error(client, "Missing arguments.");
			break;
		}

		str = imap_arg_string(&imap_args[i]);
		if (str == NULL) {
			client_send_command_error(client, "Invalid arguments.");
			break;
		}

		if (ret != NULL)
			*ret = str;
	}
	va_end(va);

	return i == count;
}

void _client_reset_command(struct client *client)
{
	client->cmd_tag = NULL;
	client->cmd_name = NULL;
	client->cmd_func = NULL;
	client->cmd_error = FALSE;
	client->cmd_uid = FALSE;

        imap_parser_reset(client->parser);
}

/* Skip incoming data until newline is found,
   returns TRUE if newline was found. */
static int client_skip_line(struct client *client)
{
	const unsigned char *data;
	size_t i, data_size;

	data = i_stream_get_data(client->input, &data_size);

	for (i = 0; i < data_size; i++) {
		if (data[i] == '\n') {
			client->input_skip_line = FALSE;
			i++;
			break;
		}
	}

	i_stream_skip(client->input, i);
	return !client->input_skip_line;
}

static int client_handle_input(struct client *client)
{
        if (client->cmd_func != NULL) {
		/* command is being executed - continue it */
		client->input_skip_line = TRUE;
		if (client->cmd_func(client) || client->cmd_error) {
			/* command execution was finished */
			_client_reset_command(client);
                        client->bad_counter = 0;
			return TRUE;
		}
		return FALSE;
	}

	if (client->input_skip_line) {
		/* we're just waiting for new line.. */
		if (!client_skip_line(client))
			return FALSE;

		/* got the newline */
		_client_reset_command(client);

		/* pass through to parse next command */
	}

	if (client->cmd_tag == NULL) {
                client->cmd_tag = imap_parser_read_word(client->parser);
		if (client->cmd_tag == NULL)
			return FALSE; /* need more data */
	}

	if (client->cmd_name == NULL) {
                client->cmd_name = imap_parser_read_word(client->parser);
		if (client->cmd_name == NULL)
			return FALSE; /* need more data */
	}

	if (client->cmd_name == '\0') {
		/* command not given - cmd_func is already NULL. */
	} else {
		/* find the command function */
		client->cmd_func = command_find(client->cmd_name);
	}

	if (client->cmd_func == NULL) {
		/* unknown command */
		client_send_command_error(client, "Unknown command.");
		client->input_skip_line = TRUE;
		_client_reset_command(client);
	} else {
		client->input_skip_line = TRUE;
		if (client->cmd_func(client) || client->cmd_error) {
			/* command execution was finished */
			_client_reset_command(client);
                        client->bad_counter = 0;
		} else {
			/* unfinished */
			return FALSE;
		}
	}

	return TRUE;
}

void _client_input(void *context)
{
	struct client *client = context;

	client->last_input = ioloop_time;

	switch (i_stream_read(client->input)) {
	case -1:
		/* disconnected */
		client_destroy(client);
		return;
	case -2:
		/* parameter word is longer than max. input buffer size.
		   this is most likely an error, so skip the new data
		   until newline is found. */
		client->input_skip_line = TRUE;

		client_send_command_error(client, "Too long argument.");
		_client_reset_command(client);
		break;
	}

	o_stream_cork(client->output);
	while (client_handle_input(client))
		;
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
				 "* BYE Disconnected for inactivity.");
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
		client_send_line(my_client, "* BYE Server shutting down.");
		client_destroy(my_client);
	}

	timeout_remove(to_idle);
}
