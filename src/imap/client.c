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

/* max. number of IMAP argument elements to accept. The maximum memory usage
   for command from user is around MAX_INBUF_SIZE * MAX_IMAP_ARG_ELEMENTS */
#define MAX_IMAP_ARG_ELEMENTS 128

/* If we can't send a buffer in a minute, disconnect the client */
#define CLIENT_OUTPUT_TIMEOUT (60*1000)

/* If we don't soon receive expected data from client while processing
   a command, disconnect the client */
#define CLIENT_CMDINPUT_TIMEOUT CLIENT_OUTPUT_TIMEOUT

/* Disconnect client when it sends too many bad commands */
#define CLIENT_MAX_BAD_COMMANDS 20

/* Disconnect client after idling this many seconds */
#define CLIENT_IDLE_TIMEOUT (60*30)

extern struct mail_storage_callbacks mail_storage_callbacks;

static struct client *my_client; /* we don't need more than one currently */
static struct timeout *to_idle;

static void client_input(struct client *client);

static void client_output_timeout(void *context)
{
	struct client *client = context;

	i_stream_close(client->input);
	o_stream_close(client->output);
}

static void client_input_timeout(void *context)
{
	struct client *client = context;

	client_send_line(my_client, "* BYE Disconnected for inactivity "
			 "while waiting for command data.");
	o_stream_close(client->output);
}

struct client *client_create(int hin, int hout, struct mail_storage *storage)
{
	struct client *client;

	client = i_new(struct client, 1);
	client->input = i_stream_create_file(hin, default_pool,
					     MAX_INBUF_SIZE, FALSE);
	client->output = o_stream_create_file(hout, default_pool, 4096,
					      IO_PRIORITY_DEFAULT, FALSE);

	/* set timeout for reading expected data (eg. APPEND). This is
	   different from the actual idle time. */
	i_stream_set_blocking(client->input, CLIENT_CMDINPUT_TIMEOUT,
			      client_input_timeout, client);

	/* set timeout for sending data */
	o_stream_set_blocking(client->output, CLIENT_OUTPUT_TIMEOUT,
			      client_output_timeout, client);

	client->io = io_add(hin, IO_READ, (IOFunc) client_input, client);
	client->parser = imap_parser_create(client->input, client->output,
					    MAX_INBUF_SIZE,
					    MAX_IMAP_ARG_ELEMENTS);
        client->last_input = ioloop_time;

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
	const char *error;

	if (msg == NULL)
                msg = imap_parser_get_error(client->parser);
	error = t_strconcat("BAD Error in IMAP command: ", msg, NULL);

	client->cmd_error = TRUE;
	client_send_tagline(client, error);

	if (++client->bad_counter >= CLIENT_MAX_BAD_COMMANDS) {
		client_send_line(client,
				 "* BYE Too many invalid IMAP commands.");
		client_disconnect(client);
	}
}

int client_read_args(struct client *client, unsigned int count,
		     unsigned int flags, struct imap_arg **args)
{
	int ret;

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

		str = imap_arg_string(&imap_args[i]);
		if (str == NULL) {
			client_send_command_error(client, "Missing arguments.");
			va_end(va);
			return FALSE;
		}

		if (ret != NULL)
			*ret = str;
	}
	va_end(va);

	return TRUE;
}

static void client_reset_command(struct client *client)
{
	client->cmd_tag = NULL;
	client->cmd_name = NULL;
	client->cmd_func = NULL;
	client->cmd_error = FALSE;
	client->cmd_uid = FALSE;

        imap_parser_reset(client->parser);
}

static void client_command_finished(struct client *client)
{
	client->input_skip_line = TRUE;
        client_reset_command(client);
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
			i_stream_skip(client->input, i+1);
			break;
		}
	}

	return !client->input_skip_line;
}

static int client_handle_input(struct client *client)
{
        if (client->cmd_func != NULL) {
		/* command is being executed - continue it */
		if (client->cmd_func(client) || client->cmd_error) {
			/* command execution was finished */
			client_command_finished(client);
			return TRUE;
		}
		return FALSE;
	}

	if (client->input_skip_line) {
		/* we're just waiting for new line.. */
		if (!client_skip_line(client))
			return FALSE;

		/* got the newline */
		client_reset_command(client);

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
		client->cmd_func = client_command_find(client->cmd_name);
	}

	if (client->cmd_func == NULL) {
		/* unknown command */
		client_send_command_error(client, t_strconcat(
			"Unknown command '", client->cmd_name, "'", NULL));
		client_command_finished(client);
	} else {
		if (client->cmd_func(client) || client->cmd_error) {
			/* command execution was finished */
			client_command_finished(client);
		}
	}

	return TRUE;
}

static void client_input(struct client *client)
{
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
		client_command_finished(client);
		break;
	}

	o_stream_cork(client->output);
	while (client_handle_input(client))
		;
	o_stream_flush(client->output);

	if (client->output->closed)
		client_destroy(client);
}

static void idle_timeout(void *context __attr_unused__,
			 struct timeout *timeout __attr_unused__)
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
