/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "network.h"
#include "iobuffer.h"
#include "commands.h"

#include <stdlib.h>

/* max. size of one parameter in line */
#define MAX_INBUF_SIZE 8192

/* If we can't send a buffer in a minute, disconnect the client */
#define CLIENT_OUTPUT_TIMEOUT (60*1000)

/* If we don't soon receive expected data from client while processing
   a command, disconnect the client */
#define CLIENT_CMDINPUT_TIMEOUT CLIENT_OUTPUT_TIMEOUT

/* Disconnect client when it sends too many bad commands */
#define CLIENT_MAX_BAD_COMMANDS 20

/* Disconnect client after idling this many seconds */
#define CLIENT_IDLE_TIMEOUT (60*30)

static Client *my_client; /* we don't need more than one currently */
static Timeout to_idle;

static void client_input(Client *client);

static void client_output_timeout(void *context,
				  Timeout timeout __attr_unused__)
{
	Client *client = context;

	io_buffer_close(client->inbuf);
	io_buffer_close(client->outbuf);
}

static void client_input_timeout(void *context,
				 Timeout timeout __attr_unused__)
{
	Client *client = context;

	client_send_line(my_client, "* BYE Disconnected for inactivity "
			 "while waiting for command data.");
	io_buffer_close(client->outbuf);
}

Client *client_create(int hin, int hout, int socket, MailStorage *storage)
{
	Client *client;

	client = i_new(Client, 1);
	client->socket = socket;
	client->inbuf = io_buffer_create(hin, default_pool, 0,
					 MAX_INBUF_SIZE);
	client->outbuf = io_buffer_create(hout, default_pool, 0, 0);

	/* always use nonblocking I/O */
	net_set_nonblock(hin, TRUE);
	net_set_nonblock(hout, TRUE);

	/* set timeout for sending data */
	io_buffer_set_blocking(client->outbuf, 4096, CLIENT_OUTPUT_TIMEOUT,
			       client_output_timeout, client);

	/* set timeout for reading expected data (eg. APPEND). This is
	   different from the actual idle time. */
	io_buffer_set_blocking(client->inbuf, 0, CLIENT_CMDINPUT_TIMEOUT,
			       client_input_timeout, client);

	client->inbuf->file = !socket;
	client->outbuf->file = !socket;

	client->io = io_add(socket, IO_READ, (IOFunc) client_input, client);
	client->parser = imap_parser_create(client->inbuf, client->outbuf);
        client->last_input = ioloop_time;

	client->storage = storage;

	i_assert(my_client == NULL);
	my_client = client;
	return client;
}

void client_destroy(Client *client)
{
	io_buffer_send_flush(client->outbuf);

	if (client->mailbox != NULL)
		client->mailbox->close(client->mailbox);
	mail_storage_destroy(client->storage);

	imap_parser_destroy(client->parser);
	io_remove(client->io);

	io_buffer_unref(client->inbuf);
	io_buffer_unref(client->outbuf);

	i_free(client);

	/* quit the program */
	my_client = NULL;
	io_loop_stop(ioloop);
}

void client_disconnect(Client *client)
{
	io_buffer_send_flush(client->outbuf);

	io_buffer_close(client->inbuf);
	io_buffer_close(client->outbuf);
}

void client_send_line(Client *client, const char *data)
{
	unsigned char *buf;
	size_t len;

	if (client->outbuf->closed)
		return;

	len = strlen(data);

	buf = io_buffer_get_space(client->outbuf, len+2);
	if (buf != NULL) {
		memcpy(buf, data, len);
		buf[len++] = '\r'; buf[len++] = '\n';

		/* Returns error only if we disconnected -
		   we don't need to do anything about it. */
		(void)io_buffer_send_buffer(client->outbuf, len);
	} else {
		/* not enough space in output buffer, send this directly.
		   will block. */
		io_buffer_send(client->outbuf, data, len);
		io_buffer_send(client->outbuf, "\r\n", 2);
	}
}

void client_send_tagline(Client *client, const char *data)
{
	const char *tag = client->cmd_tag;
	unsigned char *buf;
	size_t taglen, len;

	if (client->outbuf->closed)
		return;

	if (tag == NULL || *tag == '\0')
		tag = "*";

	taglen = strlen(tag);
	len = strlen(data);

	buf = io_buffer_get_space(client->outbuf, taglen+1+len+2);
	if (buf != NULL) {
		memcpy(buf, tag, taglen); buf[taglen] = ' ';
		buf += taglen+1;

		memcpy(buf, data, len); buf += len;
		buf[0] = '\r'; buf[1] = '\n';

		(void)io_buffer_send_buffer(client->outbuf, taglen+1+len+2);
	} else {
		const char *str;

		str = t_strconcat(tag, " ", data, "\r\n", NULL);
		(void)io_buffer_send(client->outbuf, str, strlen(str));
	}
}

void client_send_command_error(Client *client, const char *msg)
{
	const char *error;

	if (msg == NULL)
		error = "BAD Error in IMAP command.";
	else
		error = t_strconcat("BAD Error in IMAP command: ", msg, NULL);

	client->cmd_error = TRUE;
	client_send_tagline(client, error);

	if (++client->bad_counter >= CLIENT_MAX_BAD_COMMANDS) {
		client_send_line(client,
				 "* BYE Too many invalid IMAP commands.");
		client_disconnect(client);
	}
}

int client_read_args(Client *client, unsigned int count, unsigned int flags,
		     ImapArg **args)
{
	int ret;

	ret = imap_parser_read_args(client->parser, count, flags, args);
	if ((unsigned int) ret == count) {
		/* all parameters read successfully */
		return TRUE;
	} else if (ret == -2) {
		/* need more data */
		return FALSE;
	} else {
		/* error, or missing arguments */
		client_send_command_error(client,
					  "Missing or invalid arguments.");
		return FALSE;
	}
}

int client_read_string_args(Client *client, unsigned int count, ...)
{
	ImapArg *imap_args;
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

static void client_reset_command(Client *client)
{
	client->cmd_tag = NULL;
	client->cmd_name = NULL;
	client->cmd_func = NULL;
	client->cmd_error = FALSE;
	client->cmd_uid = FALSE;

        imap_parser_reset(client->parser);
}

static void client_command_finished(Client *client)
{
	client->inbuf_skip_line = TRUE;
        client_reset_command(client);
}

/* Skip incoming data until newline is found,
   returns TRUE if newline was found. */
static int client_skip_line(Client *client)
{
	unsigned char *data;
	size_t i, data_size;

	/* get the beginning of data in input buffer */
	data = io_buffer_get_data(client->inbuf, &data_size);

	for (i = 0; i < data_size; i++) {
		if (data[i] == '\n') {
			client->inbuf_skip_line = FALSE;
			io_buffer_skip(client->inbuf, i+1);
			break;
		}
	}

	return !client->inbuf_skip_line;
}

static int client_handle_input(Client *client)
{
        if (client->cmd_func != NULL) {
		/* command is being executed - continue it */
		if (client->cmd_func(client)) {
			/* command is finished */
			client_command_finished(client);
			return TRUE;
		}
		return FALSE;
	}

	if (client->inbuf_skip_line) {
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

static void client_input(Client *client)
{
	client->last_input = ioloop_time;

	switch (io_buffer_read(client->inbuf)) {
	case -1:
		/* disconnected */
		client_destroy(client);
		return;
	case -2:
		/* parameter word is longer than max. input buffer size.
		   this is most likely an error, so skip the new data
		   until newline is found. */
		client->inbuf_skip_line = TRUE;

		client_send_command_error(client, "Too long argument.");
		client_command_finished(client);
		break;
	}

	io_buffer_cork(client->outbuf);
	while (client_handle_input(client))
		;
	io_buffer_send_flush(client->outbuf);

	if (client->outbuf->closed)
		client_destroy(client);
}

static void idle_timeout(void *context __attr_unused__,
			 Timeout timeout __attr_unused__)
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
