/* Copyright (C) 2002-2004 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "commands.h"
#include "namespace.h"

#include <stdlib.h>
#include <unistd.h>

extern struct mail_storage_callbacks mail_storage_callbacks;

static struct client *my_client; /* we don't need more than one currently */
static struct timeout *to_idle;

struct client *client_create(int fd_in, int fd_out,
			     struct namespace *namespaces)
{
	struct client *client;

	/* always use nonblocking I/O */
	net_set_nonblock(fd_in, TRUE);
	net_set_nonblock(fd_out, TRUE);

	client = i_new(struct client, 1);
	client->fd_in = fd_in;
	client->fd_out = fd_out;
	client->input = i_stream_create_file(fd_in, default_pool,
					     imap_max_line_length, FALSE);
	client->output = o_stream_create_file(fd_out, default_pool,
					      (size_t)-1, FALSE);

	o_stream_set_flush_callback(client->output, _client_output, client);

	client->io = io_add(fd_in, IO_READ, _client_input, client);
	client->parser = imap_parser_create(client->input, client->output,
					    imap_max_line_length);
        client->last_input = ioloop_time;

	client->cmd.pool = pool_alloconly_create("command pool", 8192);
	client->cmd.client = client;

	client->keywords.pool = pool_alloconly_create("mailbox_keywords", 512);
	client->namespaces = namespaces;

	while (namespaces != NULL) {
		mail_storage_set_callbacks(namespaces->storage,
					   &mail_storage_callbacks, client);
		namespaces = namespaces->next;
	}

	i_assert(my_client == NULL);
	my_client = client;

	if (hook_client_created != NULL)
		hook_client_created(&client);
	return client;
}

void client_destroy(struct client *client, const char *reason)
{
	int ret;

	i_assert(!client->destroyed);
	client->destroyed = TRUE;

	if (!client->disconnected) {
		client->disconnected = TRUE;
		if (reason == NULL)
			reason = "Disconnected";
		i_info("%s", reason);
	}

	if (client->command_pending) {
		/* try to deinitialize the command */
		i_assert(client->cmd.func != NULL);
		i_stream_close(client->input);
		o_stream_close(client->output);
		client->input_pending = FALSE;

		ret = client->cmd.func(&client->cmd);
		i_assert(ret);
	}

	if (client->mailbox != NULL)
		mailbox_close(&client->mailbox);
	namespace_deinit(client->namespaces);

	imap_parser_destroy(&client->parser);
	if (client->io != NULL)
		io_remove(&client->io);

	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);

	if (close(client->fd_in) < 0)
		i_error("close(client in) failed: %m");
	if (client->fd_in != client->fd_out) {
		if (close(client->fd_out) < 0)
			i_error("close(client out) failed: %m");
	}

	pool_unref(client->keywords.pool);
	pool_unref(client->cmd.pool);
	i_free(client);

	/* quit the program */
	my_client = NULL;
	io_loop_stop(ioloop);
}

void client_disconnect(struct client *client, const char *reason)
{
	i_assert(reason != NULL);

	if (client->disconnected)
		return;

	i_info("Disconnected: %s", reason);
	client->disconnected = TRUE;
	(void)o_stream_flush(client->output);

	i_stream_close(client->input);
	o_stream_close(client->output);
}

void client_disconnect_with_error(struct client *client, const char *msg)
{
	client_send_line(client, t_strconcat("* BYE ", msg, NULL));
	client_disconnect(client, msg);
}

int client_send_line(struct client *client, const char *data)
{
	struct const_iovec iov[2];

	if (client->output->closed)
		return -1;

	iov[0].iov_base = data;
	iov[0].iov_len = strlen(data);
	iov[1].iov_base = "\r\n";
	iov[1].iov_len = 2;

	if (o_stream_sendv(client->output, iov, 2) < 0)
		return -1;

	if (o_stream_get_buffer_used_size(client->output) >=
	    CLIENT_OUTPUT_OPTIMAL_SIZE) {
		/* buffer full, try flushing */
		return o_stream_flush(client->output);
	}
	return 1;
}

void client_send_tagline(struct client_command_context *cmd, const char *data)
{
	struct client *client = cmd->client;
	const char *tag = cmd->tag;

	if (client->output->closed)
		return;

	if (tag == NULL || *tag == '\0')
		tag = "*";

	(void)o_stream_send_str(client->output, tag);
	(void)o_stream_send(client->output, " ", 1);
	(void)o_stream_send_str(client->output, data);
	(void)o_stream_send(client->output, "\r\n", 2);
}

void client_send_command_error(struct client_command_context *cmd,
			       const char *msg)
{
	struct client *client = cmd->client;
	const char *error, *cmd_name;
	bool fatal;

	if (msg == NULL) {
		msg = imap_parser_get_error(client->parser, &fatal);
		if (fatal) {
			client_disconnect_with_error(client, msg);
			return;
		}
	}

	if (cmd->tag == NULL)
		error = t_strconcat("BAD Error in IMAP tag: ", msg, NULL);
	else if (cmd->name == NULL)
		error = t_strconcat("BAD Error in IMAP command: ", msg, NULL);
	else {
		cmd_name = t_str_ucase(cmd->name);
		error = t_strconcat("BAD Error in IMAP command ",
				    cmd_name, ": ", msg, NULL);
	}

	client_send_tagline(cmd, error);

	if (++client->bad_counter >= CLIENT_MAX_BAD_COMMANDS) {
		client_disconnect_with_error(client,
			"Too many invalid IMAP commands.");
	}

	/* client_read_args() failures rely on this being set, so that the
	   command processing is stopped even while command function returns
	   FALSE. */
	cmd->param_error = TRUE;
}

bool client_read_args(struct client_command_context *cmd, unsigned int count,
		      unsigned int flags, struct imap_arg **args)
{
	int ret;

	i_assert(count <= INT_MAX);

	ret = imap_parser_read_args(cmd->client->parser, count, flags, args);
	if (ret >= (int)count) {
		/* all parameters read successfully */
		return TRUE;
	} else if (ret == -2) {
		/* need more data */
		return FALSE;
	} else {
		/* error, or missing arguments */
		client_send_command_error(cmd, ret < 0 ? NULL :
					  "Missing arguments");
		return FALSE;
	}
}

bool client_read_string_args(struct client_command_context *cmd,
			     unsigned int count, ...)
{
	struct imap_arg *imap_args;
	va_list va;
	const char *str;
	unsigned int i;

	if (!client_read_args(cmd, count, 0, &imap_args))
		return FALSE;

	va_start(va, count);
	for (i = 0; i < count; i++) {
		const char **ret = va_arg(va, const char **);

		if (imap_args[i].type == IMAP_ARG_EOL) {
			client_send_command_error(cmd, "Missing arguments.");
			break;
		}

		str = imap_arg_string(&imap_args[i]);
		if (str == NULL) {
			client_send_command_error(cmd, "Invalid arguments.");
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
	pool_t pool;
	size_t size;

	/* reset input idle time because command output might have taken a
	   long time and we don't want to disconnect client immediately then */
	client->last_input = ioloop_time;

	client->command_pending = FALSE;
	if (client->io == NULL && !client->disconnected) {
		client->io = io_add(i_stream_get_fd(client->input),
				    IO_READ, _client_input, client);
	}
	o_stream_set_flush_callback(client->output, _client_output, client);

	pool = client->cmd.pool;
	memset(&client->cmd, 0, sizeof(client->cmd));

	p_clear(pool);
	client->cmd.pool = pool;
	client->cmd.client = client;

	imap_parser_reset(client->parser);

	/* if there's unread data in buffer, remember that there's input
	   pending and we should get around to calling client_input() soon.
	   This is mostly for APPEND/IDLE. */
	(void)i_stream_get_data(client->input, &size);
	if (size > 0 && !client->destroyed)
		client->input_pending = TRUE;
}

/* Skip incoming data until newline is found,
   returns TRUE if newline was found. */
static bool client_skip_line(struct client *client)
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

static bool client_handle_input(struct client_command_context *cmd)
{
	struct client *client = cmd->client;

        if (cmd->func != NULL) {
		/* command is being executed - continue it */
		if (cmd->func(cmd) || cmd->param_error) {
			/* command execution was finished */
                        client->bad_counter = 0;
			_client_reset_command(client);
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

	if (cmd->tag == NULL) {
                cmd->tag = imap_parser_read_word(client->parser);
		if (cmd->tag == NULL)
			return FALSE; /* need more data */
		cmd->tag = p_strdup(cmd->pool, cmd->tag);
	}

	if (cmd->name == NULL) {
		cmd->name = imap_parser_read_word(client->parser);
		if (cmd->name == NULL)
			return FALSE; /* need more data */
		cmd->name = p_strdup(cmd->pool, cmd->name);
	}

	if (cmd->name == '\0') {
		/* command not given - cmd_func is already NULL. */
	} else {
		/* find the command function */
		cmd->func = command_find(cmd->name);
	}

	if (cmd->func == NULL) {
		/* unknown command */
		client_send_command_error(cmd, "Unknown command.");
		client->input_skip_line = TRUE;
		_client_reset_command(client);
	} else {
		client->input_skip_line = TRUE;
		if (cmd->func(cmd) || cmd->param_error) {
			/* command execution was finished. */
                        client->bad_counter = 0;
			_client_reset_command(client);
		} else {
			/* unfinished */
			if (client->command_pending) {
				o_stream_set_flush_pending(client->output,
							   TRUE);
			}
			return FALSE;
		}
	}

	return TRUE;
}

void _client_input(void *context)
{
	struct client *client = context;
	struct client_command_context *cmd = &client->cmd;
	int ret;

	if (client->command_pending) {
		/* already processing one command. wait. */
		io_remove(&client->io);
		return;
	}

	client->input_pending = FALSE;
	client->last_input = ioloop_time;

	switch (i_stream_read(client->input)) {
	case -1:
		/* disconnected */
		client_destroy(client, NULL);
		return;
	case -2:
		/* parameter word is longer than max. input buffer size.
		   this is most likely an error, so skip the new data
		   until newline is found. */
		client->input_skip_line = TRUE;

		client_send_command_error(cmd, "Too long argument.");
		_client_reset_command(client);
		break;
	}

	o_stream_cork(client->output);
	do {
		t_push();
		ret = client_handle_input(cmd);
		t_pop();
	} while (ret);
	o_stream_uncork(client->output);

	if (client->command_pending)
		client->input_pending = TRUE;

	if (client->output->closed)
		client_destroy(client, NULL);
}

int _client_output(void *context)
{
	struct client *client = context;
	struct client_command_context *cmd = &client->cmd;
	int ret;
	bool finished;

	client->last_output = ioloop_time;

	if ((ret = o_stream_flush(client->output)) < 0) {
		client_destroy(client, NULL);
		return 1;
	}

	if (!client->command_pending)
		return 1;

	/* continue processing command */
	o_stream_cork(client->output);
	client->output_pending = TRUE;
	finished = cmd->func(cmd) || cmd->param_error;

	/* a bit kludgy check. normally we would want to get back to this
	   output handler, but IDLE is a special case which has command
	   pending but without necessarily anything to write. */
	if (!finished && client->output_pending)
		o_stream_set_flush_pending(client->output, TRUE);

	o_stream_uncork(client->output);

	if (finished) {
		/* command execution was finished */
		client->bad_counter = 0;
		_client_reset_command(client);

		if (client->input_pending)
			_client_input(client);
	}
	return ret;
}

static void idle_timeout(void *context __attr_unused__)
{
	time_t idle_time;

	if (my_client == NULL)
		return;

	idle_time = ioloop_time -
		I_MAX(my_client->last_input, my_client->last_output);

	if (my_client->command_pending &&
	    o_stream_get_buffer_used_size(my_client->output) > 0 &&
	    idle_time >= CLIENT_OUTPUT_TIMEOUT) {
		/* client isn't reading our output */
		client_destroy(my_client, "Disconnected for inactivity "
			       "in reading our output");
	} else if (idle_time >= CLIENT_IDLE_TIMEOUT) {
		/* client isn't sending us anything */
		if (!my_client->command_pending) {
			client_send_line(my_client,
					 "* BYE Disconnected for inactivity.");
		}
		client_destroy(my_client, "Disconnected for inactivity");
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
		client_destroy(my_client, "Server shutting down");
	}

	timeout_remove(&to_idle);
}
