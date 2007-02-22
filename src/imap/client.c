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
        client->last_input = ioloop_time;

	client->command_pool = pool_alloconly_create("client command", 8192);
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

void client_command_cancel(struct client_command_context *cmd)
{
	bool cmd_ret;

	cmd->cancel = TRUE;
	cmd_ret = cmd->func == NULL ? TRUE : cmd->func(cmd);
	if (!cmd_ret) {
		if (cmd->client->output->closed)
			i_panic("command didn't cancel itself: %s", cmd->name);
	} else {
		client_command_free(cmd);
	}
}

void client_destroy(struct client *client, const char *reason)
{
	i_assert(!client->destroyed);
	client->destroyed = TRUE;

	if (!client->disconnected) {
		client->disconnected = TRUE;
		if (reason == NULL)
			reason = "Disconnected";
		i_info("%s", reason);
	}

	i_stream_close(client->input);
	o_stream_close(client->output);

	/* finish off all the queued commands. */
	if (client->output_lock != NULL)
		client_command_cancel(client->output_lock);
	if (client->input_lock != NULL)
		client_command_cancel(client->input_lock);
	while (client->command_queue != NULL)
		client_command_cancel(client->command_queue);

	if (client->mailbox != NULL)
		mailbox_close(&client->mailbox);
	namespace_deinit(client->namespaces);

	if (client->free_parser != NULL)
		imap_parser_destroy(&client->free_parser);
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
	pool_unref(client->command_pool);
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

	if (client->output->closed || cmd->cancel)
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
		msg = imap_parser_get_error(cmd->parser, &fatal);
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

	ret = imap_parser_read_args(cmd->parser, count, flags, args);
	if (ret >= (int)count) {
		/* all parameters read successfully */
		i_assert(cmd->client->input_lock == NULL ||
			 cmd->client->input_lock == cmd);
		cmd->client->input_lock = NULL;
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

static struct client_command_context *
client_command_find_with_flags(struct client_command_context *new_cmd,
			       enum command_flags flags)
{
	struct client_command_context *cmd;

	cmd = new_cmd->client->command_queue;
	for (; cmd != NULL; cmd = cmd->next) {
		if (cmd != new_cmd && (cmd->cmd_flags & flags) != 0)
			return cmd;
	}
	return NULL;
}

static bool client_command_check_ambiguity(struct client_command_context *cmd)
{
	enum command_flags flags;
	bool broken_client = FALSE;

	if ((cmd->cmd_flags & COMMAND_FLAG_USES_SEQS) != 0) {
		/* no existing command must be breaking sequences */
		flags = COMMAND_FLAG_BREAKS_SEQS;
		broken_client = TRUE;
	} else if ((cmd->cmd_flags & COMMAND_FLAG_BREAKS_SEQS) != 0) {
		/* if existing command uses sequences, we'll have to block */
		flags = COMMAND_FLAG_USES_SEQS;
	} else {
		return FALSE;
	}

	if (client_command_find_with_flags(cmd, flags) == NULL)
		return FALSE;

	if (broken_client) {
		client_send_line(cmd->client,
			"* BAD Command pipelining results in ambiguity.");
	}

	return TRUE;
}

static struct client_command_context *
client_command_new(struct client *client)
{
	struct client_command_context *cmd;

	cmd = p_new(client->command_pool, struct client_command_context, 1);
	cmd->client = client;
	cmd->pool = client->command_pool;

	if (client->free_parser != NULL) {
		cmd->parser = client->free_parser;
		client->free_parser = NULL;
	} else {
		cmd->parser = imap_parser_create(client->input, client->output,
						 imap_max_line_length);
	}

	/* add to beginning of the queue */
	if (client->command_queue != NULL) {
		client->command_queue->prev = cmd;
		cmd->next = client->command_queue;
	}
	client->command_queue = cmd;
	client->command_queue_size++;

	return cmd;
}

void client_command_free(struct client_command_context *cmd)
{
	struct client *client = cmd->client;

	/* reset input idle time because command output might have taken a
	   long time and we don't want to disconnect client immediately then */
	client->last_input = ioloop_time;

	if (cmd->cancel) {
		cmd->cancel = FALSE;
		client_send_tagline(cmd, "NO Command cancelled.");
	}

	if (!cmd->param_error)
		client->bad_counter = 0;

	if (client->input_lock == cmd) {
		/* reset the input handler in case it was changed */
		client->input_lock = NULL;
	}
	if (client->output_lock == cmd) {
		/* reset the output handler in case it was changed */
		o_stream_set_flush_callback(client->output,
					    _client_output, client);
		client->output_lock = NULL;
	}

	if (client->free_parser != NULL)
		imap_parser_destroy(&cmd->parser);
	else {
		imap_parser_reset(cmd->parser);
		client->free_parser = cmd->parser;
	}

	client->command_queue_size--;
	if (cmd->prev != NULL)
		cmd->prev->next = cmd->next;
	else
		client->command_queue = cmd->next;
	if (cmd->next != NULL)
		cmd->next->prev = cmd->prev;
	cmd = NULL;

	if (client->command_queue == NULL) {
		/* no commands left in the queue, we can clear the pool */
		p_clear(client->command_pool);
	}
}

static void client_add_missing_io(struct client *client)
{
	if (client->io == NULL && !client->disconnected) {
		client->io = io_add(client->fd_in,
				    IO_READ, _client_input, client);
	}
}

void client_continue_pending_input(struct client *client)
{
	size_t size;

	i_assert(!client->handling_input);

	if (client->disconnected)
		return;

	if (client->input_lock != NULL) {
		/* there's a command that has locked the input */
		if (!client->input_lock->waiting_unambiguity)
			return;

		/* the command is waiting for existing ambiguity causing
		   commands to finish. */
		if (client_command_check_ambiguity(client->input_lock))
			return;
	}

	client_add_missing_io(client);

	/* if there's unread data in buffer, handle it. */
	(void)i_stream_get_data(client->input, &size);
	if (size > 0)
		_client_input(client);
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

static bool client_command_input(struct client_command_context *cmd)
{
	struct client *client = cmd->client;

        if (cmd->func != NULL) {
		/* command is being executed - continue it */
		if (cmd->func(cmd) || cmd->param_error) {
			/* command execution was finished */
			client_command_free(cmd);
			client_add_missing_io(client);
			return TRUE;
		}

		/* unfinished */
		if (cmd->output_pending)
			o_stream_set_flush_pending(client->output, TRUE);
		return FALSE;
	}

	if (cmd->tag == NULL) {
                cmd->tag = imap_parser_read_word(cmd->parser);
		if (cmd->tag == NULL)
			return FALSE; /* need more data */
		cmd->tag = p_strdup(cmd->pool, cmd->tag);
	}

	if (cmd->name == NULL) {
		cmd->name = imap_parser_read_word(cmd->parser);
		if (cmd->name == NULL)
			return FALSE; /* need more data */
		cmd->name = p_strdup(cmd->pool, cmd->name);
	}

	client->input_skip_line = TRUE;

	if (cmd->name == '\0') {
		/* command not given - cmd_func is already NULL. */
	} else {
		/* find the command function */
		struct command *command = command_find(cmd->name);

		if (command != NULL) {
			cmd->func = command->func;
			cmd->cmd_flags = command->flags;
			if (client_command_check_ambiguity(cmd)) {
				/* do nothing until existing commands are
				   finished */
				cmd->waiting_unambiguity = TRUE;
				io_remove(&client->io);
				return FALSE;
			}
		}
	}

	if (cmd->func == NULL) {
		/* unknown command */
		client_send_command_error(cmd, "Unknown command.");
		cmd->param_error = TRUE;
		client_command_free(cmd);
		return TRUE;
	} else {
		i_assert(!client->disconnected);

		return client_command_input(cmd);
	}
}

static bool client_handle_next_command(struct client *client)
{
	size_t size;

	if (client->input_lock != NULL)
		return client_command_input(client->input_lock);

	if (client->input_skip_line) {
		/* first eat the previous command line */
		if (!client_skip_line(client))
			return FALSE;
		client->input_skip_line = FALSE;
	}

	/* don't bother creating a new client command before there's at least
	   some input */
	(void)i_stream_get_data(client->input, &size);
	if (size == 0)
		return FALSE;

	/* beginning a new command */
	if (client->command_queue_size >= CLIENT_COMMAND_QUEUE_MAX_SIZE ||
	    client->output_lock != NULL) {
		/* wait for some of the commands to finish */
		io_remove(&client->io);
		return FALSE;
	}

	client->input_lock = client_command_new(client);
	return client_command_input(client->input_lock);
}

void _client_input(struct client *client)
{
	struct client_command_context *cmd;
	int ret;

	i_assert(client->io != NULL);

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

		cmd = client->input_lock != NULL ? client->input_lock :
			client_command_new(client);
		cmd->param_error = TRUE;
		client_send_command_error(cmd, "Too long argument.");
		client_command_free(cmd);
		return;
	}

	o_stream_cork(client->output);
	client->handling_input = TRUE;
	do {
		t_push();
		ret = client_handle_next_command(client);
		t_pop();
	} while (ret && !client->disconnected);
	client->handling_input = FALSE;
	o_stream_uncork(client->output);

	if (client->output->closed)
		client_destroy(client, NULL);
	else
		client_continue_pending_input(client);
}

static void client_output_cmd(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	bool finished;

	/* continue processing command */
	finished = cmd->func(cmd) || cmd->param_error;

	if (!finished) {
		if (cmd->output_pending)
			o_stream_set_flush_pending(client->output, TRUE);
	} else {
		/* command execution was finished */
		client_command_free(cmd);
	}
}

int _client_output(struct client *client)
{
	struct client_command_context *cmd;
	int ret;

	i_assert(!client->destroyed);

	client->last_output = ioloop_time;

	if ((ret = o_stream_flush(client->output)) < 0) {
		client_destroy(client, NULL);
		return 1;
	}

	o_stream_cork(client->output);
	if (client->output_lock != NULL)
		client_output_cmd(client->output_lock);
	if (client->output_lock == NULL) {
		cmd = client->command_queue;
		for (; cmd != NULL; cmd = cmd->next) {
			client_output_cmd(cmd);
			if (client->output_lock != NULL)
				break;
		}
	}
	o_stream_uncork(client->output);

	if (client->output->closed) {
		client_destroy(client, NULL);
		return 1;
	} else {
		client_continue_pending_input(client);
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

	if (o_stream_get_buffer_used_size(my_client->output) > 0 &&
	    idle_time >= CLIENT_OUTPUT_TIMEOUT) {
		/* client isn't reading our output */
		client_destroy(my_client, "Disconnected for inactivity "
			       "in reading our output");
	} else if (idle_time >= CLIENT_IDLE_TIMEOUT) {
		/* client isn't sending us anything */
		if (my_client->output_lock == NULL) {
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
