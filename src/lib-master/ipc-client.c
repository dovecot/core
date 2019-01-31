/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "net.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
#include "hostpid.h"
#include "master-service.h"
#include "ipc-client.h"

#include <unistd.h>

struct ipc_client_cmd {
	struct ipc_client_cmd *prev, *next;

	ipc_client_callback_t *callback;
	void *context;
};

struct ipc_client {
	char *path;
	ipc_client_callback_t *callback;

	int fd;
	struct io *io;
	struct timeout *to_failed;
	struct istream *input;
	struct ostream *output;
	struct ipc_client_cmd *cmds_head, *cmds_tail;
	unsigned int aborted_cmds_count;
};

static void ipc_client_disconnect(struct ipc_client *client);

static void ipc_client_input_line(struct ipc_client *client, const char *line)
{
	struct ipc_client_cmd *cmd = client->cmds_head;
	enum ipc_client_cmd_state state;
	bool disconnect = FALSE;

	if (client->aborted_cmds_count > 0) {
		/* the command was already aborted */
		cmd = NULL;
	} else if (cmd == NULL) {
		i_error("IPC proxy sent unexpected input: %s", line);
		return;
	}

	switch (*line++) {
	case ':':
		state = IPC_CLIENT_CMD_STATE_REPLY;
		break;
	case '+':
		state = IPC_CLIENT_CMD_STATE_OK;
		break;
	case '-':
		state = IPC_CLIENT_CMD_STATE_ERROR;
		break;
	default:
		i_error("IPC proxy sent invalid input: %s", line);
		line = "Invalid input";
		disconnect = TRUE;
		state = IPC_CLIENT_CMD_STATE_ERROR;
		break;
	}

	if (state != IPC_CLIENT_CMD_STATE_REPLY) {
		if (cmd != NULL)
			DLLIST2_REMOVE(&client->cmds_head,
				       &client->cmds_tail, cmd);
		else
			client->aborted_cmds_count--;
	}
	if (cmd != NULL)
		cmd->callback(state, line, cmd->context);
	if (state != IPC_CLIENT_CMD_STATE_REPLY)
		i_free(cmd);
	if (disconnect)
		ipc_client_disconnect(client);
}

static void ipc_client_input(struct ipc_client *client)
{
	const char *line;

	if (i_stream_read(client->input) < 0) {
		ipc_client_disconnect(client);
		return;
	}
	while ((line = i_stream_next_line(client->input)) != NULL) T_BEGIN {
		ipc_client_input_line(client, line);
	} T_END;
}

static int ipc_client_connect(struct ipc_client *client)
{
	if (client->fd != -1)
		return 0;

	client->fd = net_connect_unix(client->path);
	if (client->fd == -1) {
		i_error("connect(%s) failed: %m", client->path);
		return -1;
	}

	client->io = io_add(client->fd, IO_READ, ipc_client_input, client);
	client->input = i_stream_create_fd(client->fd, (size_t)-1, FALSE);
	client->output = o_stream_create_fd(client->fd, (size_t)-1, FALSE);
	o_stream_set_no_error_handling(client->output, TRUE);
	return 0;
}

static void ipc_client_abort_commands(struct ipc_client *client,
				      const char *reason)
{
	struct ipc_client_cmd *cmd, *next;

	cmd = client->cmds_head;
	client->cmds_head = client->cmds_tail = NULL;
	for (; cmd != NULL; cmd = next) {
		cmd->callback(IPC_CLIENT_CMD_STATE_ERROR, reason, cmd->context);
		next = cmd->next;
		i_free(cmd);
	}
}

static void ipc_client_disconnect(struct ipc_client *client)
{
	if (client->to_failed != NULL)
		timeout_remove(&client->to_failed);
	ipc_client_abort_commands(client, "Disconnected");

	if (client->fd == -1)
		return;

	io_remove(&client->io);
	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);
	if (close(client->fd) < 0)
		i_error("close(%s) failed: %m", client->path);
	client->fd = -1;
}

struct ipc_client *
ipc_client_init(const char *ipc_socket_path)
{
	struct ipc_client *client;

	client = i_new(struct ipc_client, 1);
	client->path = i_strdup(ipc_socket_path);
	client->fd = -1;
	return client;
}

void ipc_client_deinit(struct ipc_client **_client)
{
	struct ipc_client *client = *_client;

	*_client = NULL;

	ipc_client_disconnect(client);
	i_free(client->path);
	i_free(client);
}

static void ipc_client_cmd_connect_failed(struct ipc_client *client)
{
	ipc_client_abort_commands(client, "ipc connect failed");
	if (client->to_failed != NULL)
		timeout_remove(&client->to_failed);
}

struct ipc_client_cmd *
ipc_client_cmd(struct ipc_client *client, const char *cmd,
	       ipc_client_callback_t *callback, void *context)
{
	struct ipc_client_cmd *ipc_cmd;
	struct const_iovec iov[2];

	ipc_cmd = i_new(struct ipc_client_cmd, 1);
	ipc_cmd->callback = callback;
	ipc_cmd->context = context;
	DLLIST2_APPEND(&client->cmds_head, &client->cmds_tail, ipc_cmd);

	if (client->to_failed != NULL ||
	    ipc_client_connect(client) < 0) {
		/* Delay calling the failure callback. Fail all commands until
		   the callback is called. */
		if (client->to_failed == NULL) {
			client->to_failed = timeout_add_short(0,
				ipc_client_cmd_connect_failed, client);
		}
	} else {
		iov[0].iov_base = cmd;
		iov[0].iov_len = strlen(cmd);
		iov[1].iov_base = "\n";
		iov[1].iov_len = 1;
		o_stream_nsendv(client->output, iov, N_ELEMENTS(iov));
	}
	return ipc_cmd;
}

void ipc_client_cmd_abort(struct ipc_client *client,
			  struct ipc_client_cmd **_cmd)
{
	struct ipc_client_cmd *cmd = *_cmd;

	*_cmd = NULL;
	cmd->callback = NULL;
	/* Free the command only if it's the oldest. Free also other such
	   commands in case they were aborted earlier. */
	while (client->cmds_head != NULL &&
	       client->cmds_head->callback == NULL) {
		struct ipc_client_cmd *head = client->cmds_head;

		client->aborted_cmds_count++;
		DLLIST2_REMOVE(&client->cmds_head, &client->cmds_tail, head);
		i_free(head);
	}
}
