/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "hostpid.h"
#include "master-service.h"
#include "ipc-client.h"

#include <unistd.h>

struct ipc_client_cmd {
	ipc_client_callback_t *callback;
	void *context;
};

struct ipc_client {
	char *path;
	ipc_client_callback_t *callback;

	int fd;
	struct io *io;
	struct timeout *to;
	struct istream *input;
	struct ostream *output;
	ARRAY_DEFINE(cmds, struct ipc_client_cmd);
};

static void ipc_client_disconnect(struct ipc_client *client);

static void ipc_client_input_line(struct ipc_client *client, const char *line)
{
	const struct ipc_client_cmd *cmds;
	unsigned int count;
	enum ipc_client_cmd_state state;

	cmds = array_get(&client->cmds, &count);
	if (count == 0) {
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
		ipc_client_disconnect(client);
		state = IPC_CLIENT_CMD_STATE_ERROR;
		break;
	}

	cmds[0].callback(state, line, cmds[0].context);
	if (state != IPC_CLIENT_CMD_STATE_REPLY)
		array_delete(&client->cmds, 0, 1);
}

static void ipc_client_input(struct ipc_client *client)
{
	const char *line;

	if (i_stream_read(client->input) < 0) {
		ipc_client_disconnect(client);
		return;
	}
	while ((line = i_stream_next_line(client->input)) != NULL)
		ipc_client_input_line(client, line);
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
	return 0;
}

static void ipc_client_disconnect(struct ipc_client *client)
{
	const struct ipc_client_cmd *cmd;

	if (client->fd == -1)
		return;

	array_foreach(&client->cmds, cmd) {
		cmd->callback(IPC_CLIENT_CMD_STATE_ERROR,
			      "Disconnected", cmd->context);
	}
	array_clear(&client->cmds);

	io_remove(&client->io);
	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);
	if (close(client->fd) < 0)
		i_error("close(%s) failed: %m", client->path);
}

struct ipc_client *
ipc_client_init(const char *ipc_socket_path)
{
	struct ipc_client *client;

	client = i_new(struct ipc_client, 1);
	client->path = i_strdup(ipc_socket_path);
	client->fd = -1;
	i_array_init(&client->cmds, 8);
	return client;
}

void ipc_client_deinit(struct ipc_client **_client)
{
	struct ipc_client *client = *_client;

	*_client = NULL;

	ipc_client_disconnect(client);
	array_free(&client->cmds);
	i_free(client->path);
	i_free(client);
}

void ipc_client_cmd(struct ipc_client *client, const char *cmd,
		    ipc_client_callback_t *callback, void *context)
{
	struct ipc_client_cmd *ipc_cmd;
	struct const_iovec iov[2];

	if (ipc_client_connect(client) < 0) {
		callback(IPC_CLIENT_CMD_STATE_ERROR,
			 "ipc connect failed", context);
		return;
	}

	iov[0].iov_base = cmd;
	iov[0].iov_len = strlen(cmd);
	iov[1].iov_base = "\n";
	iov[1].iov_len = 1;
	o_stream_sendv(client->output, iov, N_ELEMENTS(iov));

	ipc_cmd = array_append_space(&client->cmds);
	ipc_cmd->callback = callback;
	ipc_cmd->context = context;
}
