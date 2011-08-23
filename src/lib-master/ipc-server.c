/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "hostpid.h"
#include "master-service.h"
#include "ipc-server.h"

#include <unistd.h>

#define IPC_SERVER_RECONNECT_MSECS (60*1000)
#define IPC_SERVER_PROTOCOL_MAJOR_VERSION 1
#define IPC_SERVER_PROTOCOL_MINOR_VERSION 0
#define IPC_SERVER_HANDSHAKE "VERSION\tipc-server\t1\t0\nHANDSHAKE\t%s\t%s\n"

struct ipc_cmd {
	struct ipc_server *server;
	unsigned int tag;
};

struct ipc_server {
	char *name, *path;
	ipc_command_callback_t *callback;

	int ipc_cmd_refcount;

	int fd;
	struct io *io;
	struct timeout *to;
	struct istream *input;
	struct ostream *output;

	unsigned int version_received:1;
};

static void ipc_server_disconnect(struct ipc_server *server);

static void ipc_server_input_line(struct ipc_server *server, char *line)
{
	struct ipc_cmd *cmd;
	unsigned int tag = 0;
	char *p;

	/* tag cmd */
	p = strchr(line, '\t');
	if (p != NULL) {
		*p++ = '\0';
		if (str_to_uint(line, &tag) < 0)
			p = NULL;
	}
	if (p == NULL || *p == '\0') {
		i_error("IPC proxy sent invalid input: %s", line);
		return;
	}

	cmd = i_new(struct ipc_cmd, 1);
	cmd->server = server;
	cmd->tag = tag;

	server->ipc_cmd_refcount++;
	T_BEGIN {
		server->callback(cmd, p);
	} T_END;
}

static void ipc_server_input(struct ipc_server *server)
{
	char *line;

	if (i_stream_read(server->input) < 0) {
		ipc_server_disconnect(server);
		return;
	}

	if (!server->version_received) {
		if ((line = i_stream_next_line(server->input)) == NULL)
			return;

		if (!version_string_verify(line, "ipc-proxy",
				IPC_SERVER_PROTOCOL_MAJOR_VERSION)) {
			i_error("IPC proxy not compatible with this server "
				"(mixed old and new binaries?)");
			ipc_server_disconnect(server);
			return;
		}
		server->version_received = TRUE;
	}

	while ((line = i_stream_next_line(server->input)) != NULL)
		ipc_server_input_line(server, line);
}

static void ipc_server_connect(struct ipc_server *server)
{
	i_assert(server->fd == -1);

	if (server->to != NULL)
		timeout_remove(&server->to);

	server->fd = net_connect_unix(server->path);
	if (server->fd == -1) {
		i_error("connect(%s) failed: %m", server->path);
		server->to = timeout_add(IPC_SERVER_RECONNECT_MSECS,
					 ipc_server_connect, server);
		return;
	}

	server->io = io_add(server->fd, IO_READ, ipc_server_input, server);
	server->input = i_stream_create_fd(server->fd, (size_t)-1, FALSE);
	server->output = o_stream_create_fd(server->fd, (size_t)-1, FALSE);
	o_stream_send_str(server->output,
		t_strdup_printf(IPC_SERVER_HANDSHAKE, server->name, my_pid));
	o_stream_cork(server->output);
}

static void ipc_server_disconnect(struct ipc_server *server)
{
	if (server->fd == -1)
		return;

	io_remove(&server->io);
	i_stream_destroy(&server->input);
	o_stream_destroy(&server->output);
	if (close(server->fd) < 0)
		i_error("close(%s) failed: %m", server->path);
	server->fd = -1;
}

struct ipc_server *
ipc_server_init(const char *ipc_socket_path, const char *name,
		ipc_command_callback_t *callback)
{
	struct ipc_server *server;

	server = i_new(struct ipc_server, 1);
	server->name = i_strdup(name);
	server->path = i_strdup(ipc_socket_path);
	server->callback = callback;
	server->fd = -1;
	ipc_server_connect(server);
	return server;
}

void ipc_server_deinit(struct ipc_server **_server)
{
	struct ipc_server *server = *_server;

	*_server = NULL;

	i_assert(server->ipc_cmd_refcount == 0);

	ipc_server_disconnect(server);
	i_free(server->name);
	i_free(server->path);
	i_free(server);
}

void ipc_cmd_send(struct ipc_cmd *cmd, const char *data)
{
	o_stream_send_str(cmd->server->output,
			  t_strdup_printf("%u\t:%s\n", cmd->tag, data));
}

static void ipc_cmd_finish(struct ipc_cmd *cmd, const char *line)
{
	o_stream_send_str(cmd->server->output,
			  t_strdup_printf("%u\t%s\n", cmd->tag, line));
	o_stream_uncork(cmd->server->output);

	i_assert(cmd->server->ipc_cmd_refcount > 0);
	cmd->server->ipc_cmd_refcount--;
}

void ipc_cmd_success(struct ipc_cmd **_cmd)
{
	ipc_cmd_success_reply(_cmd, NULL);
}

void ipc_cmd_success_reply(struct ipc_cmd **_cmd, const char *data)
{
	struct ipc_cmd *cmd = *_cmd;

	*_cmd = NULL;
	ipc_cmd_finish(cmd, t_strconcat("+", data, NULL));
}

void ipc_cmd_fail(struct ipc_cmd **_cmd, const char *errormsg)
{
	struct ipc_cmd *cmd = *_cmd;

	i_assert(errormsg != NULL);

	*_cmd = NULL;
	ipc_cmd_finish(cmd, t_strconcat("-", errormsg, NULL));
}
