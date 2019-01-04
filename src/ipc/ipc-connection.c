/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "llist.h"
#include "strescape.h"
#include "master-service.h"
#include "ipc-group.h"
#include "ipc-connection.h"

#include <unistd.h>

#define IPC_SERVER_PROTOCOL_MAJOR_VERSION 1
#define IPC_SERVER_PROTOCOL_MINOR_VERSION 0

#define IPC_SERVER_HANDSHAKE "VERSION\tipc-proxy\t1\t0\n"

static unsigned int connection_id_counter;

static void ipc_connection_cmd_free(struct ipc_connection_cmd **_cmd,
				    const char *reason)
{
	struct ipc_connection_cmd *cmd = *_cmd;
	struct ipc_connection_cmd **cmds;
	unsigned int i, count;

	*_cmd = NULL;

	cmds = array_get_modifiable(&cmd->conn->cmds, &count);
	for (i = 0; i < count; i++) {
		if (cmds[i] == cmd) {
			array_delete(&cmd->conn->cmds, i, 1);
			break;
		}
	}
	if (cmd->callback != NULL) {
		i_assert(reason != NULL);
		cmd->callback(IPC_CMD_STATUS_ERROR, reason, cmd->context);
	}
	i_free(cmd);
}

static struct ipc_connection_cmd *
ipc_connection_cmd_find(struct ipc_connection *conn, unsigned int tag)
{
	struct ipc_connection_cmd *const *cmdp;

	array_foreach(&conn->cmds, cmdp) {
		if ((*cmdp)->tag == tag)
			return *cmdp;
	}
	return NULL;
}

static int
ipc_connection_input_line(struct ipc_connection *conn, char *line)
{
	struct ipc_connection_cmd *cmd;
	unsigned int tag;
	enum ipc_cmd_status status;
	char *data;

	/* <tag> [:+-]<data> */
	data = strchr(line, '\t');
	if (data == NULL)
		return -1;

	*data++ = '\0';
	if (str_to_uint(line, &tag) < 0)
		return -1;

	switch (data[0]) {
	case ':':
		status = IPC_CMD_STATUS_REPLY;
		break;
	case '+':
		status = IPC_CMD_STATUS_OK;
		break;
	case '-':
		status = IPC_CMD_STATUS_ERROR;
		break;
	default:
		return -1;
	}
	data++;

	cmd = ipc_connection_cmd_find(conn, tag);
	if (cmd == NULL) {
		i_error("IPC server: Input for unexpected command tag %u", tag);
		return 0;
	}
	cmd->callback(status, data, cmd->context);
	if (status != IPC_CMD_STATUS_REPLY) {
		cmd->callback = NULL;
		ipc_connection_cmd_free(&cmd, NULL);
	}
	return 0;
}

static void ipc_connection_input(struct ipc_connection *conn)
{
	const char *const *args;
	char *line;
	int ret;

	if (i_stream_read(conn->input) < 0) {
		ipc_connection_destroy(&conn, FALSE,
			i_stream_get_disconnect_reason(conn->input));
		return;
	}

	if (!conn->version_received) {
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;

		if (!version_string_verify(line, "ipc-server",
				IPC_SERVER_PROTOCOL_MAJOR_VERSION)) {
			ipc_connection_destroy(&conn, TRUE,
				"IPC server not compatible with this server "
				"(mixed old and new binaries?)");
			return;
		}
		conn->version_received = TRUE;
	}
	if (!conn->handshake_received) {
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;

		args = t_strsplit_tabescaped(line);
		if (str_array_length(args) < 3 ||
		    strcmp(args[0], "HANDSHAKE") != 0) {
			ipc_connection_destroy(&conn, TRUE,
				"IPC server sent invalid handshake");
			return;
		}
		if (ipc_group_update_name(conn->group, args[1]) < 0) {
			ipc_connection_destroy(&conn, TRUE, t_strdup_printf(
				"IPC server named itself unexpectedly: %s "
				"(existing ones were %s)",
				args[1], conn->group->name));
			return;
		}
		if (str_to_pid(args[2], &conn->pid) < 0) {
			ipc_connection_destroy(&conn, TRUE, t_strdup_printf(
				"IPC server gave broken PID: %s", args[2]));
			return;
		}
		conn->handshake_received = TRUE;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		T_BEGIN {
			ret = ipc_connection_input_line(conn, line);
		} T_END;
		if (ret < 0) {
			ipc_connection_destroy(&conn, TRUE, t_strdup_printf(
				"Invalid input from IPC server '%s': %s",
				conn->group->name, line));
			break;
		}
	}
}

struct ipc_connection *ipc_connection_create(int listen_fd, int fd)
{
	struct ipc_connection *conn;

	conn = i_new(struct ipc_connection, 1);
	conn->group = ipc_group_lookup_listen_fd(listen_fd);
	if (conn->group == NULL)
		conn->group = ipc_group_alloc(listen_fd);
	conn->id = ++connection_id_counter;
	if (conn->id == 0)
		conn->id = ++connection_id_counter;
	conn->fd = fd;
	conn->io = io_add(fd, IO_READ, ipc_connection_input, conn);
	conn->input = i_stream_create_fd(fd, (size_t)-1);
	conn->output = o_stream_create_fd(fd, (size_t)-1);
	o_stream_set_no_error_handling(conn->output, TRUE);
	i_array_init(&conn->cmds, 8);
	o_stream_nsend_str(conn->output, IPC_SERVER_HANDSHAKE);

	DLLIST_PREPEND(&conn->group->connections, conn);
	return conn;
}

void ipc_connection_destroy(struct ipc_connection **_conn,
			    bool log_error, const char *error)
{
	struct ipc_connection *conn = *_conn;
	struct ipc_connection_cmd *const *cmdp, *cmd;
	const char *group_name = conn->group->name != NULL ?
		conn->group->name :
		t_strdup_printf("#%d", conn->group->listen_fd);

	*_conn = NULL;

	error = t_strdup_printf("IPC: '%s' PID %d server connection: %s",
				group_name, conn->pid, error);
	if (log_error)
		i_error("%s", error);
	DLLIST_REMOVE(&conn->group->connections, conn);

	while (array_count(&conn->cmds) > 0) {
		cmdp = array_first(&conn->cmds);
		cmd = *cmdp;

		ipc_connection_cmd_free(&cmd, error);
	}
	array_free(&conn->cmds);

	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(ipc connection) failed: %m");
	i_free(conn);

	master_service_client_connection_destroyed(master_service);
}

struct ipc_connection *
ipc_connection_lookup_id(struct ipc_group *group, unsigned int id)
{
	struct ipc_connection *conn;

	for (conn = group->connections; conn != NULL; conn = conn->next) {
		if (conn->id == id)
			return conn;
	}
	return NULL;
}

void ipc_connection_cmd(struct ipc_connection *conn, const char *cmd,
			ipc_cmd_callback_t *callback, void *context)
{
	struct ipc_connection_cmd *ipc_cmd;

	ipc_cmd = i_new(struct ipc_connection_cmd, 1);
	ipc_cmd->tag = ++conn->cmd_tag_counter;
	ipc_cmd->conn = conn;
	ipc_cmd->callback = callback;
	ipc_cmd->context = context;
	array_append(&conn->cmds, &ipc_cmd, 1);

	T_BEGIN {
		o_stream_nsend_str(conn->output,
			t_strdup_printf("%u\t%s\n", ipc_cmd->tag, cmd));
	} T_END;
}
