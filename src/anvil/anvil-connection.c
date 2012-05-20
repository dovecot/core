/* Copyright (c) 2009-2012 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
#include "master-service.h"
#include "master-interface.h"
#include "connect-limit.h"
#include "penalty.h"
#include "anvil-connection.h"

#include <stdlib.h>
#include <unistd.h>

#define MAX_INBUF_SIZE 1024

#define ANVIL_CLIENT_PROTOCOL_MAJOR_VERSION 1
#define ANVIL_CLIENT_PROTOCOL_MINOR_VERSION 0

struct anvil_connection {
	struct anvil_connection *prev, *next;

	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;

	unsigned int version_received:1;
	unsigned int handshaked:1;
	unsigned int master:1;
	unsigned int fifo:1;
};

struct anvil_connection *anvil_connections = NULL;

static const char *const *
anvil_connection_next_line(struct anvil_connection *conn)
{
	const char *line;

	line = i_stream_next_line(conn->input);
	return line == NULL ? NULL : t_strsplit_tab(line);
}

static int
anvil_connection_request(struct anvil_connection *conn,
			 const char *const *args, const char **error_r)
{
	const char *cmd = args[0];
	unsigned int value, checksum;
	time_t stamp;
	pid_t pid;

	args++;
	if (strcmp(cmd, "CONNECT") == 0) {
		if (args[0] == NULL || args[1] == NULL) {
			*error_r = "CONNECT: Not enough parameters";
			return -1;
		}
		pid = strtol(args[0], NULL, 10);
		connect_limit_connect(connect_limit, pid, args[1]);
	} else if (strcmp(cmd, "DISCONNECT") == 0) {
		if (args[0] == NULL || args[1] == NULL) {
			*error_r = "DISCONNECT: Not enough parameters";
			return -1;
		}
		pid = strtol(args[0], NULL, 10);
		connect_limit_disconnect(connect_limit, pid, args[1]);
	} else if (strcmp(cmd, "CONNECT-DUMP") == 0) {
		connect_limit_dump(connect_limit, conn->output);
	} else if (strcmp(cmd, "KILL") == 0) {
		if (args[0] == NULL) {
			*error_r = "KILL: Not enough parameters";
			return -1;
		}
		if (!conn->master) {
			*error_r = "KILL sent by a non-master connection";
			return -1;
		}
		pid = strtol(args[0], NULL, 10);
		connect_limit_disconnect_pid(connect_limit, pid);
	} else if (strcmp(cmd, "LOOKUP") == 0) {
		if (args[0] == NULL) {
			*error_r = "LOOKUP: Not enough parameters";
			return -1;
		}
		if (conn->output == NULL) {
			*error_r = "LOOKUP on a FIFO, can't send reply";
			return -1;
		}
		value = connect_limit_lookup(connect_limit, args[0]);
		(void)o_stream_send_str(conn->output,
					t_strdup_printf("%u\n", value));
	} else if (strcmp(cmd, "PENALTY-GET") == 0) {
		if (args[0] == NULL) {
			*error_r = "PENALTY-GET: Not enough parameters";
			return -1;
		}
		value = penalty_get(penalty, args[0], &stamp);
		(void)o_stream_send_str(conn->output,
			t_strdup_printf("%u %s\n", value, dec2str(stamp)));
	} else if (strcmp(cmd, "PENALTY-INC") == 0) {
		if (args[0] == NULL || args[1] == NULL || args[2] == NULL) {
			*error_r = "PENALTY-INC: Not enough parameters";
			return -1;
		}
		if (str_to_uint(args[1], &checksum) < 0 ||
		    str_to_uint(args[2], &value) < 0 ||
		    value > PENALTY_MAX_VALUE ||
		    (value == 0 && checksum != 0)) {
			*error_r = "PENALTY-INC: Invalid parameters";
			return -1;
		}
		penalty_inc(penalty, args[0], checksum, value);
	} else if (strcmp(cmd, "PENALTY-SET-EXPIRE-SECS") == 0) {
		if (args[0] == NULL || str_to_uint(args[0], &value) < 0) {
			*error_r = "PENALTY-SET-EXPIRE-SECS: "
				"Invalid parameters";
			return -1;
		}
		penalty_set_expire_secs(penalty, value);
	} else if (strcmp(cmd, "PENALTY-DUMP") == 0) {
		penalty_dump(penalty, conn->output);
	} else {
		*error_r = t_strconcat("Unknown command: ", cmd, NULL);
		return -1;
	}
	return 0;
}

static void anvil_connection_input(void *context)
{
	struct anvil_connection *conn = context;
	const char *line, *const *args, *error;

	switch (i_stream_read(conn->input)) {
	case -2:
		i_error("BUG: Anvil client connection sent too much data");
		anvil_connection_destroy(conn);
		return;
	case -1:
		anvil_connection_destroy(conn);
		return;
	}

	if (!conn->version_received) {
		if ((line = i_stream_next_line(conn->input)) == NULL)
			return;

		if (!version_string_verify(line, "anvil",
				ANVIL_CLIENT_PROTOCOL_MAJOR_VERSION)) {
			if (anvil_restarted && (conn->master || conn->fifo)) {
				/* old pending data. ignore input until we get
				   the handshake. */
				anvil_connection_input(context);
				return;
			}
			i_error("Anvil client not compatible with this server "
				"(mixed old and new binaries?) %s", line);
			anvil_connection_destroy(conn);
			return;
		}
		conn->version_received = TRUE;
	}

	while ((args = anvil_connection_next_line(conn)) != NULL) {
		if (args[0] != NULL) {
			if (anvil_connection_request(conn, args, &error) < 0) {
				i_error("Anvil client input error: %s", error);
				anvil_connection_destroy(conn);
				break;
			}
		}
	}
}

struct anvil_connection *
anvil_connection_create(int fd, bool master, bool fifo)
{
	struct anvil_connection *conn;

	conn = i_new(struct anvil_connection, 1);
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	if (!fifo)
		conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	conn->io = io_add(fd, IO_READ, anvil_connection_input, conn);
	conn->master = master;
	conn->fifo = fifo;
	DLLIST_PREPEND(&anvil_connections, conn);
	return conn;
}

void anvil_connection_destroy(struct anvil_connection *conn)
{
	bool fifo = conn->fifo;

	DLLIST_REMOVE(&anvil_connections, conn);

	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	if (conn->output != NULL)
		o_stream_destroy(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(anvil conn) failed: %m");
	i_free(conn);

	if (!fifo)
		master_service_client_connection_destroyed(master_service);
}

void anvil_connections_destroy_all(void)
{
	while (anvil_connections != NULL)
		anvil_connection_destroy(anvil_connections);
}
