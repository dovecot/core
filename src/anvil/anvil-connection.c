/* Copyright (C) 2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
#include "master-service.h"
#include "master-interface.h"
#include "connect-limit.h"
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
	unsigned char *fifo_inbuf;
	size_t fifo_inbuf_size;

	unsigned int version_received:1;
	unsigned int handshaked:1;
	unsigned int master:1;
};

struct anvil_connection *anvil_connections = NULL;

static const char *
anvil_connection_fifo_read_line(struct anvil_connection *conn)
{
	ssize_t ret;

	ret = read(conn->fd, conn->fifo_inbuf, conn->fifo_inbuf_size);
	if (ret > 0) {
		if (conn->fifo_inbuf[ret-1] != '\n') {
			i_error("BUG: Client packet didn't end with LF");
			return NULL;
		}
		conn->fifo_inbuf[ret-1] = '\0';
		return (const char *)conn->fifo_inbuf;
	}
	if (ret == 0) {
		/* disconnected */
	} else {
		if (errno == EAGAIN)
			return NULL;
		i_error("read() failed: %m");
	}
	anvil_connection_destroy(conn);
	return NULL;
}

static const char *const *
anvil_connection_next_line(struct anvil_connection *conn)
{
	const char *line;

	if (conn->input != NULL)
		line = i_stream_next_line(conn->input);
	else
		line = anvil_connection_fifo_read_line(conn);
	return line == NULL ? NULL : t_strsplit(line, "\t");
}

static int
anvil_connection_request(struct anvil_connection *conn,
			 const char *const *args, const char **error_r)
{
	const char *cmd = args[0];
	unsigned int count;
	pid_t pid;

	args++;
	if (strcmp(cmd, "CONNECT") == 0) {
		if (args[0] == NULL || args[1] == NULL) {
			*error_r = "CONNECT: Not enough parameters";
			return -1;
		}
		pid = strtol(args[0], NULL, 10);
		connect_limit_connect(connect_limit, pid, args[1]);
		return 0;
	} else if (strcmp(cmd, "DISCONNECT") == 0) {
		if (args[0] == NULL || args[1] == NULL) {
			*error_r = "DISCONNECT: Not enough parameters";
			return -1;
		}
		pid = strtol(args[0], NULL, 10);
		connect_limit_disconnect(connect_limit, pid, args[1]);
		return 0;
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
		return 0;
	} else if (strcmp(cmd, "LOOKUP") == 0) {
		if (args[0] == NULL) {
			*error_r = "LOOKUP: Not enough parameters";
			return -1;
		}
		if (conn->output == NULL) {
			*error_r = "LOOKUP on a FIFO, can't send reply";
			return -1;
		}
		count = connect_limit_lookup(connect_limit, args[0]);
		(void)o_stream_send_str(conn->output,
					t_strdup_printf("%u\n", count));
		return 0;
	} else {
		*error_r = t_strconcat("Unknown command: ", cmd, NULL);
		return -1;
	}
}

static void anvil_connection_input(void *context)
{
	struct anvil_connection *conn = context;
	const char *const *args, *error;

	if (conn->input != NULL) {
		switch (i_stream_read(conn->input)) {
		case -2:
			i_error("BUG: Anvil client connection sent too "
				"much data");
			anvil_connection_destroy(conn);
			return;
		case -1:
			anvil_connection_destroy(conn);
			return;
		}
	}

	if (!conn->version_received) {
		if ((args = anvil_connection_next_line(conn)) == NULL)
			return;

		if (str_array_length(args) < 3 ||
		    strcmp(args[0], "VERSION") != 0 ||
		    atoi(args[1]) != ANVIL_CLIENT_PROTOCOL_MAJOR_VERSION) {
			i_error("Anvil client not compatible with this server "
				"(mixed old and new binaries?)");
			anvil_connection_destroy(conn);
			return;
		}
		conn->version_received = TRUE;
	}

	while ((args = anvil_connection_next_line(conn)) != NULL) {
		if (args[0] != NULL) {
			if (anvil_connection_request(conn, args, &error) < 0)
				i_error("Anvil client input error: %s", error);
		}
	}
}

struct anvil_connection *
anvil_connection_create(int fd, bool master, bool fifo)
{
	struct anvil_connection *conn;

	conn = i_new(struct anvil_connection, 1);
	conn->fd = fd;
	if (!fifo) {
		conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
		conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	} else {
		conn->fifo_inbuf_size = MAX_INBUF_SIZE;
		conn->fifo_inbuf = i_malloc(conn->fifo_inbuf_size);
	}
	conn->io = io_add(fd, IO_READ, anvil_connection_input, conn);
	conn->master = master;
	DLLIST_PREPEND(&anvil_connections, conn);
	return conn;
}

void anvil_connection_destroy(struct anvil_connection *conn)
{
	DLLIST_REMOVE(&anvil_connections, conn);

	io_remove(&conn->io);
	if (conn->input != NULL)
		i_stream_destroy(&conn->input);
	if (conn->output != NULL)
		o_stream_destroy(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(anvil conn) failed: %m");
	i_free(conn->fifo_inbuf);
	i_free(conn);

	master_service_client_connection_destroyed(master_service);
}

void anvil_connections_destroy_all(void)
{
	while (anvil_connections != NULL)
		anvil_connection_destroy(anvil_connections);
}
