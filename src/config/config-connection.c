/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "env-util.h"
#include "config-request.h"
#include "config-connection.h"

#include <stdlib.h>
#include <unistd.h>

#define MAX_INBUF_SIZE 1024

#define CONFIG_CLIENT_PROTOCOL_MAJOR_VERSION 1
#define CONFIG_CLIENT_PROTOCOL_MINOR_VERSION 0

struct config_connection {
	struct config_connection *prev, *next;

	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;

	unsigned int version_received:1;
	unsigned int handshaked:1;
};

struct config_connection *config_connections = NULL;

static const char *const *
config_connection_next_line(struct config_connection *conn)
{
	const char *line;

	line = i_stream_next_line(conn->input);
	if (line == NULL)
		return NULL;

	return t_strsplit(line, "\t");
}

static void
config_request_output(const char *key, const char *value,
		      bool list ATTR_UNUSED, void *context)
{
	struct ostream *output = context;

	o_stream_send_str(output, key);
	o_stream_send_str(output, "=");
	o_stream_send_str(output, value);
	o_stream_send_str(output, "\n");
}

static void config_connection_request(struct config_connection *conn,
				      const char *const *args)
{
	const char *service = "";

	/* [<args>] */
	for (; *args != NULL; args++) {
		if (strncmp(*args, "service=", 8) == 0)
			service = *args + 8;
	}

	o_stream_cork(conn->output);
	config_request_handle(service, 0, config_request_output, conn->output);
	o_stream_send_str(conn->output, "\n");
	o_stream_uncork(conn->output);
}

static void config_connection_input(void *context)
{
	struct config_connection *conn = context;
	const char *const *args, *line;

	switch (i_stream_read(conn->input)) {
	case -2:
		i_error("BUG: Config client connection sent too much data");
                config_connection_destroy(conn);
		return;
	case -1:
                config_connection_destroy(conn);
		return;
	}

	if (!conn->version_received) {
		line = i_stream_next_line(conn->input);
		if (line == NULL)
			return;

		if (strncmp(line, "VERSION\t", 8) != 0 ||
		    atoi(t_strcut(line + 8, '\t')) !=
		    CONFIG_CLIENT_PROTOCOL_MAJOR_VERSION) {
			i_error("Config client not compatible with this server "
				"(mixed old and new binaries?)");
			config_connection_destroy(conn);
			return;
		}
		conn->version_received = TRUE;
	}

	while ((args = config_connection_next_line(conn)) != NULL) {
		if (args[0] == NULL)
			continue;
		if (strcmp(args[0], "REQ") == 0)
			config_connection_request(conn, args + 1);
	}
}

struct config_connection *config_connection_create(int fd)
{
	struct config_connection *conn;

	conn = i_new(struct config_connection, 1);
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	conn->io = io_add(fd, IO_READ, config_connection_input, conn);
	DLLIST_PREPEND(&config_connections, conn);
	return conn;
}

void config_connection_destroy(struct config_connection *conn)
{
	DLLIST_REMOVE(&config_connections, conn);

	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(config conn) failed: %m");
	i_free(conn);
}

void config_connections_destroy_all(void)
{
	while (config_connections != NULL)
		config_connection_destroy(config_connections);
}
