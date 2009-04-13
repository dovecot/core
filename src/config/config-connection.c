/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "str.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "env-util.h"
#include "config-connection.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define MAX_INBUF_SIZE 1024

#define CONFIG_CLIENT_PROTOCOL_MAJOR_VERSION 1
#define CONFIG_CLIENT_PROTOCOL_MINOR_VERSION 0

struct config_connection {
	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;

	unsigned int version_received:1;
	unsigned int handshaked:1;
};

static const char *const *
config_connection_next_line(struct config_connection *conn)
{
	const char *line;

	line = i_stream_next_line(conn->input);
	if (line == NULL)
		return NULL;

	return t_strsplit(line, "\t");
}

static void config_connection_request(struct config_connection *conn,
				      const char *const *args,
				      enum config_dump_flags flags)
{
	const char *const *strings;
	unsigned int i, count;
	string_t *str;

	/* <process> [<args>] */
	str = t_str_new(256);
	strings = array_get(&config_strings, &count);
	o_stream_cork(conn->output);
	for (i = 0; i < count; i += 2) {
		str_truncate(str, 0);
		str_printfa(str, "%s=%s\n", strings[i], strings[i+1]);
		o_stream_send(conn->output, str_data(str), str_len(str));
	}
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

	t_push();
	while ((args = config_connection_next_line(conn)) != NULL) {
		if (args[0] == NULL)
			continue;
		if (strcmp(args[0], "REQ") == 0)
			config_connection_request(conn, args + 1, 0);
	}
	t_pop();
}

struct config_connection *config_connection_create(int fd)
{
	struct config_connection *conn;

	conn = i_new(struct config_connection, 1);
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	conn->io = io_add(fd, IO_READ, config_connection_input, conn);
	return conn;
}

void config_connection_destroy(struct config_connection *conn)
{
	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(config conn) failed: %m");
	i_free(conn);
}

void config_connection_dump_request(int fd, const char *service,
				    enum config_dump_flags flags)
{
	struct config_connection *conn;
	const char *args[2] = { service, NULL };

	conn = config_connection_create(fd);
        config_connection_request(conn, args, flags);
	config_connection_destroy(conn);
}

void config_connection_putenv(void)
{
	const char *const *strings;
	unsigned int i, count;

	strings = array_get(&config_strings, &count);
	for (i = 0; i < count; i += 2) T_BEGIN {
		env_put(t_strconcat(t_str_ucase(strings[i]), "=",
				    strings[i+1], NULL));
	} T_END;
}
