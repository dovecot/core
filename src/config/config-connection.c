/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
#include "ostream-unix.h"
#include "strescape.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "config-request.h"
#include "config-parser.h"
#include "config-connection.h"
#include "config-dump-full.h"

#include <unistd.h>

#define MAX_INBUF_SIZE 1024

#define CONFIG_CLIENT_PROTOCOL_MAJOR_VERSION 3
#define CONFIG_CLIENT_PROTOCOL_MINOR_VERSION 0

struct config_connection {
	struct config_connection *prev, *next;

	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;

	bool version_received:1;
	bool handshaked:1;
};

static struct config_connection *config_connections = NULL;
static int global_config_fd = -1;

static const char *const *
config_connection_next_line(struct config_connection *conn)
{
	const char *line;

	line = i_stream_next_line(conn->input);
	if (line == NULL)
		return NULL;

	return t_strsplit_tabescaped(line);
}

static int config_connection_request(struct config_connection *conn,
				     const char *const *args ATTR_UNUSED)
{
	const char *import_environment;
	enum config_dump_flags flags = CONFIG_DUMP_FLAG_CHECK_SETTINGS;

	while (*args != NULL) {
		if (strcmp(*args, "disable-check-settings") == 0)
			flags &= ENUM_NEGATE(CONFIG_DUMP_FLAG_CHECK_SETTINGS);
		else if (strcmp(*args, "reload") == 0) {
			const char *path, *error;

			path = master_service_get_config_path(master_service);
			if (config_parse_file(path, CONFIG_PARSE_FLAG_EXPAND_VALUES, &error) <= 0) {
				o_stream_nsend_str(conn->output,
						   t_strconcat("-", error, "\n", NULL));
				return 0;
			}
			i_close_fd(&global_config_fd);
		} else {
			o_stream_nsend_str(conn->output, "-Unknown parameters\n");
			return 0;
		}
		args++;
	}

	if (global_config_fd == -1) {
		int fd = config_dump_full(CONFIG_DUMP_FULL_DEST_RUNDIR,
					  flags, &import_environment);
		if (fd == -1) {
			o_stream_nsend_str(conn->output, "-Failed\n");
			return 0;
		}
		global_config_fd = fd;
	}
	if (!o_stream_unix_write_fd(conn->output, global_config_fd))
		i_unreached();

	o_stream_nsend_str(conn->output, "+\n");
	return 0;
}

static void config_connection_input(struct config_connection *conn)
{
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

		if (!version_string_verify(line, "config",
				     CONFIG_CLIENT_PROTOCOL_MAJOR_VERSION)) {
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
		if (strcmp(args[0], "REQ") == 0) {
			if (config_connection_request(conn, args + 1) < 0)
				break;
		}
	}
}

struct config_connection *config_connection_create(int fd)
{
	struct config_connection *conn;

	conn = i_new(struct config_connection, 1);
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, MAX_INBUF_SIZE);
	conn->output = o_stream_create_unix(fd, SIZE_MAX);
	o_stream_set_no_error_handling(conn->output, TRUE);
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

	master_service_client_connection_destroyed(master_service);
}

void config_connections_destroy_all(void)
{
	while (config_connections != NULL)
		config_connection_destroy(config_connections);
	i_close_fd(&global_config_fd);
}
