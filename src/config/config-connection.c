/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "config-request.h"
#include "config-parser.h"
#include "config-connection.h"

#include <stdlib.h>
#include <unistd.h>

#define MAX_INBUF_SIZE 1024

#define CONFIG_CLIENT_PROTOCOL_MAJOR_VERSION 2
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
		      enum config_key_type type ATTR_UNUSED, void *context)
{
	struct ostream *output = context;
	const char *p;

	o_stream_send_str(output, key);
	o_stream_send_str(output, "=");
	while ((p = strchr(value, '\n')) != NULL) {
		o_stream_send(output, value, p-value);
		o_stream_send(output, SETTING_STREAM_LF_CHAR, 1);
		value = p+1;
	}
	o_stream_send_str(output, value);
	o_stream_send_str(output, "\n");
}

static int config_connection_request(struct config_connection *conn,
				     const char *const *args)
{
	struct config_export_context *ctx;
	struct master_service_settings_output output;
	struct config_filter filter;
	const char *path, *error, *module = "";

	/* [<args>] */
	memset(&filter, 0, sizeof(filter));
	for (; *args != NULL; args++) {
		if (strncmp(*args, "service=", 8) == 0)
			filter.service = *args + 8;
		else if (strncmp(*args, "module=", 7) == 0)
			module = *args + 7;
		else if (strncmp(*args, "lname=", 6) == 0)
			filter.local_name = *args + 6;
		else if (strncmp(*args, "lip=", 4) == 0) {
			if (net_addr2ip(*args + 4, &filter.local_net) == 0) {
				filter.local_bits =
					IPADDR_IS_V4(&filter.local_net) ?
					32 : 128;
			}
		} else if (strncmp(*args, "rip=", 4) == 0) {
			if (net_addr2ip(*args + 4, &filter.remote_net) == 0) {
				filter.remote_bits =
					IPADDR_IS_V4(&filter.remote_net) ?
					32 : 128;
			}
		}
	}

	if (strcmp(module, "master") == 0) {
		/* master reads configuration only when reloading settings */
		path = master_service_get_config_path(master_service);
		if (config_parse_file(path, TRUE, "", &error) <= 0) {
			o_stream_send_str(conn->output,
				t_strconcat("ERROR ", error, "\n", NULL));
			config_connection_destroy(conn);
			return -1;
		}
	}

	o_stream_cork(conn->output);

	ctx = config_export_init(module, CONFIG_DUMP_SCOPE_SET, 0,
				 config_request_output, conn->output);
	config_export_by_filter(ctx, &filter);
	config_export_get_output(ctx, &output);

	if (output.specific_services != NULL) {
		const char *const *s;

		for (s = output.specific_services; *s != NULL; s++) {
			o_stream_send_str(conn->output,
				t_strdup_printf("service=%s\t", *s));
		}
	}
	if (output.service_uses_local)
		o_stream_send_str(conn->output, "service-uses-local\t");
	if (output.service_uses_remote)
		o_stream_send_str(conn->output, "service-uses-remote\t");
	if (output.used_local)
		o_stream_send_str(conn->output, "used-local\t");
	if (output.used_remote)
		o_stream_send_str(conn->output, "used-remote\t");
	o_stream_send_str(conn->output, "\n");

	if (config_export_finish(&ctx) < 0) {
		config_connection_destroy(conn);
		return -1;
	}
	o_stream_send_str(conn->output, "\n");
	o_stream_uncork(conn->output);
	return 0;
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

	master_service_client_connection_destroyed(master_service);
}

void config_connections_destroy_all(void)
{
	while (config_connections != NULL)
		config_connection_destroy(config_connections);
}
