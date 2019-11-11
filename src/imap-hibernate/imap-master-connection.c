/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "connection.h"
#include "imap-master-connection.h"

#define IMAP_MASTER_CONNECTION_TIMEOUT_MSECS 30000

struct imap_master_connection {
	struct connection conn;
	struct timeout *to;

	imap_master_connection_send_callback_t *send_callback;
	imap_master_connection_read_callback_t *read_callback;
	void *context;
};

static struct connection_list *master_clients;

static void imap_master_connection_timeout(struct imap_master_connection *conn)
{
	i_error("Timeout communicating with %s (version %sreceived)",
		conn->conn.name, conn->conn.version_received ? "" : "not ");
	imap_master_connection_deinit(&conn);
}

int imap_master_connection_init(const char *path,
				imap_master_connection_send_callback_t *send_callback,
				imap_master_connection_read_callback_t *read_callback,
				void *context,
				struct imap_master_connection **conn_r,
				const char **error_r)
{
	struct imap_master_connection *conn;

	conn = i_new(struct imap_master_connection, 1);
	conn->send_callback = send_callback;
	conn->read_callback = read_callback;
	conn->context = context;
	connection_init_client_unix(master_clients, &conn->conn, path);
	if (connection_client_connect(&conn->conn) < 0) {
		int ret = errno == EAGAIN ? 0 : -1;

		*error_r = t_strdup_printf(
			"net_connect_unix(%s) failed: %m", path);
		connection_deinit(&conn->conn);
		i_free(conn);
		return ret;
	}
	conn->to = timeout_add(IMAP_MASTER_CONNECTION_TIMEOUT_MSECS,
			       imap_master_connection_timeout, conn);
	*conn_r = conn;
	return 1;
}

static void
imap_master_read_callback(struct imap_master_connection **_conn,
			  const char *line)
{
	struct imap_master_connection *conn = *_conn;
	imap_master_connection_read_callback_t *read_callback =
		conn->read_callback;

	*_conn = NULL;
	conn->read_callback = NULL;
	read_callback(conn->context, line);
	/* connection is destroyed now */
}

void imap_master_connection_deinit(struct imap_master_connection **_conn)
{
	imap_master_read_callback(_conn, "-");
}

void imap_master_connection_free(struct imap_master_connection **_conn)
{
	struct imap_master_connection *conn = *_conn;

	*_conn = NULL;

	timeout_remove(&conn->to);
	connection_deinit(&conn->conn);
	i_free(conn);
}

static void imap_master_client_destroy(struct connection *_conn)
{
	struct imap_master_connection *conn =
		(struct imap_master_connection *)_conn;

	imap_master_connection_deinit(&conn);
}

static int
imap_master_client_input_line(struct connection *_conn, const char *line)
{
	struct imap_master_connection *conn =
		(struct imap_master_connection *)_conn;

	if (!_conn->version_received) {
		if (connection_input_line_default(_conn, line) < 0)
			return -1;

		conn->send_callback(conn->context, _conn->output);
		return 1;
	} else {
		imap_master_read_callback(&conn, line);
		/* we're finished now with this connection - disconnect it */
		return -1;
	}
}

static struct connection_settings client_set = {
	.service_name_in = "imap-master",
	.service_name_out = "imap-master",
	.major_version = 1,
	.minor_version = 0,

	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = TRUE
};

static const struct connection_vfuncs client_vfuncs = {
	.destroy = imap_master_client_destroy,
	.input_line = imap_master_client_input_line
};

void imap_master_connections_init(void)
{
	master_clients = connection_list_init(&client_set, &client_vfuncs);
}

void imap_master_connections_deinit(void)
{
	connection_list_deinit(&master_clients);
}
