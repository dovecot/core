/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "ostream-unix.h"
#include "str.h"
#include "strescape.h"
#include "fdpass.h"
#include "eacces-error.h"
#include "connection.h"

#include "imap-urlauth-common.h"
#include "imap-urlauth-settings.h"
#include "imap-urlauth-client.h"
#include "imap-urlauth-worker-client.h"

/* max. length of input lines (URLs) */
#define MAX_INBUF_SIZE 2048

enum imap_urlauth_worker_state {
	IMAP_URLAUTH_WORKER_STATE_INACTIVE = 0,
	IMAP_URLAUTH_WORKER_STATE_CONNECTED,
	IMAP_URLAUTH_WORKER_STATE_ACTIVE,
};

struct imap_urlauth_worker_client {
	struct connection conn;
	struct client *client;
	struct event *event;

	char *path;

	enum imap_urlauth_worker_state worker_state;
};

static struct connection_list *imap_urlauth_worker_connections = NULL;

static void
imap_urlauth_worker_client_connected(struct connection *_conn, bool success);
static void imap_urlauth_worker_connection_destroy(struct connection *_conn);
static int
imap_urlauth_worker_connection_input_args(struct connection *conn,
					  const char *const *args);

static const struct connection_vfuncs client_worker_connection_vfuncs = {
	.destroy = imap_urlauth_worker_connection_destroy,
	.input_args = imap_urlauth_worker_connection_input_args,
	.client_connected = imap_urlauth_worker_client_connected,
};

static const struct connection_settings client_worker_connection_set = {
	.service_name_in = IMAP_URLAUTH_WORKER_SOCKET,
	.service_name_out = IMAP_URLAUTH_WORKER_SOCKET,
	.major_version = IMAP_URLAUTH_WORKER_PROTOCOL_MAJOR_VERSION,
	.minor_version = IMAP_URLAUTH_WORKER_PROTOCOL_MINOR_VERSION,
	.unix_client_connect_msecs = 1000,
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.client = TRUE,
};

struct imap_urlauth_worker_client *
imap_urlauth_worker_client_init(struct client *client)
{
	struct imap_urlauth_worker_client *wclient;

	if (imap_urlauth_worker_connections == NULL) {
		imap_urlauth_worker_connections =
			connection_list_init(&client_worker_connection_set,
					     &client_worker_connection_vfuncs);
	}


	wclient = i_new(struct imap_urlauth_worker_client, 1);
	wclient->client = client;

	wclient->path = i_strconcat(client->set->base_dir,
				    "/"IMAP_URLAUTH_WORKER_SOCKET, NULL);

	wclient->event = event_create(client->event);
	event_set_append_log_prefix(wclient->event, "worker: ");

	wclient->conn.event_parent = wclient->event;
	connection_init_client_unix(imap_urlauth_worker_connections,
				    &wclient->conn, wclient->path);

	return wclient;
}

void imap_urlauth_worker_client_deinit(
	struct imap_urlauth_worker_client **_wclient)
{
	struct imap_urlauth_worker_client *wclient = *_wclient;

	if (wclient == NULL)
		return;
	*_wclient = NULL;

	imap_urlauth_worker_client_disconnect(wclient);
	connection_deinit(&wclient->conn);
	event_unref(&wclient->event);
	i_free(wclient->path);
	i_free(wclient);

	if (imap_urlauth_worker_connections->connections == NULL)
		connection_list_deinit(&imap_urlauth_worker_connections);
}

static void
imap_urlauth_worker_client_connected(struct connection *_conn, bool success)
{
	struct imap_urlauth_worker_client *wclient =
		container_of(_conn, struct imap_urlauth_worker_client, conn);
	struct client *client = wclient->client;
	ssize_t ret;
	unsigned char data;

	/* Cannot get here unless UNIX socket connect() was successful */
	i_assert(success);

	/* transfer one or two fds */
	ret = (o_stream_unix_write_fd(wclient->conn.output,
				      client->conn.fd_in) ? 1 : 0);
	if (ret > 0) {
		data = (client->conn.fd_in == client->conn.fd_out ? '0' : '1');
		ret = o_stream_send(wclient->conn.output, &data, sizeof(data));
	}
	if (client->conn.fd_in != client->conn.fd_out) {
		if (ret > 0) {
			ret = (o_stream_unix_write_fd(wclient->conn.output,
						      client->conn.fd_out) ?
			       1 : 0);
		}
		if (ret > 0) {
			data = '0';
			ret = o_stream_send(wclient->conn.output,
					    &data, sizeof(data));
		}
	}
	if (ret <= 0) {
		if (ret < 0) {
			e_error(wclient->event,
				"write(%s) failed: %s", wclient->path,
				o_stream_get_error(wclient->conn.output));
		} else {
			e_error(wclient->event,
				"write(%s) failed: failed to send byte",
				wclient->path);
		}
		imap_urlauth_worker_client_disconnect(wclient);
		return;
	}
}

int imap_urlauth_worker_client_connect(
	struct imap_urlauth_worker_client *wclient)
{
	if (!wclient->conn.disconnected)
               return 1;

	e_debug(wclient->event, "Connecting to worker socket %s", wclient->path);

	if (connection_client_connect(&wclient->conn) < 0) {
		if (errno == EACCES) {
			e_error(wclient->event, "imap-urlauth-client: %s",
				eacces_error_get("net_connect_unix",
						 wclient->path));
		} else {
			e_error(wclient->event, "imap-urlauth-client: "
				"net_connect_unix(%s) failed: %m",
				wclient->path);
		}
		return -1;
	}

	return 0;
}

void imap_urlauth_worker_client_disconnect(
	struct imap_urlauth_worker_client *wclient)
{
	wclient->worker_state = IMAP_URLAUTH_WORKER_STATE_INACTIVE;

        connection_disconnect(&wclient->conn);
}

static void
imap_urlauth_worker_client_error(struct imap_urlauth_worker_client *wclient,
				 const char *error)
{
	client_disconnect(wclient->client, error);
	imap_urlauth_worker_client_disconnect(wclient);
}

static void imap_urlauth_worker_connection_destroy(struct connection *_conn)
{
	struct imap_urlauth_worker_client *wclient =
		container_of(_conn, struct imap_urlauth_worker_client, conn);

	switch (_conn->disconnect_reason) {
	case CONNECTION_DISCONNECT_HANDSHAKE_FAILED:
		imap_urlauth_worker_client_error(wclient,
			"Handshake with imap-urlauth-worker service failed");
		break;
	case CONNECTION_DISCONNECT_BUFFER_FULL:
		i_unreached();
	default:
		/* Disconnected */
		imap_urlauth_worker_client_disconnect(wclient);
	}
}

static int
imap_urlauth_worker_connection_input_args(struct connection *conn,
					  const char *const *args)
{
	struct imap_urlauth_worker_client *wclient =
		container_of(conn, struct imap_urlauth_worker_client, conn);
	struct client *client = wclient->client;
	const char *response = args[0];
	const char *const *apps;
	unsigned int count, i;
	bool restart;
	string_t *str;
	int ret;

	switch (wclient->worker_state) {
	case IMAP_URLAUTH_WORKER_STATE_INACTIVE:
		if (strcasecmp(response, "OK") != 0) {
			imap_urlauth_worker_client_error(
				wclient, "Worker handshake failed");
			return -1;
		}
		wclient->worker_state = IMAP_URLAUTH_WORKER_STATE_CONNECTED;

		str = t_str_new(256);
		str_append(str, "ACCESS\t");
		if (client->username != NULL)
			str_append_tabescaped(str, client->username);
		str_append(str, "\t");
		str_append_tabescaped(str, client->service);
		if (client->set->mail_debug)
			str_append(str, "\tdebug");
		if (array_count(&client->access_apps) > 0) {
			str_append(str, "\tapps=");
			apps = array_get(&client->access_apps, &count);
			str_append(str, apps[0]);
			for (i = 1; i < count; i++) {
				str_append_c(str, ',');
				str_append_tabescaped(str, apps[i]);
			}
		}
		str_append(str, "\n");

		ret = o_stream_send(wclient->conn.output,
				    str_data(str), str_len(str));
		i_assert(ret < 0 || (size_t)ret == str_len(str));
		if (ret < 0) {
			imap_urlauth_worker_client_error(wclient,
				"Failed to send ACCESS control command to worker");
			return -1;
		}
		break;

	case IMAP_URLAUTH_WORKER_STATE_CONNECTED:
		if (strcasecmp(response, "OK") != 0) {
			imap_urlauth_worker_client_error(wclient,
				"Failed to negotiate access parameters");
			return -1;
		}
		wclient->worker_state = IMAP_URLAUTH_WORKER_STATE_ACTIVE;
		break;

	case IMAP_URLAUTH_WORKER_STATE_ACTIVE:
		restart = TRUE;
		if (strcasecmp(response, "DISCONNECTED") == 0) {
			/* worker detected client disconnect */
			restart = FALSE;
		} else if (strcasecmp(response, "FINISHED") != 0) {
			/* unknown response */
			imap_urlauth_worker_client_error(wclient,
				"Worker finished with unknown response");
			return -1;
		}

		e_debug(wclient->event, "Worker finished successfully");

		if (restart) {
			/* connect to new worker for accessing different user */
			imap_urlauth_worker_client_disconnect(wclient);
			if (imap_urlauth_worker_client_connect(wclient) < 0) {
				imap_urlauth_worker_client_error(wclient,
					"Failed to connect to new worker");
				return -1;
			}

			/* indicate success of "END" command */
			client_send_line(client, "OK");
		} else {
			imap_urlauth_worker_client_error(
				wclient, "Client disconnected");
		}
		return -1;
 	default:
		i_unreached();
	}
	return 0;
}
