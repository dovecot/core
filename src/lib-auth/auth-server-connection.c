/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "network.h"
#include "auth-client.h"
#include "auth-server-connection.h"
#include "auth-server-request.h"

#include <unistd.h>

/* Maximum size for an auth reply. 50kB should be more than enough. */
#define MAX_INBUF_SIZE (1024*50)

#define MAX_OUTBUF_SIZE \
	(sizeof(struct auth_client_request_continue) + \
	 AUTH_CLIENT_MAX_REQUEST_DATA_SIZE)

static void auth_server_connection_unref(struct auth_server_connection *conn);

static void update_available_auth_mechs(struct auth_client *client)
{
	struct auth_server_connection *conn;

        client->available_auth_mechs = 0;
	for (conn = client->connections; conn != NULL; conn = conn->next)
                client->available_auth_mechs |= conn->available_auth_mechs;
}

static void auth_handle_handshake(struct auth_server_connection *conn,
				  struct auth_client_handshake_reply *handshake)
{
	if (handshake->server_pid == 0) {
		i_error("BUG: Auth server said it's PID 0");
		auth_server_connection_destroy(conn, FALSE);
		return;
	}

	conn->pid = handshake->server_pid;
	conn->available_auth_mechs = handshake->auth_mechanisms;
	conn->handshake_received = TRUE;

        conn->client->conn_waiting_handshake_count--;
	update_available_auth_mechs(conn->client);

	if (conn->client->connect_notify_callback != NULL &&
	    auth_client_is_connected(conn->client)) {
		conn->client->connect_notify_callback(conn->client, TRUE,
				conn->client->connect_notify_context);
	}
}

static void auth_client_input(void *context)
{
	struct auth_server_connection *conn = context;
	struct auth_client_handshake_reply handshake;
	const unsigned char *data;
	size_t size;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_server_connection_destroy(conn, TRUE);
		return;
	case -2:
		/* buffer full - can't happen unless auth is buggy */
		i_error("BUG: Auth server sent us more than %d bytes of data",
			MAX_INBUF_SIZE);
		auth_server_connection_destroy(conn, FALSE);
		return;
	}

	if (!conn->handshake_received) {
		data = i_stream_get_data(conn->input, &size);
		if (size == sizeof(handshake)) {
			memcpy(&handshake, data, sizeof(handshake));
			i_stream_skip(conn->input, sizeof(handshake));

			auth_handle_handshake(conn, &handshake);
		} else if (size > sizeof(handshake)) {
			i_error("BUG: Auth server sent us too large handshake "
				"(%"PRIuSIZE_T " vs %"PRIuSIZE_T")", size,
				sizeof(handshake));
			auth_server_connection_destroy(conn, FALSE);
		}
		return;
	}

	if (!conn->reply_received) {
		data = i_stream_get_data(conn->input, &size);
		if (size < sizeof(conn->reply))
			return;

		memcpy(&conn->reply, data, sizeof(conn->reply));
		i_stream_skip(conn->input, sizeof(conn->reply));
		conn->reply_received = TRUE;
	}

	data = i_stream_get_data(conn->input, &size);
	if (size < conn->reply.data_size)
		return;

	/* we've got a full reply */
	conn->refcount++;
	conn->reply_received = FALSE;

	auth_server_request_handle_reply(conn, &conn->reply, data);
	i_stream_skip(conn->input, conn->reply.data_size);

	auth_server_connection_unref(conn);
}

struct auth_server_connection *
auth_server_connection_new(struct auth_client *client, const char *path)
{
	struct auth_server_connection *conn;
	struct auth_client_handshake_request handshake;
	pool_t pool;
	int fd;

	fd = net_connect_unix(path);
	if (fd == -1) {
		i_error("Can't connect to auth server at %s: %m", path);
		return NULL;
	}

	/* use blocking connection since we depend on auth server -
	   if it's slow, just wait */

	pool = pool_alloconly_create("Auth connection", 1024);
	conn = p_new(pool, struct auth_server_connection, 1);
	conn->refcount = 1;
	conn->pool = pool;

	conn->client = client;
	conn->path = p_strdup(pool, path);
	conn->fd = fd;
	conn->io = io_add(fd, IO_READ, auth_client_input, conn);
	conn->input = i_stream_create_file(fd, default_pool, MAX_INBUF_SIZE,
					   FALSE);
	conn->output = o_stream_create_file(fd, default_pool, MAX_OUTBUF_SIZE,
					    FALSE);
	conn->requests = hash_create(default_pool, pool, 100, NULL, NULL);

	conn->next = client->connections;
	client->connections = conn;

	/* send our handshake */
	memset(&handshake, 0, sizeof(handshake));
	handshake.client_pid = client->pid;

        client->conn_waiting_handshake_count++;
	if (o_stream_send(conn->output, &handshake, sizeof(handshake)) < 0) {
		errno = conn->output->stream_errno;
		i_warning("Error sending handshake to auth server: %m");
		auth_server_connection_destroy(conn, TRUE);
		return NULL;
	}
	return conn;
}

void auth_server_connection_destroy(struct auth_server_connection *conn,
				    int reconnect)
{
	struct auth_client *client = conn->client;
	struct auth_server_connection **pos;

	if (conn->fd == -1)
		return;

        pos = &conn->client->connections;
	for (; *pos != NULL; pos = &(*pos)->next) {
		if (*pos == conn) {
			*pos = conn->next;
			break;
		}
	}

	if (!conn->handshake_received)
		client->conn_waiting_handshake_count--;

	io_remove(conn->io);
	conn->io = NULL;

	i_stream_close(conn->input);
	o_stream_close(conn->output);

	if (close(conn->fd) < 0)
		i_error("close(auth) failed: %m");
	conn->fd = -1;

	auth_server_requests_remove_all(conn);
        auth_server_connection_unref(conn);

	if (reconnect)
		auth_client_connect_missing_servers(client);
	else if (client->connect_notify_callback != NULL) {
		client->connect_notify_callback(client,
				auth_client_is_connected(client),
				client->connect_notify_context);
	}
}

static void auth_server_connection_unref(struct auth_server_connection *conn)
{
	if (--conn->refcount > 0)
		return;

	hash_destroy(conn->requests);

	i_stream_unref(conn->input);
	o_stream_unref(conn->output);
	pool_unref(conn->pool);
}

struct auth_server_connection *
auth_server_connection_find_path(struct auth_client *client, const char *path)
{
	struct auth_server_connection *conn;

	for (conn = client->connections; conn != NULL; conn = conn->next) {
		if (strcmp(conn->path, path) == 0)
			return conn;
	}

	return NULL;
}

struct auth_server_connection *
auth_server_connection_find_mech(struct auth_client *client,
				 enum auth_mech mech, const char **error_r)
{
	struct auth_server_connection *conn;

	for (conn = client->connections; conn != NULL; conn = conn->next) {
		if ((conn->available_auth_mechs & mech))
			return conn;
	}

	if ((client->available_auth_mechs & mech) == 0)
		*error_r = "Unsupported authentication mechanism";
	else {
		*error_r = "Authentication server isn't connected, "
			"try again later..";
	}

	return NULL;
}
