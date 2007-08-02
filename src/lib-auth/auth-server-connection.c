/* Copyright (C) 2003-2004 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "hash.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "network.h"
#include "auth-client.h"
#include "auth-server-connection.h"
#include "auth-server-request.h"

#include <unistd.h>
#include <stdlib.h>

static void auth_server_connection_unref(struct auth_server_connection *conn);

static void update_available_auth_mechs(struct auth_server_connection *conn)
{
	struct auth_client *client = conn->client;
	const struct auth_mech_desc *mech;
	struct auth_mech_desc *new_mech;
	unsigned int i;

	mech = conn->available_auth_mechs;
	for (i = 0; i < conn->available_auth_mechs_count; i++) {
		if (auth_client_find_mech(client, mech[i].name) == NULL) {
			new_mech = buffer_append_space_unsafe(
				client->available_auth_mechs, sizeof(*mech));
			*new_mech = mech[i];
			new_mech->name = i_strdup(mech[i].name);
		}
	}
}

static bool
auth_client_input_mech(struct auth_server_connection *conn, const char *args)
{
	const char *const *list;
	struct auth_mech_desc mech_desc;

	if (conn->handshake_received) {
		i_error("BUG: Authentication server already sent handshake");
		return FALSE;
	}

	list = t_strsplit(args, "\t");
	if (list[0] == NULL) {
		i_error("BUG: Authentication server sent broken MECH line");
		return FALSE;
	}

	memset(&mech_desc, 0, sizeof(mech_desc));
	mech_desc.name = p_strdup(conn->pool, list[0]);

	if (strcmp(mech_desc.name, "PLAIN") == 0)
		conn->has_plain_mech = TRUE;

	for (list++; *list != NULL; list++) {
		if (strcmp(*list, "private") == 0)
			mech_desc.flags |= MECH_SEC_PRIVATE;
		else if (strcmp(*list, "anonymous") == 0)
			mech_desc.flags |= MECH_SEC_ANONYMOUS;
		else if (strcmp(*list, "plaintext") == 0)
			mech_desc.flags |= MECH_SEC_PLAINTEXT;
		else if (strcmp(*list, "dictionary") == 0)
			mech_desc.flags |= MECH_SEC_DICTIONARY;
		else if (strcmp(*list, "active") == 0)
			mech_desc.flags |= MECH_SEC_ACTIVE;
		else if (strcmp(*list, "forward-secrecy") == 0)
			mech_desc.flags |= MECH_SEC_FORWARD_SECRECY;
		else if (strcmp(*list, "mutual-auth") == 0)
			mech_desc.flags |= MECH_SEC_MUTUAL_AUTH;
	}
	buffer_append(conn->auth_mechs_buf, &mech_desc, sizeof(mech_desc));
	return TRUE;
}

static bool
auth_client_input_spid(struct auth_server_connection *conn, const char *args)
{
	if (conn->handshake_received) {
		i_error("BUG: Authentication server already sent handshake");
		return FALSE;
	}

	conn->server_pid = (unsigned int)strtoul(args, NULL, 10);
	return TRUE;
}

static bool
auth_client_input_cuid(struct auth_server_connection *conn, const char *args)
{
	if (conn->handshake_received) {
		i_error("BUG: Authentication server already sent handshake");
		return FALSE;
	}

	conn->connect_uid = (unsigned int)strtoul(args, NULL, 10);
	return TRUE;
}

static bool auth_client_input_done(struct auth_server_connection *conn)
{
	conn->available_auth_mechs = conn->auth_mechs_buf->data;
	conn->available_auth_mechs_count =
		conn->auth_mechs_buf->used / sizeof(struct auth_mech_desc);

	if (conn->available_auth_mechs_count == 0) {
		i_error("BUG: Authentication server returned no mechanisms");
		return FALSE;
	}

	conn->handshake_received = TRUE;
	conn->client->conn_waiting_handshake_count--;
	update_available_auth_mechs(conn);

	if (conn->client->connect_notify_callback != NULL &&
	    auth_client_is_connected(conn->client)) {
		conn->client->connect_notify_callback(conn->client, TRUE,
				conn->client->connect_notify_context);
	}
	return TRUE;
}

static void auth_client_input(struct auth_server_connection *conn)
{
	const char *line;
	int ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_server_connection_destroy(&conn, TRUE);
		return;
	case -2:
		/* buffer full - can't happen unless auth is buggy */
		i_error("BUG: Auth server sent us more than %d bytes of data",
			AUTH_CLIENT_MAX_LINE_LENGTH);
		auth_server_connection_destroy(&conn, FALSE);
		return;
	}

	if (conn->version_received) {
		line = i_stream_next_line(conn->input);
		if (line == NULL)
			return;

		/* make sure the major version matches */
		if (strncmp(line, "VERSION\t", 8) != 0 ||
		    atoi(t_strcut(line + 8, '\t')) !=
		    AUTH_CLIENT_PROTOCOL_MAJOR_VERSION) {
			i_error("Authentication server not compatible with "
				"this client (mixed old and new binaries?)");
			auth_server_connection_destroy(&conn, FALSE);
			return;
		}
		conn->version_received = TRUE;
	}

	conn->refcount++;
	while ((line = i_stream_next_line(conn->input)) != NULL) {
		t_push();
		if (strncmp(line, "OK\t", 3) == 0)
			ret = auth_client_input_ok(conn, line + 3);
		else if (strncmp(line, "CONT\t", 5) == 0)
			ret = auth_client_input_cont(conn, line + 5);
        	else if (strncmp(line, "FAIL\t", 5) == 0)
			ret = auth_client_input_fail(conn, line + 5);
		else if (strncmp(line, "MECH\t", 5) == 0)
			ret = auth_client_input_mech(conn, line + 5);
		else if (strncmp(line, "SPID\t", 5) == 0)
			ret = auth_client_input_spid(conn, line + 5);
		else if (strncmp(line, "CUID\t", 5) == 0)
			ret = auth_client_input_cuid(conn, line + 5);
		else if (strcmp(line, "DONE") == 0)
			ret = auth_client_input_done(conn);
		else {
			/* ignore unknown command */
			ret = TRUE;
		}
		t_pop();

		if (!ret) {
			auth_server_connection_destroy(&conn, FALSE);
			break;
		}
	}
	auth_server_connection_unref(conn);
}

struct auth_server_connection *
auth_server_connection_new(struct auth_client *client, const char *path)
{
	struct auth_server_connection *conn;
	const char *handshake;
	pool_t pool;
	int fd, try;

	/* max. 1 second wait here. */
	for (try = 0; try < 10; try++) {
		fd = net_connect_unix(path);
		if (fd != -1 || (errno != EAGAIN && errno != ECONNREFUSED))
			break;

		/* busy. wait for a while. */
		usleep(((rand() % 10) + 1) * 10000);
	}
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
	conn->input = i_stream_create_fd(fd, AUTH_CLIENT_MAX_LINE_LENGTH,
					 FALSE);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);
	conn->requests = hash_create(default_pool, pool, 100, NULL, NULL);
	conn->auth_mechs_buf = buffer_create_dynamic(default_pool, 256);

	conn->next = client->connections;
	client->connections = conn;

	handshake = t_strdup_printf("VERSION\t%u\t%u\nCPID\t%u\n",
				    AUTH_CLIENT_PROTOCOL_MAJOR_VERSION,
                                    AUTH_CLIENT_PROTOCOL_MINOR_VERSION,
				    client->pid);

        client->conn_waiting_handshake_count++;
	if (o_stream_send_str(conn->output, handshake) < 0) {
		errno = conn->output->stream_errno;
		i_warning("Error sending handshake to auth server: %m");
		auth_server_connection_destroy(&conn, TRUE);
		return NULL;
	}
	return conn;
}

void auth_server_connection_destroy(struct auth_server_connection **_conn,
				    bool reconnect)
{
        struct auth_server_connection *conn = *_conn;
	struct auth_client *client = conn->client;
	struct auth_server_connection **pos;

	*_conn = NULL;

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

	if (conn->io != NULL)
		io_remove(&conn->io);

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
	i_assert(conn->refcount == 0);

	hash_destroy(conn->requests);
	buffer_free(conn->auth_mechs_buf);

	i_stream_unref(&conn->input);
	o_stream_unref(&conn->output);
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
				 const char *name, const char **error_r)
{
	struct auth_server_connection *conn, *match;
	const struct auth_mech_desc *mech;
	unsigned int i, n, match_n;

	/* find a connection which has this mechanism. if there are multiple
	   available connections to use, do round robin load balancing */
	match = NULL; match_n = n = 0;
	for (conn = client->connections; conn != NULL; conn = conn->next, n++) {
		mech = conn->available_auth_mechs;
		for (i = 0; i < conn->available_auth_mechs_count; i++) {
			if (strcasecmp(mech[i].name, name) == 0) {
				if (n > client->last_used_auth_process) {
					client->last_used_auth_process = n;
					return conn;
				}
				if (match == NULL) {
					match = conn;
					match_n = n;
				}
				break;
			}
		}
	}

	if (match != NULL) {
		client->last_used_auth_process = match_n;
		return match;
	}

	if (auth_client_find_mech(client, name) == NULL)
		*error_r = "Unsupported authentication mechanism";
	else {
		*error_r = "Authentication server isn't connected, "
			"try again later..";
	}

	return NULL;
}
