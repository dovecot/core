/* Copyright (c) 2003-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "ioloop.h"
#include "hash.h"
#include "auth-client.h"
#include "auth-server-connection.h"

#include <dirent.h>
#include <sys/stat.h>

#define AUTH_CLIENT_SOCKET_MAX_WAIT_TIME 10

struct auth_client *auth_client_new(unsigned int client_pid)
{
	struct auth_client *client;

	client = i_new(struct auth_client, 1);
	client->pid = client_pid;
	client->available_auth_mechs = buffer_create_dynamic(default_pool, 128);

	auth_client_connect_missing_servers(client);
	return client;
}

void auth_client_free(struct auth_client **_client)
{
	struct auth_client *client = *_client;
	struct auth_server_connection *next;
	struct auth_mech_desc *mech;
	size_t i, size;

	*_client = NULL;

	mech = buffer_get_modifiable_data(client->available_auth_mechs, &size);
	size /= sizeof(*mech);
	for (i = 0; i < size; i++)
		i_free(mech[i].name);
	buffer_free(&client->available_auth_mechs);

	while (client->connections != NULL) {
		next = client->connections->next;
		auth_server_connection_destroy(&client->connections, FALSE);
		client->connections = next;
	}

	if (client->to_reconnect != NULL)
		timeout_remove(&client->to_reconnect);
	i_free(client);
}

void auth_client_reconnect(struct auth_client *client)
{
	struct auth_server_connection *next;

	while (client->connections != NULL) {
		next = client->connections->next;
		auth_server_connection_destroy(&client->connections, FALSE);
		client->connections = next;
	}

	auth_client_connect_missing_servers(client);
}

const struct auth_mech_desc *
auth_client_get_available_mechs(struct auth_client *client,
				unsigned int *mech_count)
{
	const struct auth_mech_desc *mechs;
	size_t size;

	mechs = buffer_get_data(client->available_auth_mechs, &size);
	*mech_count = size / sizeof(*mechs);
	return mechs;
}

const struct auth_mech_desc *
auth_client_find_mech(struct auth_client *client, const char *name)
{
	const struct auth_mech_desc *mech;
	size_t i, size;

	mech = buffer_get_data(client->available_auth_mechs, &size);
	size /= sizeof(*mech);
	for (i = 0; i < size; i++) {
		if (strcasecmp(mech[i].name, name) == 0)
			return &mech[i];
	}

	return NULL;
}

bool auth_client_reserve_connection(struct auth_client *client,
				    const char *mech,
				    struct auth_connect_id *id_r)
{
	struct auth_server_connection *conn;
	const char *error;

	conn = auth_server_connection_find_mech(client, mech, &error);
	if (conn == NULL)
		return FALSE;

	id_r->server_pid = conn->server_pid;
	id_r->connect_uid = conn->connect_uid;

	return TRUE;
}

bool auth_client_is_connected(struct auth_client *client)
{
	return !client->reconnect &&
		client->conn_waiting_handshake_count == 0 &&
		client->connections != NULL;
}

void auth_client_set_connect_notify(struct auth_client *client,
				    auth_connect_notify_callback_t *callback,
				    void *context)
{
	client->connect_notify_callback = callback;
	client->connect_notify_context = context;
}

static void reconnect_timeout(struct auth_client *client)
{
	auth_client_connect_missing_servers(client);
}

void auth_client_connect_missing_servers(struct auth_client *client)
{
	DIR *dirp;
	struct dirent *dp;
	struct stat st;

	/* we're chrooted */
	dirp = opendir(".");
	if (dirp == NULL) {
		i_fatal("opendir(.) failed when trying to get list of "
			"authentication servers: %m");
	}

	client->reconnect = FALSE;
	while ((dp = readdir(dirp)) != NULL) {
		const char *name = dp->d_name;

		if (name[0] == '.')
			continue;

		if (auth_server_connection_find_path(client, name) != NULL) {
			/* already connected */
			continue;
		}

		/* Normally they're sockets, but in UnixWare they're
		   created as fifos. */
		if (stat(name, &st) == 0 &&
		    (S_ISSOCK(st.st_mode) || S_ISFIFO(st.st_mode))) {
			if (auth_server_connection_new(client, name) == NULL)
				client->reconnect = TRUE;
		}
	}

	if (client->connections == NULL && !client->reconnect) {
		if (client->missing_sockets_start_time == 0)
			client->missing_sockets_start_time = ioloop_time;
		else if (ioloop_time - client->missing_sockets_start_time >
			 AUTH_CLIENT_SOCKET_MAX_WAIT_TIME)
			i_fatal("No authentication sockets found");
	}

	if (closedir(dirp) < 0)
		i_error("closedir() failed: %m");

	if (client->reconnect || client->connections == NULL) {
		if (client->to_reconnect == NULL) {
			client->to_reconnect =
				timeout_add(1000, reconnect_timeout, client);
		}
	} else if (client->to_reconnect != NULL)
		timeout_remove(&client->to_reconnect);

	if (client->connect_notify_callback != NULL) {
		client->connect_notify_callback(client,
				auth_client_is_connected(client),
				client->connect_notify_context);
	}
}
