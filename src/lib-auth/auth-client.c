/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "hash.h"
#include "auth-client.h"
#include "auth-server-connection.h"

#include <dirent.h>
#include <sys/stat.h>

struct auth_client *auth_client_new(unsigned int client_pid)
{
	struct auth_client *client;

	client = i_new(struct auth_client, 1);
	client->pid = client_pid;

	auth_client_connect_missing_servers(client);
	return client;
}

void auth_client_free(struct auth_client *client)
{
	struct auth_server_connection *next;

	while (client->connections != NULL) {
		next = client->connections->next;
		auth_server_connection_destroy(client->connections, FALSE);
		client->connections = next;
	}

	if (client->to_reconnect != NULL)
		timeout_remove(client->to_reconnect);
	i_free(client);
}

enum auth_mech auth_client_get_available_mechs(struct auth_client *client)
{
	return client->available_auth_mechs;
}

int auth_client_is_connected(struct auth_client *client)
{
	return client->to_reconnect == NULL &&
		client->conn_waiting_handshake_count == 0;
}

void auth_client_set_connect_notify(struct auth_client *client,
				    auth_connect_notify_callback_t *callback,
				    void *context)
{
	client->connect_notify_callback = callback;
	client->connect_notify_context = context;
}

static void reconnect_timeout(void *context)
{
	struct auth_client *client = context;

	auth_client_connect_missing_servers(client);
}

void auth_client_connect_missing_servers(struct auth_client *client)
{
	DIR *dirp;
	struct dirent *dp;
	struct stat st;
	int reconnect;

	/* we're chrooted into */
	dirp = opendir(".");
	if (dirp == NULL) {
		i_fatal("opendir(.) failed when trying to get list of "
			"authentication servers: %m");
	}

	reconnect = FALSE;
	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;

		if (auth_server_connection_find_path(client, dp->d_name) != NULL) {
			/* already connected */
			continue;
		}

		if (stat(dp->d_name, &st) == 0 && S_ISSOCK(st.st_mode)) {
			if (auth_server_connection_new(client,
						       dp->d_name) == NULL)
				reconnect = TRUE;
		}
	}

	if (closedir(dirp) < 0)
		i_error("closedir() failed: %m");

	if (reconnect || client->connections == NULL) {
		if (client->to_reconnect == NULL) {
			client->to_reconnect =
				timeout_add(5000, reconnect_timeout, client);
		}
	} else if (client->to_reconnect != NULL) {
		timeout_remove(client->to_reconnect);
		client->to_reconnect = NULL;
	}

	client->connect_notify_callback(client,
					auth_client_is_connected(client),
					client->connect_notify_context);
}
