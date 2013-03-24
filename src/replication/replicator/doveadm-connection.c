/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "connection.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "wildcard-match.h"
#include "master-service.h"
#include "replicator-queue.h"
#include "doveadm-connection.h"

#include <unistd.h>

#define REPLICATOR_DOVEADM_MAJOR_VERSION 1
#define REPLICATOR_DOVEADM_MINOR_VERSION 0

struct doveadm_connection {
	struct connection conn;
	struct replicator_queue *queue;
};
static struct connection_list *doveadm_connections;

static int
client_input_status(struct doveadm_connection *client, const char *const *args)
{
	struct replicator_user *const *users, *user;
	unsigned int i, count;
	const char *mask = args[0];
	string_t *str = t_str_new(128);

	users = replicator_queue_get_users(client->queue, &count);
	for (i = 0; i < count; i++) {
		user = users[i];
		if (mask != NULL && !wildcard_match(user->username, mask))
			continue;

		str_truncate(str, 0);
		str_append_tabescaped(str, user->username);
		str_append_c(str, '\t');
		str_append(str, replicator_priority_to_str(user->priority));
		str_printfa(str, "\t%lld\t%lld\t%d\n",
			    (long long)user->last_fast_sync,
			    (long long)user->last_full_sync,
			    user->last_sync_failed);
		o_stream_send(client->conn.output, str_data(str), str_len(str));
	}
	o_stream_send(client->conn.output, "\n", 1);
	return 0;
}

static int client_input_args(struct connection *conn, const char *const *args)
{
	struct doveadm_connection *client = (struct doveadm_connection *)conn;
	const char *cmd = args[0];

	if (cmd == NULL) {
		i_error("%s: Empty command", conn->name);
		return 0;
	}
	args++;

	if (strcmp(cmd, "STATUS") == 0)
		return client_input_status(client, args);
	i_error("%s: Unknown command: %s", conn->name, cmd);
	return -1;
}

static void client_destroy(struct connection *conn)
{
	struct doveadm_connection *client = (struct doveadm_connection *)conn;

	connection_deinit(&client->conn);
	i_free(client);

	master_service_client_connection_destroyed(master_service);
}

void doveadm_connection_create(struct replicator_queue *queue, int fd)
{
	struct doveadm_connection *client;

	client = i_new(struct doveadm_connection, 1);
	client->queue = queue;
	connection_init_server(doveadm_connections, &client->conn,
			       "(doveadm client)", fd, fd);
}

static struct connection_settings doveadm_conn_set = {
	.service_name_in = "replicator-doveadm-client",
	.service_name_out = "replicator-doveadm-server",
	.major_version = REPLICATOR_DOVEADM_MAJOR_VERSION,
	.minor_version = REPLICATOR_DOVEADM_MINOR_VERSION,

	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1,
	.client = FALSE
};

static const struct connection_vfuncs doveadm_conn_vfuncs = {
	.destroy = client_destroy,
	.input_args = client_input_args
};

void doveadm_connections_init(void)
{
	doveadm_connections = connection_list_init(&doveadm_conn_set,
						   &doveadm_conn_vfuncs);
}

void doveadm_connections_deinit(void)
{
	connection_list_deinit(&doveadm_connections);
}
