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

static int client_input_status_overview(struct doveadm_connection *client)
{
	struct replicator_queue_iter *iter;
	struct replicator_user *user;
	enum replication_priority priority;
	unsigned int pending_counts[REPLICATION_PRIORITY_SYNC+1];
	unsigned int user_count, next_secs, pending_failed_count;
	unsigned int pending_full_resync_count, waiting_failed_count;
	string_t *str = t_str_new(256);

	memset(pending_counts, 0, sizeof(pending_counts));
	pending_failed_count = 0; waiting_failed_count = 0;
	pending_full_resync_count = 0;

	user_count = 0;
	iter = replicator_queue_iter_init(client->queue);
	while ((user = replicator_queue_iter_next(iter)) != NULL) {
		if (user->priority != REPLICATION_PRIORITY_NONE)
			pending_counts[user->priority]++;
		else if (replicator_queue_want_sync_now(client->queue,
							user, &next_secs)) {
			if (user->last_sync_failed)
				pending_failed_count++;
			else
				pending_full_resync_count++;
		} else {
			if (user->last_sync_failed)
				waiting_failed_count++;
		}
		user_count++;
	}
	replicator_queue_iter_deinit(&iter);

	for (priority = REPLICATION_PRIORITY_SYNC; priority > 0; priority--) {
		str_printfa(str, "Queued '%s' requests\t%u\n",
			    replicator_priority_to_str(priority),
			    pending_counts[priority]);
	}
	str_printfa(str, "Queued 'failed' requests\t%u\n",
		    pending_failed_count);
	str_printfa(str, "Queued 'full resync' requests\t%u\n",
		    pending_full_resync_count);
	str_printfa(str, "Waiting 'failed' requests\t%u\n",
		    waiting_failed_count);
	str_printfa(str, "Total number of known users\t%u\n", user_count);
	str_append_c(str, '\n');
	o_stream_send(client->conn.output, str_data(str), str_len(str));
	return 0;
}

static int
client_input_status(struct doveadm_connection *client, const char *const *args)
{
	struct replicator_queue_iter *iter;
	struct replicator_user *user;
	const char *mask = args[0];
	string_t *str = t_str_new(128);

	if (mask == NULL)
		return client_input_status_overview(client);

	iter = replicator_queue_iter_init(client->queue);
	while ((user = replicator_queue_iter_next(iter)) != NULL) {
		if (!wildcard_match(user->username, mask))
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
	replicator_queue_iter_deinit(&iter);
	o_stream_send(client->conn.output, "\n", 1);
	return 0;
}

static int
client_input_replicate(struct doveadm_connection *client, const char *const *args)
{
	struct replicator_queue_iter *iter;
	struct replicator_user *user;
	const char *usermask;
	enum replication_priority priority;
	unsigned int match_count;

	/* <priority> <username>|<mask> */
	if (str_array_length(args) != 2) {
		i_error("%s: REPLICATE: Invalid parameters", client->conn.name);
		return -1;
	}
	if (replication_priority_parse(args[0], &priority) < 0) {
		o_stream_send_str(client->conn.output, "-Invalid priority\n");
		return 0;
	}
	usermask = args[1];
	if (strchr(usermask, '*') == NULL && strchr(usermask, '?') == NULL) {
		replicator_queue_add(client->queue, usermask, priority);
		o_stream_send_str(client->conn.output, "+1\n");
		return 0;
	}

	match_count = 0;
	iter = replicator_queue_iter_init(client->queue);
	while ((user = replicator_queue_iter_next(iter)) != NULL) {
		if (!wildcard_match(user->username, usermask))
			continue;
		replicator_queue_add(client->queue, user->username, priority);
		match_count++;
	}
	replicator_queue_iter_deinit(&iter);
	o_stream_send_str(client->conn.output,
			  t_strdup_printf("+%u\n", match_count));
	return 0;
}

static int
client_input_remove(struct doveadm_connection *client, const char *const *args)
{
	struct replicator_user *user;

	/* <username> */
	if (str_array_length(args) != 1) {
		i_error("%s: REMOVE: Invalid parameters", client->conn.name);
		return -1;
	}
	user = replicator_queue_lookup(client->queue, args[0]);
	if (user == NULL)
		o_stream_send_str(client->conn.output, "-User not found\n");
	else {
		replicator_queue_remove(client->queue, &user);
		o_stream_send_str(client->conn.output, "+\n");
	}
	return 0;
}

static int
client_input_notify(struct doveadm_connection *client, const char *const *args)
{
	struct replicator_user *user;

	/* <username> <flags> <state> */
	if (str_array_length(args) < 3) {
		i_error("%s: NOTIFY: Invalid parameters", client->conn.name);
		return -1;
	}

	user = replicator_queue_add(client->queue, args[0],
				    REPLICATION_PRIORITY_NONE);
	if (args[1][0] == 'f')
		user->last_full_sync = ioloop_time;
	user->last_fast_sync = ioloop_time;
	user->last_update = ioloop_time;

	if (args[2][0] != '\0') {
		i_free(user->state);
		user->state = i_strdup(args[2]);
	}
	o_stream_send_str(client->conn.output, "+\n");
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
	else if (strcmp(cmd, "REPLICATE") == 0)
		return client_input_replicate(client, args);
	else if (strcmp(cmd, "REMOVE") == 0)
		return client_input_remove(client, args);
	else if (strcmp(cmd, "NOTIFY") == 0)
		return client_input_notify(client, args);
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
