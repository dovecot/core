/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "connection.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "wildcard-match.h"
#include "master-service.h"
#include "replicator-brain.h"
#include "replicator-queue.h"
#include "replicator-settings.h"
#include "dsync-client.h"
#include "doveadm-connection.h"

#include <unistd.h>

#define REPLICATOR_DOVEADM_MAJOR_VERSION 1
#define REPLICATOR_DOVEADM_MINOR_VERSION 0

struct doveadm_connection {
	struct connection conn;
	struct replicator_brain *brain;
};
static struct connection_list *doveadm_connections;

static int client_input_status_overview(struct doveadm_connection *client)
{
	struct replicator_queue *queue =
		replicator_brain_get_queue(client->brain);
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
	iter = replicator_queue_iter_init(queue);
	while ((user = replicator_queue_iter_next(iter)) != NULL) {
		if (user->priority != REPLICATION_PRIORITY_NONE)
			pending_counts[user->priority]++;
		else if (replicator_queue_want_sync_now(queue, user, &next_secs)) {
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
	o_stream_nsend(client->conn.output, str_data(str), str_len(str));
	return 0;
}

static int
client_input_status(struct doveadm_connection *client, const char *const *args)
{
	struct replicator_queue *queue =
		replicator_brain_get_queue(client->brain);
	struct replicator_queue_iter *iter;
	struct replicator_user *user;
	const char *mask = args[0];
	string_t *str = t_str_new(128);

	if (mask == NULL)
		return client_input_status_overview(client);

	iter = replicator_queue_iter_init(queue);
	while ((user = replicator_queue_iter_next(iter)) != NULL) {
		if (!wildcard_match(user->username, mask))
			continue;

		str_truncate(str, 0);
		str_append_tabescaped(str, user->username);
		str_append_c(str, '\t');
		str_append(str, replicator_priority_to_str(user->priority));
		str_printfa(str, "\t%lld\t%lld\t%d\t%lld\n",
			    (long long)user->last_fast_sync,
			    (long long)user->last_full_sync,
			    user->last_sync_failed ? 1 : 0,
			    (long long)user->last_successful_sync);
		o_stream_nsend(client->conn.output, str_data(str), str_len(str));
	}
	replicator_queue_iter_deinit(&iter);
	o_stream_nsend(client->conn.output, "\n", 1);
	return 0;
}

static int
client_input_status_dsyncs(struct doveadm_connection *client)
{
	string_t *str = t_str_new(256);
	const ARRAY_TYPE(dsync_client) *clients;
	struct dsync_client *const *clientp;
	const char *username;

	clients = replicator_brain_get_dsync_clients(client->brain);
	array_foreach(clients, clientp) {
		username = dsync_client_get_username(*clientp);
		if (username != NULL) {
			str_append_tabescaped(str, username);
			str_append_c(str, '\t');
			switch (dsync_client_get_type(*clientp)) {
			case DSYNC_TYPE_FULL:
				str_append(str, "full");
				break;
			case DSYNC_TYPE_NORMAL:
				str_append(str, "normal");
				break;
			case DSYNC_TYPE_INCREMENTAL:
				str_append(str, "incremental");
				break;
			}
		} else {
			str_append(str, "\t-");
		}
		str_append_c(str, '\t');
		str_append_tabescaped(str, dsync_client_get_state(*clientp));
		str_append_c(str, '\n');
	}

	str_append_c(str, '\n');
	o_stream_nsend(client->conn.output, str_data(str), str_len(str));
	return 0;
}

static int
client_input_replicate(struct doveadm_connection *client, const char *const *args)
{
	struct replicator_queue *queue =
		replicator_brain_get_queue(client->brain);
	struct replicator_queue_iter *iter;
	struct replicator_user *user;
	const char *usermask;
	enum replication_priority priority;
	unsigned int match_count;
	bool full;

	/* <priority> <flags> <username>|<mask> */
	if (str_array_length(args) != 3) {
		i_error("%s: REPLICATE: Invalid parameters", client->conn.name);
		return -1;
	}
	if (replication_priority_parse(args[0], &priority) < 0) {
		o_stream_nsend_str(client->conn.output, "-Invalid priority\n");
		return 0;
	}
	full = strchr(args[1], 'f') != NULL;
	usermask = args[2];
	if (strchr(usermask, '*') == NULL && strchr(usermask, '?') == NULL) {
		user = replicator_queue_add(queue, usermask, priority);
		if (full)
			user->force_full_sync = TRUE;
		o_stream_nsend_str(client->conn.output, "+1\n");
		return 0;
	}

	match_count = 0;
	iter = replicator_queue_iter_init(queue);
	while ((user = replicator_queue_iter_next(iter)) != NULL) {
		if (!wildcard_match(user->username, usermask))
			continue;
		user = replicator_queue_add(queue, user->username, priority);
		if (full)
			user->force_full_sync = TRUE;
		match_count++;
	}
	replicator_queue_iter_deinit(&iter);
	o_stream_nsend_str(client->conn.output,
			  t_strdup_printf("+%u\n", match_count));
	return 0;
}

static int
client_input_add(struct doveadm_connection *client, const char *const *args)
{
	struct replicator_queue *queue =
		replicator_brain_get_queue(client->brain);
	const struct replicator_settings *set =
		replicator_brain_get_settings(client->brain);

	/* <usermask> */
	if (str_array_length(args) != 1) {
		i_error("%s: ADD: Invalid parameters", client->conn.name);
		return -1;
	}

	if (strchr(args[0], '*') == NULL && strchr(args[0], '?') == NULL) {
		(void)replicator_queue_add(queue, args[0],
					   REPLICATION_PRIORITY_NONE);
	} else {
		replicator_queue_add_auth_users(queue, set->auth_socket_path,
						args[0], ioloop_time);
	}
	o_stream_nsend_str(client->conn.output, "+\n");
	return 0;
}

static int
client_input_remove(struct doveadm_connection *client, const char *const *args)
{
	struct replicator_queue *queue =
		replicator_brain_get_queue(client->brain);
	struct replicator_user *user;

	/* <username> */
	if (str_array_length(args) != 1) {
		i_error("%s: REMOVE: Invalid parameters", client->conn.name);
		return -1;
	}
	user = replicator_queue_lookup(queue, args[0]);
	if (user == NULL)
		o_stream_nsend_str(client->conn.output, "-User not found\n");
	else {
		replicator_queue_remove(queue, &user);
		o_stream_nsend_str(client->conn.output, "+\n");
	}
	return 0;
}

static int
client_input_notify(struct doveadm_connection *client, const char *const *args)
{
	struct replicator_queue *queue =
		replicator_brain_get_queue(client->brain);
	struct replicator_user *user;

	/* <username> <flags> <state> */
	if (str_array_length(args) < 3) {
		i_error("%s: NOTIFY: Invalid parameters", client->conn.name);
		return -1;
	}

	user = replicator_queue_add(queue, args[0], REPLICATION_PRIORITY_NONE);
	if (args[1][0] == 'f')
		user->last_full_sync = ioloop_time;
	user->last_fast_sync = ioloop_time;
	user->last_update = ioloop_time;

	if (args[2][0] != '\0') {
		i_free(user->state);
		user->state = i_strdup(args[2]);
	}
	o_stream_nsend_str(client->conn.output, "+\n");
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
	else if (strcmp(cmd, "STATUS-DSYNC") == 0)
		return client_input_status_dsyncs(client);
	else if (strcmp(cmd, "REPLICATE") == 0)
		return client_input_replicate(client, args);
	else if (strcmp(cmd, "ADD") == 0)
		return client_input_add(client, args);
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

void doveadm_connection_create(struct replicator_brain *brain, int fd)
{
	struct doveadm_connection *client;

	client = i_new(struct doveadm_connection, 1);
	client->brain = brain;
	connection_init_server(doveadm_connections, &client->conn,
			       "doveadm-client", fd, fd);
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
