/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "connection.h"
#include "ostream.h"
#include "admin-client.h"

struct admin_client_command {
	char *cmdline;
	admin_client_callback_t *callback;
	void *context;
};

struct admin_client {
	struct connection conn;
	int refcount;
	struct timeout *to_failed;
	ARRAY(struct admin_client_command) commands;
};

static struct connection_list *admin_clients;

struct admin_client *
admin_client_init(const char *base_dir, const char *service, pid_t pid)
{
	struct admin_client *client;
	const char *path;

	path = t_strdup_printf("%s/srv.%s/%ld",
			       base_dir, service, (long)pid);

	client = i_new(struct admin_client, 1);
	client->refcount = 1;
	connection_init_client_unix(admin_clients, &client->conn, path);
	i_array_init(&client->commands, 8);
	return client;
}

static void admin_client_ref(struct admin_client *client)
{
	i_assert(client->refcount > 0);
	client->refcount++;
}

static void admin_client_reply(struct admin_client *client,
			       const char *reply, const char *error)
{
	struct admin_client_command *cmd;

	cmd = array_idx_modifiable(&client->commands, 0);
	cmd->callback(reply, error, cmd->context);
	i_free(cmd->cmdline);
	array_pop_front(&client->commands);
}

static void
admin_client_fail_commands(struct admin_client *client, const char *error)
{
	admin_client_ref(client);
	timeout_remove(&client->to_failed);
	while (array_count(&client->commands) > 0)
		admin_client_reply(client, NULL, error);
	admin_client_unref(&client);
}

static void admin_client_destroy(struct connection *conn)
{
	struct admin_client *client =
		container_of(conn, struct admin_client, conn);

	admin_client_fail_commands(client, connection_disconnect_reason(conn));
}

void admin_client_unref(struct admin_client **_client)
{
	struct admin_client *client = *_client;
	struct admin_client_command *cmd;

	if (client == NULL)
		return;
	*_client = NULL;

	i_assert(client->refcount > 0);
	if (--client->refcount > 0)
		return;

	array_foreach_modifiable(&client->commands, cmd)
		i_free(cmd->cmdline);
	array_free(&client->commands);
	connection_deinit(&client->conn);
	i_free(client);
}

static void admin_client_connected(struct connection *conn, bool success)
{
	struct admin_client *client =
		container_of(conn, struct admin_client, conn);

	if (success)
		return;

	e_error(conn->event, "net_connect_unix(%s) failed: %m",
		conn->base_name);
	admin_client_fail_commands(client, "Failed to connect to admin socket");
}

#undef admin_client_send_cmd
void admin_client_send_cmd(struct admin_client *client, const char *cmdline,
			   admin_client_callback_t *callback, void *context)
{
	struct admin_client_command *cmd;

	cmd = array_append_space(&client->commands);
	cmd->cmdline = i_strdup(cmdline);
	cmd->callback = callback;
	cmd->context = context;

	if (client->conn.disconnected) {
		if (connection_client_connect_async(&client->conn) < 0)
			return;
	}
	const struct const_iovec iov[] = {
		{ cmdline, strlen(cmdline) },
		{ "\n", 1 }
	};
	o_stream_nsendv(client->conn.output, iov, N_ELEMENTS(iov));
}

static int
admin_client_input_line(struct connection *conn, const char *line)
{
	struct admin_client *client =
		container_of(conn, struct admin_client, conn);

	if (!conn->version_received)
		return connection_input_line_default(conn, line);

	if (array_count(&client->commands) == 0) {
		e_error(conn->event, "Unexpected input: %s", line);
		return -1;
	}
	admin_client_ref(client);
	admin_client_reply(client, line, NULL);
	int ret = client->refcount == 1 ? -1 : 1;
	admin_client_unref(&client);
	return ret;
}

static const struct connection_settings admin_client_set = {
	.service_name_in = "master-admin-server",
	.service_name_out = "master-admin-client",
	.major_version = 1,
	.minor_version = 0,

	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.client = TRUE,
};

static const struct connection_vfuncs admin_client_vfuncs = {
	.destroy = admin_client_destroy,
	.client_connected = admin_client_connected,
	.input_line = admin_client_input_line,
};

void admin_clients_init(void)
{
	admin_clients = connection_list_init(&admin_client_set,
					     &admin_client_vfuncs);
}

void admin_clients_deinit(void)
{
	connection_list_deinit(&admin_clients);
}
