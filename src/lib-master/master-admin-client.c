/* Copyright (c) 2022 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "connection.h"
#include "ostream.h"
#include "str.h"
#include "master-service-private.h"
#include "master-admin-client.h"

struct master_admin_client {
	struct connection conn;
	int refcount;

	struct ioloop *wait_ioloop;
	bool reply_pending;
};

static struct connection_list *master_admin_clients = NULL;
static struct master_admin_client_callback master_admin_client_callbacks;

static void master_admin_client_ref(struct master_admin_client *client)
{
	i_assert(client->refcount > 0);
	client->refcount++;
}

static void master_admin_client_unref(struct master_admin_client **_client)
{
	struct master_admin_client *client = *_client;

	i_assert(client->refcount > 0);
	*_client = NULL;

	if (--client->refcount == 0)
		i_free(client);
}

static void
cmd_kick_user(struct master_admin_client *client, const char *const *args)
{
	const char *user = args[0];
	if (user == NULL) {
		master_admin_client_send_reply(client, "-Missing parameter");
		return;
	}
	guid_128_t conn_guid;
	if (args[1] == NULL)
		guid_128_empty(conn_guid);
	else if (guid_128_from_string(args[1], conn_guid) < 0) {
		master_admin_client_send_reply(client,
					       "-Invalid conn-guid parameter");
		return;
	} else if (args[2] != NULL) {
		master_admin_client_send_reply(client, "-Extra parameters");
		return;
	}

	master_admin_client_send_reply(client, t_strdup_printf("+%u",
		master_admin_client_callbacks.cmd_kick_user(user, conn_guid)));
}

static void
cmd_kick_user_signal(struct master_admin_client *client,
		     const char *const *args)
{
	const char *user = args[0];
	if (user == NULL) {
		master_admin_client_send_reply(client, "-Missing parameter");
		return;
	}

	/* This command is usually handled by the signal handler, but looks
	   like the signal handling was delayed. Remember the username for
	   the signal. */
	master_service_set_last_kick_signal_user(master_service, user);
	/* Don't send a response back, just like the signal handler won't. */
	client->reply_pending = FALSE;
	master_admin_client_unref(&client);
}

static int
master_admin_client_input_args(struct connection *conn, const char *const *args)
{
	struct master_admin_client *client =
		container_of(conn, struct master_admin_client, conn);

	if (client->reply_pending) {
		/* Delay handling the command until the previous command is
		   replied to. */
		connection_input_halt(conn);
		return 0;
	}
	const char *cmd = args[0];
	args++;

	if (client->wait_ioloop != NULL) {
		/* A command was received while waiting in
		   master_admin_client_initial_read(). Now that we've seen it,
		   stop the wait ioloop after the command is finished. */
		io_loop_stop(client->wait_ioloop);
	}

	/* Delay freeing the client until reply is sent */
	master_admin_client_ref(client);
	client->reply_pending = TRUE;

	if (strcmp(cmd, "KICK-USER") == 0 &&
	    master_admin_client_callbacks.cmd_kick_user != NULL)
		cmd_kick_user(client, args);
	else if (strcmp(cmd, "KICK-USER-SIGNAL") == 0) {
		cmd_kick_user_signal(client, args);
		return -1;
	} else if (master_admin_client_callbacks.cmd == NULL ||
		   !master_admin_client_callbacks.cmd(client, cmd, args)) {
		client->reply_pending = FALSE;
		o_stream_nsend_str(conn->output, "-Unknown command\n");
		master_admin_client_unref(&client);
	}
	return 1;
}

void master_admin_client_send_reply(struct master_admin_client *client,
				    const char *reply)
{
	i_assert(client->reply_pending);
	client->reply_pending = FALSE;

	struct const_iovec iov[] = {
		{ reply, strlen(reply) },
		{ "\n", 1 }
	};
	if (client->conn.output != NULL) {
		o_stream_nsendv(client->conn.output, iov, N_ELEMENTS(iov));
		connection_input_resume(&client->conn);
	} else {
		/* client already disconnected */
	}
	master_admin_client_unref(&client);
}

static void master_admin_client_destroy(struct connection *conn)
{
	struct master_admin_client *client =
		container_of(conn, struct master_admin_client, conn);

	connection_deinit(conn);
	master_admin_client_unref(&client);
}

static const struct connection_settings master_admin_conn_set = {
	.service_name_in = "master-admin-client",
	.service_name_out = "master-admin-server",
	.major_version = 1,
	.minor_version = 0,

	.input_max_size = 1024,
	.output_max_size = SIZE_MAX,
	.client = FALSE
};

static const struct connection_vfuncs master_admin_conn_vfuncs = {
	.destroy = master_admin_client_destroy,
	.input_args = master_admin_client_input_args
};

static void master_admin_client_initial_read(struct master_admin_client *client)
{
	struct ioloop *prev_ioloop = current_ioloop;
	client->wait_ioloop = io_loop_create();
	connection_switch_ioloop(&client->conn);
	struct timeout *to =
		timeout_add_short(100, io_loop_stop, client->wait_ioloop);

	io_loop_run(client->wait_ioloop);

	timeout_remove(&to);
	connection_switch_ioloop_to(&client->conn, prev_ioloop);
	io_loop_destroy(&client->wait_ioloop);
}

void master_admin_client_create(struct master_service_connection *master_conn)
{
	struct master_admin_client *client;

	if (master_admin_clients == NULL) {
		master_admin_clients =
			connection_list_init(&master_admin_conn_set,
					     &master_admin_conn_vfuncs);
	}

	client = i_new(struct master_admin_client, 1);
	client->refcount = 1;
	connection_init_server(master_admin_clients, &client->conn, master_conn->name,
			       master_conn->fd, master_conn->fd);
	if (master_service_get_client_limit(master_service) == 1) {
		/* client_limit=1 for this process, so this connection is
		   likely to be for KICK-USER-SIGNAL command. We're currently
		   blocking the SIGTERM, so try for a while to read the command
		   here. This way the command can be handled more reliably
		   instead of SIGTERM interrupting its handling too early. */
		master_admin_client_ref(client);
		master_admin_client_initial_read(client);
		master_admin_client_unref(&client);
	}
}

bool master_admin_client_can_accept(const char *name)
{
	return name != NULL && strcmp(name, "%{pid}") == 0;
}

void master_admin_clients_init(const struct master_admin_client_callback *callbacks)
{
	master_admin_client_callbacks = *callbacks;
}

void master_admin_clients_deinit(void)
{
	if (master_admin_clients != NULL)
		connection_list_deinit(&master_admin_clients);
}
