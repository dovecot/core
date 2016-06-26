/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ostream.h"
#include "connection.h"
#include "service.h"
#include "service-monitor.h"
#include "master-client.h"

struct master_client {
	struct connection conn;
};

static int
master_client_stop(struct master_client *client, const char *const *args)
{
	struct service *service;
	const char *reply = "+\n";

	for (unsigned int i = 0; args[i] != NULL; i++) {
		service = service_lookup(services, args[i]);
		if (service == NULL)
			reply = t_strdup_printf("-Unknown service: %s\n", args[i]);
		else
			service_monitor_stop_close(service);
	}
	o_stream_send_str(client->conn.output, reply);
	return 1;
}

static int
master_client_input_args(struct connection *conn, const char *const *args)
{
	struct master_client *client = (struct master_client *)conn;
	const char *cmd = args[0];

	if (cmd == NULL) {
		i_error("%s: Empty command", conn->name);
		return 0;
	}
	args++;

	if (strcmp(cmd, "STOP") == 0)
		return master_client_stop(client, args);
	i_error("%s: Unknown command: %s", conn->name, cmd);
	return -1;
}

static void master_client_destroy(struct connection *conn)
{
	struct master_client *client = (struct master_client *)conn;

	connection_deinit(conn);
	i_free(client);
}

static const struct connection_settings master_conn_set = {
	.service_name_in = "master-client",
	.service_name_out = "master-server",
	.major_version = 1,
	.minor_version = 0,

	.input_max_size = 1024,
	.output_max_size = 1024,
	.client = FALSE
};

static const struct connection_vfuncs master_conn_vfuncs = {
	.destroy = master_client_destroy,
	.input_args = master_client_input_args
};

static struct connection_list *master_connections;

void master_client_connected(struct service_list *service_list)
{
	struct master_client *client;
	int fd;

	fd = net_accept(service_list->master_fd, NULL, NULL);
	if (fd < 0) {
		if (fd == -2)
			i_error("net_accept() failed: %m");
		return;
	}
	client = i_new(struct master_client, 1);
	connection_init_server(master_connections, &client->conn,
			       "master-client", fd, fd);
}

void master_clients_init(void)
{
	master_connections = connection_list_init(&master_conn_set,
						  &master_conn_vfuncs);
}

void master_clients_deinit(void)
{
	connection_list_deinit(&master_connections);
}
