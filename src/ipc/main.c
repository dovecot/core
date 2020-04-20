/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "ipc-group.h"
#include "ipc-connection.h"
#include "client.h"

static bool ipc_socket_is_client(const char *name)
{
	size_t len;

	if (strcmp(name, "ipc") == 0)
		return TRUE;

	len = strlen(name);
	if (len > 7 && strcmp(name + len - 7, "-client") == 0)
		return TRUE;
	return FALSE;
}

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);

	if (ipc_socket_is_client(conn->name))
		(void)client_create(conn->fd);
	else
		(void)ipc_connection_create(conn->listen_fd, conn->fd);
}

static void ipc_die(void)
{
	clients_destroy_all();
	ipc_groups_disconnect_all();
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_UPDATE_PROCTITLE;
	const char *error;

	master_service = master_service_init("ipc", service_flags,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;
	if (master_service_settings_read_simple(master_service,
						NULL, &error) < 0)
		i_fatal("Error reading configuration: %s", error);
	master_service_init_log(master_service);
	master_service_set_die_with_master(master_service, TRUE);
	master_service_set_die_callback(master_service, ipc_die);

	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
	ipc_groups_init();
	master_service_init_finish(master_service);

	master_service_run(master_service, client_connected);

	clients_destroy_all();
	ipc_groups_deinit();
	master_service_deinit(&master_service);
        return 0;
}
