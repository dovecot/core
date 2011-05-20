/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "ipc-group.h"
#include "ipc-connection.h"
#include "client.h"

static bool ipc_socket_is_client(int listen_fd)
{
	const char *path, *name;

	if (net_getunixname(listen_fd, &path) < 0) {
		if (errno != ENOTSOCK)
			i_fatal("getunixname(%d) failed: %m", listen_fd);
		/* not a UNIX socket. let's just assume it's a client. */
		return TRUE;
	}

	name = strrchr(path, '/');
	if (name == NULL)
		name = path;
	else
		name++;
	return strcmp(name, "ipc") == 0;
}

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);

	if (ipc_socket_is_client(conn->listen_fd))
		(void)client_create(conn->fd);
	else
		(void)ipc_connection_create(conn->listen_fd, conn->fd);
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_UPDATE_PROCTITLE;
	const char *error;

	master_service = master_service_init("ipc", service_flags,
					     &argc, &argv, NULL);
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;
	if (master_service_settings_read_simple(master_service,
						NULL, &error) < 0)
		i_fatal("Error reading configuration: %s", error);
	master_service_init_log(master_service, "ipc: ");

	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);
	master_service_init_finish(master_service);
	ipc_groups_init();

	master_service_run(master_service, client_connected);

	clients_destroy_all();
	ipc_groups_deinit();
	master_service_deinit(&master_service);
        return 0;
}
