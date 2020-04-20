/* Copyright (c) 2014-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "imap-client.h"
#include "imap-hibernate-client.h"
#include "imap-master-connection.h"

static bool debug = FALSE;

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);
	imap_hibernate_client_create(conn->fd, debug);
}

int main(int argc, char *argv[])
{
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_UPDATE_PROCTITLE;
	const char *error;
	int c;

	master_service = master_service_init("imap-hibernate", service_flags,
					     &argc, &argv, "D");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			debug = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}

	if (master_service_settings_read_simple(master_service, NULL, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	master_service_init_log(master_service);
	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);

	imap_clients_init();
	imap_master_connections_init();
	imap_hibernate_clients_init();
	master_service_init_finish(master_service);

	master_service_run(master_service, client_connected);

	imap_master_connections_deinit();
	imap_hibernate_clients_deinit();
	imap_clients_deinit();
	master_service_deinit(&master_service);
        return 0;
}
