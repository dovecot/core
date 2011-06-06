/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "log-connection.h"

#include <unistd.h>

static void
sig_reopen_logs(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	master_service_init_log(master_service, "log: ");
}

static void main_init(void)
{
	lib_signals_set_handler(SIGUSR1, LIBSIG_FLAGS_SAFE,
				sig_reopen_logs, NULL);

	log_connections_init();
}

static void main_deinit(void)
{
	log_connections_deinit();
}

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);
	log_connection_create(conn->fd, conn->listen_fd);
}

int main(int argc, char *argv[])
{
	const char *error;

	master_service = master_service_init("log", 0, &argc, &argv, NULL);

	/* use log prefix and log to stderr until we've configured the real
	   logging */
	i_set_failure_file("/dev/stderr", "log: ");

	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	if (master_service_settings_read_simple(master_service,
						NULL, &error) < 0)
		i_fatal("Error reading configuration: %s", error);
	master_service_init_log(master_service, "log: ");

	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);

	master_service_init_finish(master_service);

	/* logging should never die if there are some clients */
	master_service_set_die_with_master(master_service, FALSE);

	main_init();
	master_service_run(master_service, client_connected);
	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
