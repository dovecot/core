/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "lib-signals.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "log-connection.h"

#include <unistd.h>

pid_t master_pid;

static void
sig_reopen_logs(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	master_service_init_log(master_service, "log: ");
}

static void main_init(void)
{
	lib_signals_set_handler(SIGUSR1, TRUE, sig_reopen_logs, NULL);

	master_pid = getppid();
	log_connections_init();
}

static void main_deinit(void)
{
	log_connections_deinit();
}

static void client_connected(const struct master_service_connection *conn)
{
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
	master_service_init_finish(master_service);
	main_init();
	master_service_run(master_service, client_connected);
	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
