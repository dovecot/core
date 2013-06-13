/* Copyright (c) 2005-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "restrict-access.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "log-error-buffer.h"
#include "log-connection.h"
#include "doveadm-connection.h"

#include <unistd.h>

static struct log_error_buffer *errorbuf;

static void
sig_reopen_logs(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	master_service_init_log(master_service, "log: ");
}

static void main_init(void)
{
	lib_signals_set_handler(SIGUSR1, LIBSIG_FLAGS_SAFE,
				sig_reopen_logs, NULL);

	errorbuf = log_error_buffer_init();
	log_connections_init();
}

static void main_deinit(void)
{
	log_connections_deinit();
	log_error_buffer_deinit(&errorbuf);
}

static void client_connected(struct master_service_connection *conn)
{
	if (conn->fifo) {
		log_connection_create(errorbuf, conn->fd, conn->listen_fd);
		/* kludge: normally FIFOs aren't counted as connections,
		   but here we want log process to stay open until all writers
		   have closed */
		conn->fifo = FALSE;
	} else if (strcmp(conn->name, "log-errors") == 0)
		doveadm_connection_create(errorbuf, conn->fd);
	else {
		i_error("Unknown listener name: %s", conn->name);
		return;
	}

	master_service_client_connection_accept(conn);
}

int main(int argc, char *argv[])
{
	const char *error;

	master_service = master_service_init("log", 0, &argc, &argv, "");

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

	/* logging should never die if there are some clients */
	master_service_set_die_with_master(master_service, FALSE);

	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);
	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
