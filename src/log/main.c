/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "hostpid.h"
#include "restrict-access.h"
#include "master-interface.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "log-error-buffer.h"
#include "log-connection.h"
#include "doveadm-connection.h"

#include <unistd.h>

bool verbose_proctitle;
char *global_log_prefix;
static struct log_error_buffer *errorbuf;

static void
sig_reopen_logs(const siginfo_t *si ATTR_UNUSED, void *context ATTR_UNUSED)
{
	master_service->log_initialized = FALSE;
	master_service_init_log(master_service, global_log_prefix);
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
	i_free(global_log_prefix);
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
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_DONT_SEND_STATS;
	const char *error;

	master_service = master_service_init("log", service_flags,
					     &argc, &argv, "");

	/* use log prefix and log to stderr until we've configured the real
	   logging */
	global_log_prefix = i_strdup_printf("log(%s): ", my_pid);
	i_set_failure_file("/dev/stderr", global_log_prefix, 0600);

	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	if (master_service_settings_read_simple(master_service,
						NULL, &error) < 0)
		i_fatal("Error reading configuration: %s", error);
	master_service_init_log(master_service, global_log_prefix);

	verbose_proctitle = master_service_settings_get(master_service)->verbose_proctitle;

	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
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
