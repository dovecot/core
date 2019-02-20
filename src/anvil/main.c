/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "env-util.h"
#include "fdpass.h"
#include "ioloop.h"
#include "restrict-access.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "master-interface.h"
#include "connect-limit.h"
#include "penalty.h"
#include "anvil-connection.h"

#include <unistd.h>

struct connect_limit *connect_limit;
struct penalty *penalty;
bool anvil_restarted;
static struct io *log_fdpass_io;

static void client_connected(struct master_service_connection *conn)
{
	bool master = conn->listen_fd == MASTER_LISTEN_FD_FIRST;

	master_service_client_connection_accept(conn);
	(void)anvil_connection_create(conn->fd, master, conn->fifo);
}

static void ATTR_NULL(1)
log_fdpass_input(void *context ATTR_UNUSED)
{
	int fd;
	char c;
	ssize_t ret;

	/* master wants us to replace the log fd */
	ret = fd_read(MASTER_ANVIL_LOG_FDPASS_FD, &c, 1, &fd);
	if (ret < 0)
		i_error("fd_read(log fd) failed: %m");
	else if (ret == 0) {
		/* master died. lib-master should notice it soon. */
		io_remove(&log_fdpass_io);
	} else {
		if (dup2(fd, STDERR_FILENO) < 0)
			i_fatal("dup2(fd_read  log fd, stderr) failed: %m");
		if (close(fd) < 0)
			i_error("close(fd_read log fd) failed: %m");
	}
}

int main(int argc, char *argv[])
{
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_DONT_SEND_STATS |
		MASTER_SERVICE_FLAG_UPDATE_PROCTITLE;
	const char *error;

	master_service = master_service_init("anvil", service_flags,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;
	if (master_service_settings_read_simple(master_service,
						NULL, &error) < 0)
		i_fatal("Error reading configuration: %s", error);
	master_service_init_log(master_service, "anvil: ");

	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
	anvil_restarted = getenv("ANVIL_RESTARTED") != NULL;

	/* delay dying until all of our clients are gone */
	master_service_set_die_with_master(master_service, FALSE);

	connect_limit = connect_limit_init();
	penalty = penalty_init();
	log_fdpass_io = io_add(MASTER_ANVIL_LOG_FDPASS_FD, IO_READ,
			       log_fdpass_input, NULL);
	master_service_init_finish(master_service);

	master_service_run(master_service, client_connected);

	io_remove(&log_fdpass_io);
	penalty_deinit(&penalty);
	connect_limit_deinit(&connect_limit);
	anvil_connections_destroy_all();
	master_service_deinit(&master_service);
        return 0;
}
