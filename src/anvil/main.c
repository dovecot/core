/* Copyright (C) 2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "env-util.h"
#include "master-service.h"
#include "master-interface.h"
#include "connect-limit.h"
#include "penalty.h"
#include "anvil-connection.h"

struct connect_limit *connect_limit;
struct penalty *penalty;

static void client_connected(const struct master_service_connection *conn)
{
	bool master = conn->listen_fd == MASTER_LISTEN_FD_FIRST;

	anvil_connection_create(conn->fd, master, conn->fifo);
}

int main(int argc, char *argv[])
{
	master_service = master_service_init("anvil", 0, &argc, &argv, NULL);
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	master_service_init_log(master_service, "anvil: ");
	master_service_init_finish(master_service);
	connect_limit = connect_limit_init();
	penalty = penalty_init();

	master_service_run(master_service, client_connected);

	penalty_deinit(&penalty);
	connect_limit_deinit(&connect_limit);
	anvil_connections_destroy_all();
	master_service_deinit(&master_service);
        return 0;
}
