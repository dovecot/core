/* Copyright (C) 2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "env-util.h"
#include "master-service.h"
#include "connect-limit.h"
#include "anvil-connection.h"

#include <stdlib.h>
#include <unistd.h>

struct connect_limit *connect_limit;

static struct master_service *service;

static void client_connected(const struct master_service_connection *conn)
{
	anvil_connection_create(conn->fd);
}

int main(int argc, char *argv[])
{
	int c;

	service = master_service_init("anvil", 0, argc, argv);
	while ((c = getopt(argc, argv, master_service_getopt_string())) > 0) {
		if (!master_service_parse_option(service, c, optarg))
			exit(FATAL_DEFAULT);
	}

	master_service_init_log(service, "anvil: ", 0);
	master_service_init_finish(service);
	connect_limit = connect_limit_init();

	master_service_run(service, client_connected);

	connect_limit_deinit(&connect_limit);
	anvil_connections_destroy_all();
	master_service_deinit(&service);
        return 0;
}
