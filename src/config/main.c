/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "env-util.h"
#include "master-service.h"
#include "config-connection.h"
#include "config-parser.h"
#include "config-request.h"

#include <stdlib.h>
#include <unistd.h>

static void client_connected(const struct master_service_connection *conn)
{
	config_connection_create(conn->fd);
}

int main(int argc, char *argv[])
{
	int c;

	master_service = master_service_init("config", 0, argc, argv);
	while ((c = getopt(argc, argv, master_service_getopt_string())) > 0) {
		if (!master_service_parse_option(master_service, c, optarg))
			exit(FATAL_DEFAULT);
	}

	master_service_init_log(master_service, "config: ", 0);
	master_service_init_finish(master_service);
	config_parse_file(master_service_get_config_path(master_service), TRUE);

	master_service_run(master_service, client_connected);
	config_connections_destroy_all();
	master_service_deinit(&master_service);
        return 0;
}
