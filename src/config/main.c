/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "restrict-access.h"
#include "master-service.h"
#include "config-connection.h"
#include "config-parser.h"
#include "config-request.h"

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);
	config_connection_create(conn->fd);
}

int main(int argc, char *argv[])
{
	const char *path, *error;

	master_service = master_service_init("config", 0, &argc, &argv, NULL);
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;
	master_service_init_log(master_service, "config: ");

	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);

	master_service_init_finish(master_service);
	config_parse_load_modules();

	path = master_service_get_config_path(master_service);
	if (config_parse_file(path, TRUE, "", &error) <= 0)
		i_fatal("%s", error);

	master_service_run(master_service, client_connected);
	config_connections_destroy_all();

	config_filter_deinit(&config_filter);
	module_dir_unload(&modules);
	master_service_deinit(&master_service);
        return 0;
}
