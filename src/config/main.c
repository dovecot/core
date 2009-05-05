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

static struct master_service *service;

static void main_init(const char *service_name)
{
	config_parse_file(master_service_get_config_path(service),
			  service_name);
}

static void client_connected(const struct master_service_connection *conn)
{
	config_connection_create(conn->fd);
}

int main(int argc, char *argv[])
{
	const char *getopt_str, *service_name = "";
	char **exec_args = NULL;
	int c;

	service = master_service_init("config", 0, argc, argv);

	getopt_str = t_strconcat("anp:e", master_service_getopt_string(), NULL);
	while ((c = getopt(argc, argv, getopt_str)) > 0) {
		if (c == 'e')
			break;
		switch (c) {
		case 'p':
			service_name = optarg;
			break;
		default:
			if (!master_service_parse_option(service, c, optarg))
				exit(FATAL_DEFAULT);
		}
	}
	if (argv[optind] != NULL)
		exec_args = &argv[optind];

	master_service_init_log(service, "doveconf: ", 0);
	master_service_init_finish(service);
	main_init(service_name);

	master_service_run(service, client_connected);
	config_connections_destroy_all();
	master_service_deinit(&service);
        return 0;
}
