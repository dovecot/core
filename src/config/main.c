/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "env-util.h"
#include "master-service.h"
#include "config-connection.h"
#include "config-parser.h"

#include <stdlib.h>
#include <unistd.h>

ARRAY_TYPE(const_string) config_strings;

static struct master_service *service;
static pool_t config_pool;

static void main_init(const char *service_name)
{
	config_pool = pool_alloconly_create("config parser", 10240);
	p_array_init(&config_strings, config_pool, 256);
	config_parse_file(config_pool, &config_strings,
			  master_service_get_config_path(service),
			  service_name);
}

static void client_connected(const struct master_service_connection *conn)
{
	config_connection_create(conn->fd);
}

int main(int argc, char *argv[])
{
	enum config_dump_flags flags = 0;
	const char *getopt_str, *service_name = "";
	char **exec_args = NULL;
	int c;

	service = master_service_init("config", 0, argc, argv);

	getopt_str = t_strconcat("anp:e", master_service_getopt_string(), NULL);
	while ((c = getopt(argc, argv, getopt_str)) > 0) {
		if (c == 'e')
			break;
		switch (c) {
		case 'a':
			flags |= CONFIG_DUMP_FLAG_HUMAN |
				CONFIG_DUMP_FLAG_DEFAULTS;
			break;
		case 'n':
			flags |= CONFIG_DUMP_FLAG_HUMAN;
			break;
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

	if (master_service_get_socket_count(service) > 0)
		master_service_run(service, client_connected);
	else if (exec_args == NULL)
		config_connection_dump_request(STDOUT_FILENO, "master", flags);
	else {
		config_connection_putenv();
		env_put("DOVECONF_ENV=1");
		execvp(exec_args[0], exec_args);
		i_fatal("execvp(%s) failed: %m", exec_args[0]);
	}
	config_connections_destroy_all();
	pool_unref(&config_pool);
	master_service_deinit(&service);
        return 0;
}
