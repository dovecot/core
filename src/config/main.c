/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "array.h"
#include "env-util.h"
#include "str.h"
#include "config-connection.h"
#include "config-parser.h"

#include <stdlib.h>
#include <unistd.h>

ARRAY_TYPE(const_string) config_strings;

static const char *config_path = SYSCONFDIR "/" PACKAGE ".conf";
static pool_t config_pool;

static void main_init(const char *service)
{
	if (getenv("LOG_TO_MASTER") != NULL)
		i_set_failure_internal();

	config_pool = pool_alloconly_create("config parser", 10240);
	p_array_init(&config_strings, config_pool, 256);
	config_parse_file(config_pool, &config_strings, config_path, service);
}

int main(int argc, char *argv[])
{
	enum config_dump_flags flags = 0;
	struct ioloop *ioloop;
	const char *service = "";
	char **exec_args = NULL;
	int i;

	lib_init();

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-a") == 0) {
			flags |= CONFIG_DUMP_FLAG_HUMAN |
				CONFIG_DUMP_FLAG_DEFAULTS;
		} else if (strcmp(argv[i], "-c") == 0) {
			/* config file */
			i++;
			if (i == argc) i_fatal("Missing config file argument");
			config_path = argv[i];
		} else if (strcmp(argv[i], "-n") == 0) {
			flags |= CONFIG_DUMP_FLAG_HUMAN;
		} else if (strcmp(argv[i], "-s") == 0) {
			/* service */
			i++;
			if (i == argc) i_fatal("Missing service argument");
			service = argv[i];
		} else if (strcmp(argv[i], "--exec") == 0) {
			/* <command> [<args>] */
			i++;
			if (i == argc) i_fatal("Missing exec binary argument");
			exec_args = &argv[i];
			break;
		} else {
			i_fatal("Unknown parameter: %s", argv[i]);
		}
	}

	main_init(service);
	ioloop = io_loop_create();
	if (exec_args == NULL)
		config_connection_dump_request(STDOUT_FILENO, "master", flags);
	else {
		config_connection_putenv();
		env_put("DOVECONF_ENV=1");
		execvp(exec_args[0], exec_args);
		i_fatal("execvp(%s) failed: %m", exec_args[0]);
	}
	pool_unref(&config_pool);
	io_loop_destroy(&ioloop);
	lib_deinit();
        return 0;
}
