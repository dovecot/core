/* Copyright (C) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "env-util.h"
#include "str.h"
#include "config-connection.h"
#include "config-parser.h"

#include <stdlib.h>
#include <unistd.h>

string_t *config_string;
pool_t parsers_pool;

static const char *config_path = SYSCONFDIR "/" PACKAGE ".conf";

static void main_init(const char *service)
{
	if (getenv("LOG_TO_MASTER") != NULL)
		i_set_failure_internal();

	parsers_pool = pool_alloconly_create("parent parsers", 2048);
	config_parsers_fix_parents(parsers_pool);

	config_string = str_new(default_pool, 10240);
	config_parse_file(config_string, config_path, service);
	str_append_c(config_string, '\n');
}

int main(int argc, char *argv[])
{
	struct ioloop *ioloop;
	const char *service = "";
	char **exec_args = NULL;
	bool dump_nondefaults = FALSE, human_readable = FALSE;
	int i;

	lib_init();

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-a") == 0) {
			/* FIXME: make it work */
			human_readable = TRUE;
		} else if (strcmp(argv[i], "-c") == 0) {
			/* config file */
			i++;
			if (i == argc) i_fatal("Missing config file argument");
			config_path = argv[i];
		} else if (strcmp(argv[i], "-n") == 0) {
			dump_nondefaults = TRUE;
			human_readable = TRUE;
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
		config_connection_dump_request(STDOUT_FILENO, "master");
	else {
		config_connection_putenv();
		env_put("DOVECONF_ENV=1");
		execvp(exec_args[0], exec_args);
		i_fatal("execvp(%s) failed: %m", exec_args[0]);
	}
	io_loop_destroy(&ioloop);
	lib_deinit();
        return 0;
}
