/* Copyright (C) 2005-2008 Timo Sirainen */

#include "common.h"
#include "lib-signals.h"
#include "ioloop.h"
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
	const char *path, *service = "";
	bool dump_nondefaults = FALSE, human_readable = FALSE;
	int c;

	lib_init();

	path = getenv("CONFIG_FILE_PATH");
	if (path != NULL)
		config_path = path;

	while ((c = getopt(argc, argv, "c:s:na")) > 0) {
		switch (c) {
		case 'c':
			config_path = optarg;
			break;
		case 's':
			service = optarg;
			break;
		case 'n':
			dump_nondefaults = TRUE;
			/* fall through */
		case 'a':
			/* FIXME: make it work */
			human_readable = TRUE;
			break;
		default:
			i_fatal("Unknown parameter: %c", c);
		}
	}

	main_init(service);
	ioloop = io_loop_create();
	config_connection_dump_request(STDOUT_FILENO, "master");
	io_loop_destroy(&ioloop);
	lib_deinit();
        return 0;
}
