/* Copyright (C) 2004 Joshua Goodall */

#include "lib.h"
#include "doveadm.h"
#include "doveadm-dump.h"

#include <stdio.h>
#include <unistd.h>

static const struct doveadm_cmd_dump *dumps[] = {
	&doveadm_cmd_dump_index,
	&doveadm_cmd_dump_log,
	&doveadm_cmd_dump_mailboxlog,
	&doveadm_cmd_dump_thread
};

static const struct doveadm_cmd_dump *
dump_find_name(const char *name)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(dumps); i++) {
		if (strcmp(dumps[i]->name, name) == 0)
			return dumps[i];
	}
	return NULL;
}

static const struct doveadm_cmd_dump *
dump_find_test(const char *path)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(dumps); i++) {
		if (dumps[i]->test(path))
			return dumps[i];
	}
	return NULL;
}

static void cmd_dump(int argc, char *argv[])
{
	const struct doveadm_cmd_dump *dump;
	const char *type = NULL;
	int c;

	while ((c = getopt(argc, argv, "t:")) > 0) {
		switch (c) {
		case 't':
			type = optarg;
			break;
		default:
			help(&doveadm_cmd_dump);
		}
	}
	if (optind == argc)
		help(&doveadm_cmd_dump);

	optind--;
	argc -= optind;
	argv += optind;

	dump = type != NULL ? dump_find_name(type) : dump_find_test(argv[1]);
	if (dump == NULL) {
		if (type != NULL)
			i_fatal("Unknown type: %s", type);
		else
			i_fatal("Can't autodetect file type: %s", argv[1]);
	} else {
		if (type == NULL)
			printf("Detected file type: %s\n", dump->name);
	}
	dump->cmd(argc, argv);
}

struct doveadm_cmd doveadm_cmd_dump = {
	cmd_dump, "dump", "[-t <type>] <path>"
};
