/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "doveadm.h"
#include "doveadm-dump.h"

#include <stdio.h>
#include <unistd.h>

static ARRAY_DEFINE(dumps, const struct doveadm_cmd_dump *);

void doveadm_dump_register(const struct doveadm_cmd_dump *dump)
{
	array_append(&dumps, &dump, 1);
}

static const struct doveadm_cmd_dump *
dump_find_name(const char *name)
{
	const struct doveadm_cmd_dump *const *dumpp;

	array_foreach(&dumps, dumpp) {
		if (strcmp((*dumpp)->name, name) == 0)
			return *dumpp;
	}
	return NULL;
}

static const struct doveadm_cmd_dump *
dump_find_test(const char *path)
{
	const struct doveadm_cmd_dump *const *dumpp;

	array_foreach(&dumps, dumpp) {
		if ((*dumpp)->test(path))
			return *dumpp;
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

static const struct doveadm_cmd_dump *dumps_builtin[] = {
	&doveadm_cmd_dump_index,
	&doveadm_cmd_dump_log,
	&doveadm_cmd_dump_mailboxlog,
	&doveadm_cmd_dump_thread
};

void doveadm_dump_init(void)
{
	unsigned int i;

	i_array_init(&dumps, N_ELEMENTS(dumps_builtin) + 8);
	for (i = 0; i < N_ELEMENTS(dumps_builtin); i++)
		doveadm_dump_register(dumps_builtin[i]);
}

void doveadm_dump_deinit(void)
{
	array_free(&dumps);
}
