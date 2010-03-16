/* Copyright (c) 2009-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "module-dir.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "doveadm-mail.h"
#include "doveadm-settings.h"
#include "doveadm.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

bool doveadm_verbose = FALSE, doveadm_debug = FALSE;

static struct module *modules = NULL;
static ARRAY_DEFINE(doveadm_cmds, struct doveadm_cmd);

void doveadm_register_cmd(const struct doveadm_cmd *cmd)
{
	array_append(&doveadm_cmds, cmd, 1);
}

void usage(void)
{
	const struct doveadm_cmd *cmd;

	fprintf(stderr, "usage: doveadm\n");

	array_foreach(&doveadm_cmds, cmd) {
		fprintf(stderr, USAGE_CMDNAME_FMT" %s\n",
			cmd->name, cmd->short_usage);
	}
	doveadm_mail_usage();
	exit(1);
}

void help(const struct doveadm_cmd *cmd)
{
	fprintf(stderr, "doveadm %s %s\n", cmd->name, cmd->short_usage);
	if (cmd->long_usage != NULL)
		fprintf(stderr, "%s", cmd->long_usage);
	exit(0);
}

const char *unixdate2str(time_t timestamp)
{
	static char buf[64];
	struct tm *tm;

	tm = localtime(&timestamp);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm);
	return buf;
}

static void cmd_help(int argc ATTR_UNUSED, char *argv[])
{
	const struct doveadm_cmd *cmd;

	if (argv[1] == NULL)
		usage();
	array_foreach(&doveadm_cmds, cmd) {
		if (strcmp(cmd->name, argv[1]) == 0)
			help(cmd);
	}
	doveadm_mail_help_name(argv[1]);
	usage();
}

static struct doveadm_cmd doveadm_cmd_help = {
	cmd_help, "help", "<cmd>", NULL
};

static bool doveadm_try_run(const char *cmd_name, int argc, char *argv[])
{
	const struct doveadm_cmd *cmd;

	array_foreach(&doveadm_cmds, cmd) {
		if (strcmp(cmd_name, cmd->name) == 0) {
			cmd->cmd(argc, argv);
			return TRUE;
		}
	}
	return FALSE;
}

static void doveadm_load_modules(void)
{
	struct module_dir_load_settings mod_set;

	/* some doveadm plugins have dependencies to mail plugins. we can load
	   only those whose dependencies have been loaded earlier, the rest are
	   ignored. */
	memset(&mod_set, 0, sizeof(mod_set));
	mod_set.version = master_service_get_version_string(master_service);
	mod_set.require_init_funcs = TRUE;
	mod_set.debug = doveadm_debug;
	mod_set.ignore_dlopen_errors = TRUE;

	modules = module_dir_load_missing(modules, DOVEADM_MODULEDIR,
					  NULL, &mod_set);
	module_dir_init(modules);
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&doveadm_setting_parser_info,
		NULL
	};
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN;
	const char *cmd_name, *error;
	int c;

	/* "+" is GNU extension to stop at the first non-option.
	   others just accept -+ option. */
	master_service = master_service_init("doveadm", service_flags,
					     &argc, &argv, "+Dv");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			doveadm_debug = TRUE;
			doveadm_verbose = TRUE;
			break;
		case 'v':
			doveadm_verbose = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}

	if (master_service_settings_read_simple(master_service, set_roots,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);
	doveadm_settings = master_service_settings_get_others(master_service)[0];

	i_array_init(&doveadm_cmds, 32);
	doveadm_register_cmd(&doveadm_cmd_help);
	doveadm_register_cmd(&doveadm_cmd_auth);
	doveadm_register_cmd(&doveadm_cmd_user);
	doveadm_register_cmd(&doveadm_cmd_dump);
	doveadm_register_cmd(&doveadm_cmd_pw);
	doveadm_register_cmd(&doveadm_cmd_who);
	doveadm_register_cmd(&doveadm_cmd_penalty);
	doveadm_mail_init();
	doveadm_load_modules();

	if (optind == argc)
		usage();

	cmd_name = argv[optind];
	argc -= optind;
	argv += optind;
	optind = 1;

	master_service_init_finish(master_service);
	if (!doveadm_try_run(cmd_name, argc, argv) &&
	    !doveadm_mail_try_run(cmd_name, argc, argv))
		usage();

	doveadm_mail_deinit();
	module_dir_unload(&modules);
	array_free(&doveadm_cmds);
	master_service_deinit(&master_service);
	return 0;
}
