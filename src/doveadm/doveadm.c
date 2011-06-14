/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "env-util.h"
#include "execv-const.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "settings-parser.h"
#include "doveadm-print-private.h"
#include "doveadm-dump.h"
#include "doveadm-mail.h"
#include "doveadm-settings.h"
#include "doveadm.h"

#include <stdlib.h>
#include <unistd.h>

const struct doveadm_print_vfuncs *doveadm_print_vfuncs_all[] = {
	&doveadm_print_flow_vfuncs,
	&doveadm_print_tab_vfuncs,
	&doveadm_print_table_vfuncs,
	&doveadm_print_pager_vfuncs,
	NULL
};

static ARRAY_DEFINE(doveadm_cmds, struct doveadm_cmd);

void doveadm_register_cmd(const struct doveadm_cmd *cmd)
{
	array_append(&doveadm_cmds, cmd, 1);
}

static void
doveadm_usage_compress_lines(FILE *out, const char *str, const char *prefix)
{
	const char *cmd, *args, *p, *short_name, *prev_name = "";
	char **lines;
	unsigned int i, count, prefix_len = strlen(prefix);

	/* split lines */
	lines = p_strsplit(pool_datastack_create(), str, "\n");
	for (count = 0; lines[count] != NULL; count++) ;

	/* sort lines */
	qsort(lines, count, sizeof(*lines), i_strcmp_p);

	/* print lines, compress subcommands into a single line */
	for (i = 0; i < count; i++) {
		args = strchr(lines[i], '\t');
		if (args == NULL) {
			cmd = lines[i];
			args = "";
		} else {
			cmd = t_strdup_until(lines[i], args);
			args++;
		}
		if (*prefix != '\0') {
			if (strncmp(cmd, prefix, prefix_len) != 0 ||
			    cmd[prefix_len] != ' ')
				continue;
			cmd += prefix_len + 1;
		}

		p = strchr(cmd, ' ');
		if (p == NULL) {
			if (*prev_name != '\0') {
				fprintf(out, "\n");
				prev_name = "";
			}
			fprintf(out, USAGE_CMDNAME_FMT" %s\n", cmd, args);
		} else {
			short_name = t_strdup_until(cmd, p);
			if (strcmp(prev_name, short_name) != 0) {
				if (*prev_name != '\0')
					fprintf(out, "\n");
				fprintf(out, USAGE_CMDNAME_FMT" %s",
					short_name, t_strcut(p + 1, ' '));
				prev_name = short_name;
			} else {
				fprintf(out, "|%s", t_strcut(p + 1, ' '));
			}
		}
	}
	if (*prev_name != '\0')
		fprintf(out, "\n");
}

static void ATTR_NORETURN
usage_to(FILE *out, const char *prefix)
{
	const struct doveadm_cmd *cmd;
	string_t *str = t_str_new(1024);

	fprintf(out, "usage: doveadm [-Dv] [-f <formatter>] ");
	if (*prefix != '\0')
		fprintf(out, "%s ", prefix);
	fprintf(out, "<command> [<args>]\n");

	array_foreach(&doveadm_cmds, cmd)
		str_printfa(str, "%s\t%s\n", cmd->name, cmd->short_usage);

	doveadm_mail_usage(str);
	doveadm_usage_compress_lines(out, str_c(str), prefix);

	exit(1);
}

void usage(void)
{
	usage_to(stderr, "");
}

static void ATTR_NORETURN
help_to(const struct doveadm_cmd *cmd, FILE *out)
{
	fprintf(out, "doveadm %s %s\n", cmd->name, cmd->short_usage);
	exit(1);
}

void help(const struct doveadm_cmd *cmd)
{
	help_to(cmd, stdout);
}

static void cmd_help(int argc ATTR_UNUSED, char *argv[])
{
	const char *man_argv[3];

	if (argv[1] == NULL)
		usage_to(stdout, "");

	env_put("MANPATH="MANDIR);
	man_argv[0] = "man";
	man_argv[1] = t_strconcat("doveadm-", argv[1], NULL);
	man_argv[2] = NULL;
	execvp_const(man_argv[0], man_argv);
}

static struct doveadm_cmd doveadm_cmd_help = {
	cmd_help, "help", "<cmd>"
};

static void cmd_config(int argc ATTR_UNUSED, char *argv[])
{
	argv[0] = BINDIR"/doveconf";
	(void)execv(argv[0], argv);
	i_fatal("execv(%s) failed: %m", argv[0]);
}

static struct doveadm_cmd doveadm_cmd_config = {
	cmd_config, "config", "[doveconf parameters]"
};

static bool
doveadm_try_run_multi_word(const struct doveadm_cmd *cmd,
			   const char *cmdname, int argc, char *argv[])
{
	unsigned int len;

	if (argc < 2)
		return FALSE;

	len = strlen(argv[1]);
	if (strncmp(cmdname, argv[1], len) != 0)
		return FALSE;

	if (cmdname[len] == ' ') {
		/* more args */
		return doveadm_try_run_multi_word(cmd, cmdname + len + 1,
						  argc - 1, argv + 1);
	}
	if (cmdname[len] != '\0')
		return FALSE;

	/* match */
	cmd->cmd(argc - 1, argv + 1);
	return TRUE;
}

static bool doveadm_try_run(const char *cmd_name, int argc, char *argv[])
{
	const struct doveadm_cmd *cmd;
	unsigned int cmd_name_len;

	i_assert(argc > 0);

	cmd_name_len = strlen(cmd_name);
	array_foreach(&doveadm_cmds, cmd) {
		if (strcmp(cmd->name, cmd_name) == 0) {
			cmd->cmd(argc, argv);
			return TRUE;
		}

		/* see if it matches a multi-word command */
		if (strncmp(cmd->name, cmd_name, cmd_name_len) == 0 &&
		    cmd->name[cmd_name_len] == ' ') {
			const char *subcmd = cmd->name + cmd_name_len + 1;

			if (doveadm_try_run_multi_word(cmd, subcmd,
						       argc, argv))
				return TRUE;
		}
	}

	return FALSE;
}

static bool doveadm_has_subcommands(const char *cmd_name)
{
	const struct doveadm_cmd *cmd;
	unsigned int len = strlen(cmd_name);

	array_foreach(&doveadm_cmds, cmd) {
		if (strncmp(cmd->name, cmd_name, len) == 0 &&
		    cmd->name[len] == ' ')
			return TRUE;
	}
	return doveadm_mail_has_subcommands(cmd_name);
}

static void doveadm_read_settings(void)
{
	static const struct setting_parser_info *set_roots[] = {
		&doveadm_setting_parser_info,
		NULL
	};
	struct master_service_settings_input input;
	struct master_service_settings_output output;
	const struct doveadm_settings *set;
	const char *error;

	memset(&input, 0, sizeof(input));
	input.roots = set_roots;
	input.module = "doveadm";
	input.preserve_user = TRUE;
	input.preserve_home = TRUE;
	if (master_service_settings_read(master_service, &input,
					 &output, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	set = master_service_settings_get_others(master_service)[0];
	doveadm_settings = settings_dup(&doveadm_setting_parser_info, set,
					pool_datastack_create());
}

static struct doveadm_cmd *doveadm_commands[] = {
	&doveadm_cmd_help,
	&doveadm_cmd_config,
	&doveadm_cmd_stop,
	&doveadm_cmd_reload,
	&doveadm_cmd_auth,
	&doveadm_cmd_user,
	&doveadm_cmd_dump,
	&doveadm_cmd_pw,
	&doveadm_cmd_who,
	&doveadm_cmd_penalty,
	&doveadm_cmd_kick,
	&doveadm_cmd_mailbox_mutf7,
	&doveadm_cmd_sis_deduplicate,
	&doveadm_cmd_sis_find
};

int main(int argc, char *argv[])
{
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN;
	const char *cmd_name;
	unsigned int i;
	bool quick_init = FALSE;
	int c;

	/* "+" is GNU extension to stop at the first non-option.
	   others just accept -+ option. */
	master_service = master_service_init("doveadm", service_flags,
					     &argc, &argv, "+Df:v");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			doveadm_debug = TRUE;
			doveadm_verbose = TRUE;
			break;
		case 'f':
			doveadm_print_init(optarg);
			break;
		case 'v':
			doveadm_verbose = TRUE;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}
	cmd_name = argv[optind];

	if (cmd_name != NULL && strcmp(cmd_name, "help") == 0 &&
	    argv[optind+1] != NULL) {
		/* "help cmd" doesn't need any configuration */
		quick_init = TRUE;
	} else {
		doveadm_read_settings();
	}

	i_array_init(&doveadm_cmds, 32);
	for (i = 0; i < N_ELEMENTS(doveadm_commands); i++)
		doveadm_register_cmd(doveadm_commands[i]);

	if (cmd_name != NULL && (quick_init ||
				 strcmp(cmd_name, "stop") == 0 ||
				 strcmp(cmd_name, "reload") == 0)) {
		/* special case commands: even if there is something wrong
		   with the config (e.g. mail_plugins), don't fail these
		   commands */
		quick_init = TRUE;
	} else {
		quick_init = FALSE;
		doveadm_register_director_commands();
		doveadm_register_proxy_commands();
		doveadm_register_log_commands();
		doveadm_dump_init();
		doveadm_mail_init();
		doveadm_load_modules();

		if (cmd_name == NULL) {
			/* show usage after registering all plugins */
			usage_to(stdout, "");
		}
	}

	argc -= optind;
	argv += optind;
#ifdef __GLIBC__
	/* for subcommands allow -options anywhere in command line */
	optind = 0;
#else
	optind = 1;
#endif

	master_service_init_finish(master_service);
	if (!doveadm_debug) {
		/* disable debugging unless -D is given */
		i_set_debug_file("/dev/null");
	}

	if (!doveadm_try_run(cmd_name, argc, argv) &&
	    !doveadm_mail_try_run(cmd_name, argc, argv)) {
		if (doveadm_has_subcommands(cmd_name))
			usage_to(stdout, cmd_name);
		if (doveadm_has_unloaded_plugin(cmd_name)) {
			i_fatal("Unknown command '%s', but plugin %s exists. "
				"Try to set mail_plugins=%s",
				cmd_name, cmd_name, cmd_name);
		}
		usage();
	}

	if (!quick_init) {
		doveadm_mail_deinit();
		doveadm_dump_deinit();
		doveadm_unload_modules();
		doveadm_print_deinit();
	}
	array_free(&doveadm_cmds);
	master_service_deinit(&master_service);
	return 0;
}
