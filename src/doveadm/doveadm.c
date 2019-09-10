/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "sort.h"
#include "ostream.h"
#include "env-util.h"
#include "execv-const.h"
#include "dict.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "master-service-ssl-settings.h"
#include "settings-parser.h"
#include "doveadm-print-private.h"
#include "doveadm-dump.h"
#include "doveadm-mail.h"
#include "doveadm-settings.h"
#include "doveadm-dsync.h"
#include "doveadm.h"

#include <unistd.h>

const struct doveadm_print_vfuncs *doveadm_print_vfuncs_all[] = {
	&doveadm_print_flow_vfuncs,
	&doveadm_print_tab_vfuncs,
	&doveadm_print_table_vfuncs,
	&doveadm_print_pager_vfuncs,
	&doveadm_print_json_vfuncs,
	&doveadm_print_formatted_vfuncs,
	NULL
};

bool doveadm_verbose_proctitle;
int doveadm_exit_code = 0;

static pool_t doveadm_settings_pool = NULL;

static void failure_exit_callback(int *status)
{
	enum fatal_exit_status fatal_status = *status;

	switch (fatal_status) {
	case FATAL_LOGWRITE:
	case FATAL_LOGERROR:
	case FATAL_LOGOPEN:
	case FATAL_OUTOFMEM:
	case FATAL_EXEC:
	case FATAL_DEFAULT:
		*status = EX_TEMPFAIL;
		break;
	}
}

static void
doveadm_usage_compress_lines(FILE *out, const char *str, const char *prefix)
{
	const char *cmd, *args, *p, *short_name, *sub_name;
	const char *prev_name = "", *prev_sub_name = "";
	const char **lines;
	unsigned int i, count;
	size_t prefix_len = strlen(prefix);

	/* split lines */
	lines = (void *)p_strsplit(pool_datastack_create(), str, "\n");
	for (count = 0; lines[count] != NULL; count++) ;

	/* sort lines */
	i_qsort(lines, count, sizeof(*lines), i_strcmp_p);

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
				prev_sub_name = "";
			} else {
				sub_name = t_strcut(p + 1, ' ');
				if (strcmp(prev_sub_name, sub_name) != 0) {
					fprintf(out, "|%s", sub_name);
					prev_sub_name = sub_name;
				}
			}
		}
	}
	if (*prev_name != '\0')
		fprintf(out, "\n");
}

static void ATTR_NORETURN
usage_to(FILE *out, const char *prefix)
{
	const struct doveadm_cmd_ver2 *cmd2;
	const struct doveadm_cmd *cmd;
	string_t *str = t_str_new(1024);

	fprintf(out, "usage: doveadm [-Dv] [-f <formatter>] ");
	if (*prefix != '\0')
		fprintf(out, "%s ", prefix);
	fprintf(out, "<command> [<args>]\n");

	array_foreach(&doveadm_cmds, cmd)
		str_printfa(str, "%s\t%s\n", cmd->name, cmd->short_usage);
	array_foreach(&doveadm_cmds_ver2, cmd2)
		str_printfa(str, "%s\t%s\n", cmd2->name, cmd2->usage);

	doveadm_mail_usage(str);
	doveadm_usage_compress_lines(out, str_c(str), prefix);

	exit(EX_USAGE);
}

void usage(void)
{
	usage_to(stderr, "");
}

static void ATTR_NORETURN
help_to(const struct doveadm_cmd *cmd, FILE *out)
{
	fprintf(out, "doveadm %s %s\n", cmd->name, cmd->short_usage);
	exit(EX_USAGE);
}

void help(const struct doveadm_cmd *cmd)
{
	help_to(cmd, stdout);
}

static void ATTR_NORETURN
help_to_ver2(const struct doveadm_cmd_ver2 *cmd, FILE *out)
{
	fprintf(out, "doveadm %s %s\n", cmd->name, cmd->usage);
	exit(EX_USAGE);
}

void help_ver2(const struct doveadm_cmd_ver2 *cmd)
{
	help_to_ver2(cmd, stdout);
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
	env_put(t_strconcat(MASTER_CONFIG_FILE_ENV"=",
		master_service_get_config_path(master_service), NULL));
	argv[0] = BINDIR"/doveconf";
	(void)execv(argv[0], argv);
	i_fatal("execv(%s) failed: %m", argv[0]);
}

static struct doveadm_cmd doveadm_cmd_config = {
	cmd_config, "config", "[doveconf parameters]"
};

static void cmd_exec(int argc ATTR_UNUSED, char *argv[]);
static struct doveadm_cmd doveadm_cmd_exec = {
	cmd_exec, "exec", "<binary> [binary parameters]"
};

static void cmd_exec(int argc ATTR_UNUSED, char *argv[])
{
	const char *path, *binary = argv[1];

	if (binary == NULL)
		help(&doveadm_cmd_exec);

	path = t_strdup_printf("%s/%s", doveadm_settings->libexec_dir, binary);
	argv++;
	argv[0] = t_strdup_noconst(path);
	(void)execv(argv[0], argv);
	i_fatal("execv(%s) failed: %m", argv[0]);
}

static bool doveadm_try_run(const char *cmd_name, int argc,
			    const char *const argv[])
{
	const struct doveadm_cmd *cmd;

	cmd = doveadm_cmd_find_with_args(cmd_name, &argc, &argv);
	if (cmd == NULL)
		return FALSE;
	cmd->cmd(argc, (char **)argv);
	return TRUE;
}

static bool doveadm_has_subcommands(const char *cmd_name)
{
	const struct doveadm_cmd_ver2 *cmd2;
	const struct doveadm_cmd *cmd;
	size_t len = strlen(cmd_name);

	array_foreach(&doveadm_cmds, cmd) {
		if (strncmp(cmd->name, cmd_name, len) == 0 &&
		    cmd->name[len] == ' ')
			return TRUE;
	}
	array_foreach(&doveadm_cmds_ver2, cmd2) {
		if (strncmp(cmd2->name, cmd_name, len) == 0 &&
		    cmd2->name[len] == ' ')
			return TRUE;
	}
	return doveadm_mail_has_subcommands(cmd_name);
}

static void doveadm_read_settings(void)
{
	static const struct setting_parser_info *set_roots[] = {
		&master_service_ssl_setting_parser_info,
		&doveadm_setting_parser_info,
		NULL
	};
	struct master_service_settings_input input;
	struct master_service_settings_output output;
	const struct doveadm_settings *set;
	const char *error;

	i_zero(&input);
	input.roots = set_roots;
	input.module = "doveadm";
	input.service = "doveadm";
	input.preserve_user = TRUE;
	input.preserve_home = TRUE;
	if (master_service_settings_read(master_service, &input,
					 &output, &error) < 0)
		i_fatal("Error reading configuration: %s", error);

	doveadm_settings_pool = pool_alloconly_create("doveadm settings", 1024);
	service_set = master_service_settings_get(master_service);
	service_set = settings_dup(&master_service_setting_parser_info,
				   service_set, doveadm_settings_pool);
	doveadm_verbose_proctitle = service_set->verbose_proctitle;

	set = master_service_settings_get_others(master_service)[1];
	doveadm_settings = settings_dup(&doveadm_setting_parser_info, set,
					doveadm_settings_pool);
	doveadm_ssl_set = settings_dup(&master_service_ssl_setting_parser_info,
				       master_service_ssl_settings_get(master_service),
				       doveadm_settings_pool);
	doveadm_settings->parsed_features = set->parsed_features; /* copy this value by hand */
}

static struct doveadm_cmd *doveadm_cmdline_commands[] = {
	&doveadm_cmd_help,
	&doveadm_cmd_config,
	&doveadm_cmd_exec,
	&doveadm_cmd_dump,
	&doveadm_cmd_pw,
	&doveadm_cmd_zlibconnect
};

int main(int argc, char *argv[])
{
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_STANDALONE |
		MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN |
		MASTER_SERVICE_FLAG_USE_SSL_SETTINGS |
		MASTER_SERVICE_FLAG_NO_SSL_INIT |
		MASTER_SERVICE_FLAG_NO_INIT_DATASTACK_FRAME;
	struct doveadm_cmd_context cctx;
	const char *cmd_name;
	unsigned int i;
	bool quick_init = FALSE;
	int c;

	i_zero(&cctx);
	cctx.conn_type = DOVEADM_CONNECTION_TYPE_CLI;

	i_set_failure_exit_callback(failure_exit_callback);
	doveadm_dsync_main(&argc, &argv);

	/* "+" is GNU extension to stop at the first non-option.
	   others just accept -+ option. */
	master_service = master_service_init("doveadm", service_flags,
					     &argc, &argv, "+Df:hv");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			doveadm_debug = TRUE;
			doveadm_verbose = TRUE;
			break;
		case 'f':
			doveadm_print_init(optarg);
			break;
		case 'h':
			doveadm_print_hide_titles = TRUE;
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
	master_service_init_log(master_service, "doveadm: ");

	doveadm_cmds_init();
	for (i = 0; i < N_ELEMENTS(doveadm_cmdline_commands); i++)
		doveadm_register_cmd(doveadm_cmdline_commands[i]);
	doveadm_register_auth_commands();
	doveadm_cmd_register_ver2(&doveadm_cmd_oldstats_top_ver2);

	if (cmd_name != NULL && (quick_init ||
				 strcmp(cmd_name, "config") == 0 ||
				 strcmp(cmd_name, "stop") == 0 ||
				 strcmp(cmd_name, "reload") == 0)) {
		/* special case commands: even if there is something wrong
		   with the config (e.g. mail_plugins), don't fail these
		   commands */
		quick_init = TRUE;
	} else {
		quick_init = FALSE;
		master_service_init_stats_client(master_service, TRUE);
		doveadm_print_ostream = o_stream_create_fd(STDOUT_FILENO, 0);
		o_stream_set_no_error_handling(doveadm_print_ostream, TRUE);
		doveadm_dump_init();
		doveadm_mail_init();
		dict_drivers_register_builtin();
		doveadm_load_modules();

		if (cmd_name == NULL) {
			/* show usage after registering all plugins */
			usage_to(stdout, "");
		}
	}

	argc -= optind;
	argv += optind;
	i_getopt_reset();

	master_service_init_finish(master_service);
	if (!doveadm_debug) {
		/* disable debugging unless -D is given */
		i_set_debug_file("/dev/null");
	}

	/* this has to be done here because proctitle hack can break
	   the env pointer */
	cctx.username = getenv("USER");

	if (!doveadm_cmd_try_run_ver2(cmd_name, argc, (const char**)argv, &cctx) &&
	    !doveadm_try_run(cmd_name, argc, (const char **)argv) &&
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
		dict_drivers_unregister_builtin();
		doveadm_print_deinit();
		o_stream_unref(&doveadm_print_ostream);
	}
	doveadm_cmds_deinit();
	pool_unref(&doveadm_settings_pool);
	master_service_deinit(&master_service);
	return doveadm_exit_code;
}
