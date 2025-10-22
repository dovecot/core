/* Copyright (c) 2025 R7-Office owners, author Talipov Ilja
 * [https://github.com/GromySkynet] */

#include "lib.h"
//  #include "array.h"
//  #include "str.h"
//  #include "sort.h"
//  #include "ostream.h"
#include "env-util.h"    //uses in env_put()
#include "execv-const.h" //uses in execv_const(argv[0], argv)
// #include "dict.h"
// #include "master-service-private.h" //uses in DOVECOT_CONFIG_FD_ENV
// Deprecated
#include "master-interface.h" //uses in DOVECOT_CONFIG_FD_ENV

// #include "master-service-settings.h"
// #include "settings-parser.h"
// #include "doveadm-print-private.h"
// #include "doveadm-dump.h"
// #include "doveadm-mail.h"
#include "doveadm-settings.h"  //uses in doveadm_settings_get_config_fd()
#include "doveadm-cmd-parse.h" //uses in struct doveadm_cmd_ver2 doveadm_cmd_exec
#include "doveadm-exec.h" //uses in void doveadm_register_cmdline_commands(void)
#include "doveadm-cmd.h"  // uses doveadm_cmd_register_ver2()
#include <getopt.h>
#include <unistd.h>

static void cmd_exec(struct doveadm_cmd_context *cctx)
{
	const char *path, *binary, *const *args, **argv;

	doveadm_cmd_param_str(cctx, "binary", &binary);
	if (!doveadm_cmd_param_array(cctx, "args", &args))
		args = NULL;

	/* Avoid re-executing doveconf after the binary is executed */
	int config_fd = doveadm_settings_get_config_fd();
	if (config_fd != -1) {
		fd_close_on_exec(config_fd, FALSE);
		env_put(DOVECOT_CONFIG_FD_ENV, dec2str(config_fd));
	}

	path = t_strdup_printf("%s/%s", doveadm_settings->libexec_dir, binary);

	unsigned int len = str_array_length(args);
	argv = t_new(const char *, len + 2);
	argv[0] = path;
	if (len > 0) {
		i_assert(args != NULL);
		memcpy(argv + 1, args, len * sizeof(args[0]));
	}
	execv_const(argv[0], argv);
}

struct doveadm_cmd_ver2 doveadm_cmd_exec = {
	.name = "exec",
	.cmd = cmd_exec,
	.usage = "<binary> [binary parameters]",
	.flags = CMD_FLAG_NO_OPTIONS,
	DOVEADM_CMD_PARAMS_START DOVEADM_CMD_PARAM(
		'\0',
		"binary",
		CMD_PARAM_STR,
		CMD_PARAM_FLAG_POSITIONAL)
		DOVEADM_CMD_PARAM(
			'\0',
			"args",
			CMD_PARAM_ARRAY,
			CMD_PARAM_FLAG_POSITIONAL) DOVEADM_CMD_PARAMS_END
};

struct doveadm_cmd_ver2 *doveadm_cmdline_ver2[] = {
	&doveadm_cmd_exec
	/*	&doveadm_cmd_config,
	&doveadm_cmd_dump,
	&doveadm_cmd_help,
	&doveadm_cmd_pw,
	&doveadm_cmd_compress_connect,
*/
};

// Регистрация команды в структуре команд
void doveadm_register_cmdline_commands(void)
{
	unsigned int i;
	for (i = 0; i < N_ELEMENTS(doveadm_cmdline_ver2); i++)
		doveadm_cmd_register_ver2(doveadm_cmdline_ver2[i]);
}