/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "event-log.h"
#include "doveadm-print.h"
#include "doveadm-settings.h"  //uses in doveadm_settings_get_config_fd()
#include "doveadm-cmd-parse.h" //uses in struct doveadm_cmd_ver2 doveadm_cmd_exec
#include "env-util.h"          //uses in env_put()
#include "execv-const.h"       //uses in execv_const(argv[0], argv)
#include "master-interface.h"  //uses in DOVECOT_CONFIG_FD_ENV
#include "config.h"            //uses in DOVECOT_ABI_VERSION

#include <getopt.h>
#include <unistd.h>

struct doveapiresponse {
	const char *endpoint;
	const char *result;
};

const char *doveadm_doveapi_plugin_version = DOVECOT_ABI_VERSION;

void doveadm_doveapi_plugin_init(struct module *module);
void doveadm_doveapi_plugin_deinit(void);

static void cmd_doveapi_test1(struct doveadm_cmd_context *cctx)
{
	int ret = 0;
	const struct doveapiresponse *response;

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("endpoint", "Endpoint", 0);
	doveadm_print_header("result", "Result", 0);
	doveadm_print("endpoint1");
	doveadm_print("result1");
	doveadm_print("endpoint2");
	doveadm_print("result2");
	if (FALSE) {
		e_error(cctx->event, "%s", "template error");
		doveadm_exit_code = EX_TEMPFAIL;
	}
	/*
	const char *path, *binary, *const *args, **argv;

	doveadm_cmd_param_str(cctx, "binary", &binary);
	if (!doveadm_cmd_param_array(cctx, "args", &args))
	        args = NULL;

	// Avoid re-executing doveconf after the binary is executed
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
	execv_const(argv[0], argv); */
}

static struct doveadm_cmd_ver2 doveapi_commands[] = {
	{ .name = "doveapi",
	  .cmd = cmd_doveapi_test1,
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
			  CMD_PARAM_FLAG_POSITIONAL) DOVEADM_CMD_PARAMS_END }
};

void doveadm_doveapi_plugin_init(struct module *module ATTR_UNUSED)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveapi_commands); i++)
		doveadm_cmd_register_ver2(&doveapi_commands[i]);
}

void doveadm_doveapi_plugin_deinit(void)
{
}
