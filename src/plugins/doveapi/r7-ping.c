/* Copyright (c) 2025 R7-Office owners, author Talipov Ilja
 * [https://github.com/GromySkynet] */

#include "lib.h"
#include "module-dir.h"
#include "event-log.h"
#include "doveadm-print.h"
#include "doveadm-settings.h" //uses in doveadm_settings_get_config_fd()
#include "doveadm-cmd.h"      //uses in struct doveadm_cmd_ver2 doveadm_cmd_exec
#include "env-util.h"         //uses in env_put()
#include "execv-const.h"      //uses in execv_const(argv[0], argv)
#include "master-interface.h" //uses in DOVECOT_CONFIG_FD_ENV
#include "config.h"           //uses in DOVECOT_ABI_VERSION

#include <getopt.h>
#include <unistd.h>

void cmd_ping(struct doveadm_cmd_context *cctx);

void cmd_ping(struct doveadm_cmd_context *cctx)
{
	doveadm_print_init(DOVEADM_PRINT_TYPE_FORMATTED);
	doveadm_print_formatted_set_format("%{count}\n");
	doveadm_print_header_simple("ping");
	doveadm_print("pong");
	if (FALSE) {
		e_error(cctx->event, "%s", "template error");
		doveadm_exit_code = EX_TEMPFAIL;
	}
};

struct doveadm_cmd_ver2 r7_ping = {
	.name = "r7_ping",
	.cmd = cmd_ping,
	.usage = "",
	DOVEADM_CMD_PARAMS_START DOVEADM_CMD_PARAMS_END
};