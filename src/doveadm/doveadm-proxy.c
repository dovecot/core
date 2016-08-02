/* Copyright (c) 2011-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "ipc-client.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>

struct proxy_context {
	struct ipc_client *ipc;
};

extern struct doveadm_cmd_ver2 doveadm_cmd_proxy[];

static void proxy_cmd_help(doveadm_command_t *cmd) ATTR_NORETURN;

static struct proxy_context *
cmd_proxy_init(int argc, char *argv[], const char *getopt_args,
	       doveadm_command_t *cmd)
{
	struct proxy_context *ctx;
	const char *socket_path;
	int c;

	ctx = t_new(struct proxy_context, 1);
	socket_path = t_strconcat(doveadm_settings->base_dir, "/ipc", NULL);

	while ((c = getopt(argc, argv, getopt_args)) > 0) {
		switch (c) {
		case 'a':
			socket_path = optarg;
			break;
		default:
			proxy_cmd_help(cmd);
		}
	}
	ctx->ipc = ipc_client_init(socket_path);
	return ctx;
}

static void cmd_proxy_list_callback(enum ipc_client_cmd_state state,
				    const char *data, void *context ATTR_UNUSED)
{
	switch (state) {
	case IPC_CLIENT_CMD_STATE_REPLY:
		T_BEGIN {
			const char *const *args = t_strsplit_tab(data);
			for (; *args != NULL; args++)
				doveadm_print(*args);
		} T_END;
		return;
	case IPC_CLIENT_CMD_STATE_OK:
		break;
	case IPC_CLIENT_CMD_STATE_ERROR:
		i_error("LIST failed: %s", data);
		break;
	}
	io_loop_stop(current_ioloop);
}

static void cmd_proxy_list(int argc, char *argv[])
{
	struct proxy_context *ctx;

	ctx = cmd_proxy_init(argc, argv, "a:", cmd_proxy_list);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("username", "username", DOVEADM_PRINT_HEADER_FLAG_EXPAND);
	doveadm_print_header("service", "proto", 0);
	doveadm_print_header("src-ip", "src ip", 0);
	doveadm_print_header("dest-ip", "dest ip", 0);
	doveadm_print_header("dest-port", "port", 0);

	io_loop_set_running(current_ioloop);
	ipc_client_cmd(ctx->ipc, "proxy\t*\tLIST",
		       cmd_proxy_list_callback, NULL);
	if (io_loop_is_running(current_ioloop))
		io_loop_run(current_ioloop);
	ipc_client_deinit(&ctx->ipc);
}

static void cmd_proxy_kick_callback(enum ipc_client_cmd_state state,
				    const char *data, void *context ATTR_UNUSED)
{
	switch (state) {
	case IPC_CLIENT_CMD_STATE_REPLY:
		return;
	case IPC_CLIENT_CMD_STATE_OK:
		if (data[0] == '\0')
			data = "0";
		doveadm_print(data);
		break;
	case IPC_CLIENT_CMD_STATE_ERROR:
		i_error("KICK failed: %s", data);
		doveadm_exit_code = EX_TEMPFAIL;
		break;
	}
	io_loop_stop(current_ioloop);
}

static void cmd_proxy_kick(int argc, char *argv[])
{
	struct proxy_context *ctx;

	ctx = cmd_proxy_init(argc, argv, "a:", cmd_proxy_kick);

	if (argv[optind] == NULL) {
		proxy_cmd_help(cmd_proxy_kick);
		return;
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_FORMATTED);
	doveadm_print_formatted_set_format("%{count} connections kicked");
	doveadm_print_header_simple("count");
	ipc_client_cmd(ctx->ipc, t_strdup_printf("proxy\t*\tKICK\t%s", argv[optind]),
		       cmd_proxy_kick_callback, NULL);
	io_loop_run(current_ioloop);
	ipc_client_deinit(&ctx->ipc);
}

struct doveadm_cmd_ver2 doveadm_cmd_proxy[] = {
{
	.name = "proxy list",
	.usage = "[-a <ipc socket path>]",
	.old_cmd = cmd_proxy_list,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "proxy kick",
	.usage = "[-a <ipc socket path>] <user>",
	.old_cmd = cmd_proxy_kick,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
}
};

static void proxy_cmd_help(doveadm_command_t *cmd)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_proxy); i++) {
		if (doveadm_cmd_proxy[i].old_cmd == cmd)
			help_ver2(&doveadm_cmd_proxy[i]);
	}
	i_unreached();
}

void doveadm_register_proxy_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_proxy); i++)
		doveadm_cmd_register_ver2(&doveadm_cmd_proxy[i]);
}
