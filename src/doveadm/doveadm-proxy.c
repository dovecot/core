/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

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

extern struct doveadm_cmd doveadm_cmd_proxy[];

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
			const char *const *args = t_strsplit(data, "\t");
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
	doveadm_print_header_simple("username");
	doveadm_print_header("service", "proto", 0);
	doveadm_print_header("src-ip", "src ip", 0);
	doveadm_print_header("dest-ip", "dest ip", 0);
	doveadm_print_header("dest-port", "port", 0);

	ipc_client_cmd(ctx->ipc, "proxy\t*\tLIST",
		       cmd_proxy_list_callback, NULL);
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
		printf("%s connections kicked\n", data);
		break;
	case IPC_CLIENT_CMD_STATE_ERROR:
		i_error("KICK failed: %s", data);
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

	ipc_client_cmd(ctx->ipc, t_strdup_printf("proxy\t*\tKICK\t%s", argv[optind]),
		       cmd_proxy_kick_callback, NULL);
	io_loop_run(current_ioloop);
	ipc_client_deinit(&ctx->ipc);
}

struct doveadm_cmd doveadm_cmd_proxy[] = {
	{ cmd_proxy_list, "proxy list",
	  "[-a <ipc socket path>]" },
	{ cmd_proxy_kick, "proxy kick",
	  "[-a <ipc socket path>] <user>" }
};

static void proxy_cmd_help(doveadm_command_t *cmd)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_proxy); i++) {
		if (doveadm_cmd_proxy[i].cmd == cmd)
			help(&doveadm_cmd_proxy[i]);
	}
	i_unreached();
}

void doveadm_register_proxy_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_proxy); i++)
		doveadm_register_cmd(&doveadm_cmd_proxy[i]);
}
