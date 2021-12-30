/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "strescape.h"
#include "ipc-client.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>

struct proxy_context {
	struct ipc_client *ipc;
	const char *username_field;
	const char *kick_hosts;
};

extern struct doveadm_cmd_ver2 doveadm_cmd_proxy[];

static void proxy_cmd_help(struct doveadm_cmd_context *cctx) ATTR_NORETURN;

static struct proxy_context *
cmd_proxy_init(struct doveadm_cmd_context *cctx)
{
	struct proxy_context *ctx;
	const char *socket_path;

	ctx = t_new(struct proxy_context, 1);
	if (!doveadm_cmd_param_str(cctx, "socket-path", &socket_path)) {
		socket_path = t_strconcat(doveadm_settings->base_dir,
					  "/ipc", NULL);
	}
	(void)doveadm_cmd_param_str(cctx, "passdb-field", &ctx->username_field);
	(void)doveadm_cmd_param_str(cctx, "host", &ctx->kick_hosts);
	ctx->ipc = ipc_client_init(socket_path);
	return ctx;
}

static void cmd_proxy_list_header(const char *const *args)
{
	struct {
		const char *key;
		const char *title;
	} header_map[] = {
		{ "service", "proto" },
		{ "src-ip", "src ip" },
		{ "dest-ip", "dest ip" },
		{ "dest-port", "port" },
	};
	for (unsigned int i = 0; args[i] != NULL; i++) {
		const char *arg = args[i];

		if (strcmp(arg, "username") == 0 ||
		    str_begins(arg, "user_")) {
			doveadm_print_header(arg, arg,
					     DOVEADM_PRINT_HEADER_FLAG_EXPAND);
			continue;
		}
		const char *title = arg;
		for (unsigned int j = 0; j < N_ELEMENTS(header_map); j++) {
			if (strcmp(header_map[j].key, arg) == 0) {
				title = header_map[j].title;
				break;
			}
		}
		doveadm_print_header(arg, title, 0);
	}
}

static void cmd_proxy_list_callback(enum ipc_client_cmd_state state,
				    const char *data, void *context)
{
	bool *seen_header = context;

	switch (state) {
	case IPC_CLIENT_CMD_STATE_REPLY: {
		const char *const *args = t_strsplit_tabescaped(data);

		if (!*seen_header) {
			cmd_proxy_list_header(args);
			*seen_header = TRUE;
		} else {
			for (; *args != NULL; args++)
				doveadm_print(*args);
		}
		return;
	}
	case IPC_CLIENT_CMD_STATE_OK:
		break;
	case IPC_CLIENT_CMD_STATE_ERROR:
		i_error("LIST-FULL failed: %s", data);
		break;
	}
	io_loop_stop(current_ioloop);
}

static void cmd_proxy_list(struct doveadm_cmd_context *cctx)
{
	struct proxy_context *ctx;
	bool seen_header = FALSE;

	ctx = cmd_proxy_init(cctx);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);

	io_loop_set_running(current_ioloop);
	ipc_client_cmd(ctx->ipc, "proxy\t*\tLIST-FULL",
		       cmd_proxy_list_callback, &seen_header);
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

static void cmd_proxy_kick(struct doveadm_cmd_context *cctx)
{
	struct proxy_context *ctx;
	const char *const *users = NULL;
	string_t *cmd;

	ctx = cmd_proxy_init(cctx);
	(void)doveadm_cmd_param_array(cctx, "user", &users);
	if (users == NULL && ctx->kick_hosts == NULL) {
		proxy_cmd_help(cctx);
		return;
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_FORMATTED);
	doveadm_print_formatted_set_format("%{count} connections kicked\n");
	doveadm_print_header_simple("count");

	cmd = t_str_new(128);
	str_append(cmd, "proxy\t*\t");
	if (ctx->kick_hosts != NULL) {
		str_append(cmd, "KICK-HOST\t");
		str_append(cmd, ctx->kick_hosts);
	}
	else if (ctx->username_field == NULL)
		str_append(cmd, "KICK");
	else {
		str_append(cmd, "KICK-ALT\t");
		str_append_tabescaped(cmd, ctx->username_field);
	}
	if (users != NULL) {
		for (unsigned int i = 0; users[i] != NULL; i++) {
			str_append_c(cmd, '\t');
			str_append_tabescaped(cmd, users[i]);
		}
	}
	ipc_client_cmd(ctx->ipc, str_c(cmd), cmd_proxy_kick_callback, NULL);
	io_loop_run(current_ioloop);
	ipc_client_deinit(&ctx->ipc);
}

struct doveadm_cmd_ver2 doveadm_cmd_proxy[] = {
{
	.name = "proxy list",
	.usage = "[-a <ipc socket path>]",
	.cmd = cmd_proxy_list,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "proxy kick",
	.usage = "[-a <ipc socket path>] [-f <passdb field>] [-h <host> [...] | <user> [...]]",
	.cmd = cmd_proxy_kick,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('f', "passdb-field", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('h', "host", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
}
};

static void proxy_cmd_help(struct doveadm_cmd_context *cctx)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_proxy); i++) {
		if (doveadm_cmd_proxy[i].cmd == cctx->cmd->cmd)
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
