/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "str.h"
#include "ioloop.h"
#include "strescape.h"
#include "anvil-client.h"
#include "doveadm.h"
#include "doveadm-who.h"
#include "doveadm-print.h"

#include <stdio.h>

struct kick_session {
	const char *username;
	guid_128_t conn_guid;
};

struct kick_context {
	struct who_context who;
	enum doveadm_client_type conn_type;
	ARRAY(struct kick_session) kicks;
	ARRAY(const char *) kicked_users;

	bool kicked;
};

static void kick_print_kicked(struct kick_context *ctx)
{
	unsigned int i, count;
	const char *const *users;
	bool cli = (ctx->conn_type == DOVEADM_CONNECTION_TYPE_CLI);

	if (array_count(&ctx->kicked_users) == 0) {
		if (cli)
			printf("no users kicked\n");
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
		return;
	}

	if (cli)
		printf("kicked connections from the following users:\n");

	array_sort(&ctx->kicked_users, i_strcmp_p);
	users = array_get(&ctx->kicked_users, &count);
	doveadm_print(users[0]);
	for (i = 1; i < count; i++) {
		if (strcmp(users[i-1], users[i]) != 0)
			doveadm_print(users[i]);
	}

	doveadm_print_flush();

	if (cli)
		printf("\n");
}

static void kick_user_anvil_callback(const char *reply, void *context)
{
	struct kick_context *ctx = context;
	unsigned int count;

	if (reply != NULL) {
		if (str_to_uint(reply, &count) < 0)
			i_error("Unexpected reply from anvil: %s", reply);
		else if (count > 0)
			ctx->kicked = TRUE;
	}
	io_loop_stop(current_ioloop);
}

static void kick_users_get_via_who(struct kick_context *ctx)
{
	/* get a list of all user+sessions matching the filter */
	p_array_init(&ctx->kicks, ctx->who.pool, 64);
	struct doveadm_who_iter *iter =
		doveadm_who_iter_init(ctx->who.anvil_path);
	if (!doveadm_who_iter_init_filter(iter, &ctx->who.filter)) {
		doveadm_who_iter_deinit(&iter);
		return;
	}
	struct who_line who_line;
	while (doveadm_who_iter_next(iter, &who_line)) {
		if (!who_line_filter_match(&who_line, &ctx->who.filter))
			continue;
		struct kick_session *session = array_append_space(&ctx->kicks);
		session->username = p_strdup(ctx->who.pool, who_line.username);
		guid_128_copy(session->conn_guid, who_line.conn_guid);
	}
	if (doveadm_who_iter_deinit(&iter) < 0)
		doveadm_exit_code = EX_TEMPFAIL;
}

static void kick_users_via_anvil(struct kick_context *ctx)
{
	const struct kick_session *session;
	string_t *cmd = t_str_new(128);

	struct anvil_client *anvil =
		anvil_client_init(ctx->who.anvil_path, NULL, 0);
	if (anvil_client_connect(anvil, TRUE) < 0) {
		doveadm_exit_code = EX_TEMPFAIL;
		return;
	}

	p_array_init(&ctx->kicked_users, ctx->who.pool,
		     array_count(&ctx->kicks));

	array_foreach(&ctx->kicks, session) {
		str_truncate(cmd, 0);
		str_append(cmd, "KICK-USER\t");
		str_append_tabescaped(cmd, session->username);
		str_append_c(cmd, '\t');
		str_append_tabescaped(cmd, guid_128_to_string(session->conn_guid));

		ctx->kicked = FALSE;
		anvil_client_query(anvil, str_c(cmd),
				   kick_user_anvil_callback, ctx);
		io_loop_run(current_ioloop);
		if (ctx->kicked)
			array_push_back(&ctx->kicked_users, &session->username);
	}
	anvil_client_deinit(&anvil);

	kick_print_kicked(ctx);
}

static void cmd_kick(struct doveadm_cmd_context *cctx)
{
	const char *passdb_field, *const *masks;
	struct kick_context ctx;

	i_zero(&ctx);
	if (!doveadm_cmd_param_str(cctx, "socket-path", &(ctx.who.anvil_path)))
		ctx.who.anvil_path = t_strconcat(doveadm_settings->base_dir, "/anvil", NULL);
	if (!doveadm_cmd_param_str(cctx, "passdb-field", &passdb_field))
		passdb_field = NULL;
	if (!doveadm_cmd_param_array(cctx, "mask", &masks)) {
		doveadm_exit_code = EX_USAGE;
		i_error("user and/or ip[/bits] must be specified.");
		return;
	}
	ctx.conn_type = cctx->conn_type;
	ctx.who.pool = pool_alloconly_create("kick pids", 10240);

	if (who_parse_args(&ctx.who, passdb_field, masks) != 0) {
		pool_unref(&ctx.who.pool);
		return;
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_FORMATTED);
	doveadm_print_formatted_set_format("%{result} ");
	doveadm_print_header_simple("result");

	kick_users_get_via_who(&ctx);
	kick_users_via_anvil(&ctx);

	pool_unref(&ctx.who.pool);
}

struct doveadm_cmd_ver2 doveadm_cmd_kick_ver2 = {
	.name = "kick",
	.cmd = cmd_kick,
	.usage = "[-a <anvil socket path>] [-f <passdb field>] <user mask>[|]<ip/bits>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a',"socket-path",CMD_PARAM_STR,0)
DOVEADM_CMD_PARAM('f',"passdb-field",CMD_PARAM_STR,0)
DOVEADM_CMD_PARAM('\0',"mask",CMD_PARAM_ARRAY,CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
