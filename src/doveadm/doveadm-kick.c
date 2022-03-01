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
	unsigned int kicked_count;
};

static void
kick_user_anvil_callback(const char *reply, struct kick_context *ctx)
{
	unsigned int count;

	if (reply != NULL) {
		if (str_to_uint(reply, &count) < 0)
			i_error("Unexpected reply from anvil: %s", reply);
		else
			ctx->kicked_count += count;
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

	struct ioloop *ioloop = io_loop_create();
	struct anvil_client *anvil =
		anvil_client_init(ctx->who.anvil_path, NULL, 0);
	if (anvil_client_connect(anvil, TRUE) < 0) {
		doveadm_exit_code = EX_TEMPFAIL;
		io_loop_destroy(&ioloop);
		return;
	}

	array_foreach(&ctx->kicks, session) {
		str_truncate(cmd, 0);
		if (ctx->who.filter.alt_username_field == NULL) {
			str_append(cmd, "KICK-USER\t");
			str_append_tabescaped(cmd, session->username);
			if (!guid_128_is_empty(session->conn_guid)) {
				str_append_c(cmd, '\t');
				str_append_tabescaped(cmd,
					guid_128_to_string(session->conn_guid));
			}
		} else {
			str_append(cmd, "KICK-ALT-USER\t");
			str_append_tabescaped(cmd, ctx->who.filter.alt_username_field);
			str_append_c(cmd, '\t');
			str_append_tabescaped(cmd, session->username);
		}

		anvil_client_query(anvil, str_c(cmd),
				   ANVIL_DEFAULT_KICK_TIMEOUT_MSECS,
				   kick_user_anvil_callback, ctx);
		io_loop_run(ioloop);
	}
	anvil_client_deinit(&anvil);
	io_loop_destroy(&ioloop);

	doveadm_print(dec2str(ctx->kicked_count));
}

static void cmd_kick(struct doveadm_cmd_context *cctx)
{
	const char *passdb_field, *dest_host, *const *masks = NULL;
	struct kick_context ctx;
	struct ip_addr dest_ip;

	i_zero(&ctx);
	if (!doveadm_cmd_param_str(cctx, "socket-path", &(ctx.who.anvil_path)))
		ctx.who.anvil_path = t_strconcat(doveadm_settings->base_dir, "/anvil", NULL);
	if (!doveadm_cmd_param_str(cctx, "passdb-field", &passdb_field))
		passdb_field = NULL;

	if (!doveadm_cmd_param_str(cctx, "dest-host", &dest_host))
		i_zero(&dest_ip);
	else if (net_addr2ip(dest_host, &dest_ip) < 0)
		i_fatal("dest-host isn't a valid IP address");

	if (!doveadm_cmd_param_array(cctx, "mask", &masks) &&
	    dest_ip.family == 0) {
		help_ver2(&doveadm_cmd_kick_ver2);
		return;
	}
	ctx.conn_type = cctx->conn_type;
	ctx.who.pool = pool_alloconly_create("kick pids", 10240);

	if (who_parse_args(&ctx.who, passdb_field, &dest_ip, masks) != 0) {
		pool_unref(&ctx.who.pool);
		return;
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_FORMATTED);
	doveadm_print_formatted_set_format("%{count} connections kicked\n");
	doveadm_print_header_simple("count");

	if (ctx.who.filter.net_bits == 0 &&
	    ctx.who.filter.dest_ip.family == 0 &&
	    strpbrk(ctx.who.filter.username, "*?") == NULL) {
		/* kick a single [alternative] user's all connections */
		p_array_init(&ctx.kicks, ctx.who.pool, 1);
		struct kick_session *session = array_append_space(&ctx.kicks);
		session->username = ctx.who.filter.username;
	} else {
		/* Complex kick filter. Iterate all connections and figure out
		   locally which ones to kick. */
		kick_users_get_via_who(&ctx);
	}
	kick_users_via_anvil(&ctx);

	pool_unref(&ctx.who.pool);
}

#define DOVEADM_CMD_KICK_FIELDS \
	.cmd = cmd_kick, \
	.usage = "[-a <anvil socket path>] [-f <passdb field>] [-h <dest host>] <user mask>[|]<ip/bits>", \
DOVEADM_CMD_PARAMS_START \
DOVEADM_CMD_PARAM('a',"socket-path",CMD_PARAM_STR,0) \
DOVEADM_CMD_PARAM('f',"passdb-field",CMD_PARAM_STR,0) \
DOVEADM_CMD_PARAM('h',"dest-host",CMD_PARAM_STR,0) \
DOVEADM_CMD_PARAM('\0',"mask",CMD_PARAM_ARRAY,CMD_PARAM_FLAG_POSITIONAL) \
DOVEADM_CMD_PARAMS_END

struct doveadm_cmd_ver2 doveadm_cmd_kick_ver2 = {
	.name = "kick",
	DOVEADM_CMD_KICK_FIELDS
};
struct doveadm_cmd_ver2 doveadm_cmd_proxy_kick_ver2 = {
	.name = "proxy kick",
	DOVEADM_CMD_KICK_FIELDS
};
