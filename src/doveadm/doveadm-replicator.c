/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "strescape.h"
#include "istream.h"
#include "write-full.h"
#include "master-service.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

struct replicator_context {
	const char *socket_path;
	const char *priority;
	const char *user_mask, *username;
	struct istream *input;
	bool full_sync;
};

extern struct doveadm_cmd_ver2 doveadm_cmd_replicator[];

static void replicator_cmd_help(const struct doveadm_cmd_ver2 *cmd) ATTR_NORETURN;

static void
replicator_send(struct replicator_context *ctx, const char *data)
{
	if (write_full(i_stream_get_fd(ctx->input), data, strlen(data)) < 0)
		i_fatal("write(%s) failed: %m", ctx->socket_path);
}

static void replicator_connect(struct replicator_context *ctx)
{
#define REPLICATOR_HANDSHAKE "VERSION\treplicator-doveadm-client\t1\t0\n"
	const char *line;
	int fd;

	fd = doveadm_connect(ctx->socket_path);
	net_set_nonblock(fd, FALSE);

	ctx->input = i_stream_create_fd_autoclose(&fd, SIZE_MAX);
	replicator_send(ctx, REPLICATOR_HANDSHAKE);

	alarm(5);
	line = i_stream_read_next_line(ctx->input);
	alarm(0);
	if (line == NULL) {
		if (ctx->input->stream_errno != 0) {
			i_fatal("read(%s) failed: %s", ctx->socket_path,
				i_stream_get_error(ctx->input));
		} else if (ctx->input->eof)
			i_fatal("%s disconnected", ctx->socket_path);
		else
			i_fatal("read(%s) timed out", ctx->socket_path);
	}
	if (!version_string_verify(line, "replicator-doveadm-server", 1)) {
		i_fatal_status(EX_PROTOCOL,
			       "%s not a compatible replicator-doveadm socket",
			       ctx->socket_path);
	}
}

static void replicator_disconnect(struct replicator_context *ctx)
{
	if (ctx->input->stream_errno != 0) {
		i_fatal("read(%s) failed: %s", ctx->socket_path,
			i_stream_get_error(ctx->input));
	}
	i_stream_destroy(&ctx->input);
}

static struct replicator_context *
cmd_replicator_init(struct doveadm_cmd_context *cctx)
{
	struct replicator_context *ctx;

	ctx = t_new(struct replicator_context, 1);
	ctx->socket_path = t_strconcat(doveadm_settings->base_dir,
				       "/replicator-doveadm", NULL);

	(void)doveadm_cmd_param_str(cctx, "socket-path", &ctx->socket_path);
	(void)doveadm_cmd_param_bool(cctx, "full-sync", &ctx->full_sync);
	(void)doveadm_cmd_param_str(cctx, "priority", &ctx->priority);
	(void)doveadm_cmd_param_str(cctx, "user-mask", &ctx->user_mask);
	(void)doveadm_cmd_param_str(cctx, "user", &ctx->username);

	replicator_connect(ctx);
	return ctx;
}

static const char *time_formatted_hms(unsigned int secs)
{
	return t_strdup_printf("%02d:%02d:%02d", secs/3600,
			       (secs/60)%60, secs%60);
}

static const char *time_ago(time_t t)
{
	int diff = ioloop_time - t;

	if (t == 0)
		return "-";
	return time_formatted_hms(diff);
}

static void cmd_replicator_status_overview(struct replicator_context *ctx)
{
	char *line, *value;

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("field", "field",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
	doveadm_print_header("value", "value",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);

	replicator_send(ctx, "STATUS\n");
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		value = strchr(line, '\t');
		if (value != NULL)
			*value++ = '\0';
		else
			value = "";
		doveadm_print(line);
		doveadm_print(value);
	}
	replicator_disconnect(ctx);
}

static void cmd_replicator_status(struct doveadm_cmd_context *cctx)
{
	struct replicator_context *ctx;
	const char *line, *const *args;
	time_t last_fast, last_full, last_success;
	unsigned int next_secs;

	ctx = cmd_replicator_init(cctx);
	if (ctx->user_mask == NULL) {
	        cmd_replicator_status_overview(ctx);
		return;
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("username", "username",
			     DOVEADM_PRINT_HEADER_FLAG_EXPAND);
	doveadm_print_header_simple("priority");
	doveadm_print_header_simple("fast sync");
	doveadm_print_header_simple("full sync");
	doveadm_print_header_simple("success sync");
	doveadm_print_header_simple("failed");
	doveadm_print_header_simple("next sync secs");

	replicator_send(ctx, t_strdup_printf("STATUS\t%s\n",
					     str_tabescape(ctx->user_mask)));
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			args = t_strsplit_tabescaped(line);
			if (str_array_length(args) >= 6 &&
			    str_to_time(args[2], &last_fast) == 0 &&
			    str_to_time(args[3], &last_full) == 0 &&
			    str_to_time(args[5], &last_success) == 0 &&
			    str_to_uint(args[6], &next_secs) == 0) {
				doveadm_print(args[0]);
				doveadm_print(args[1]);
				doveadm_print(time_ago(last_fast));
				doveadm_print(time_ago(last_full));
				doveadm_print(time_ago(last_success));
				doveadm_print(args[4][0] == '0' ? "-" : "y");
				doveadm_print(time_formatted_hms(next_secs));
			}
		} T_END;
	}
	if (line == NULL) {
		e_error(cctx->event, "Replicator disconnected unexpectedly");
		doveadm_exit_code = EX_TEMPFAIL;
	}
	replicator_disconnect(ctx);
}

static void cmd_replicator_dsync_status(struct doveadm_cmd_context *cctx)
{
	struct replicator_context *ctx;
	const char *line;
	unsigned int i;

	ctx = cmd_replicator_init(cctx);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("username", "username",
			     DOVEADM_PRINT_HEADER_FLAG_EXPAND);
	doveadm_print_header_simple("type");
	doveadm_print_header_simple("status");

	replicator_send(ctx, "STATUS-DSYNC\n");
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			const char *const *args = t_strsplit_tabescaped(line);

			for (i = 0; i < 3; i++) {
				if (args[i] == NULL)
					break;
				doveadm_print(args[i]);
			}
			for (; i < 3; i++)
				doveadm_print("");
		} T_END;
	}
	replicator_disconnect(ctx);
}

static void cmd_replicator_replicate(struct doveadm_cmd_context *cctx)
{
	struct replicator_context *ctx;
	string_t *str;
	const char *line;

	ctx = cmd_replicator_init(cctx);
	if (ctx->user_mask == NULL)
		replicator_cmd_help(cctx->cmd);

	str = t_str_new(128);
	str_append(str, "REPLICATE\t");
	if (ctx->priority == NULL)
		str_append_tabescaped(str, "low");
	else
		str_append_tabescaped(str, ctx->priority);
	str_append_c(str, '\t');
	if (ctx->full_sync)
		str_append_c(str, 'f');
	str_append_c(str, '\t');
	str_append_tabescaped(str, ctx->user_mask);
	str_append_c(str, '\n');
	replicator_send(ctx, str_c(str));

	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	doveadm_print_header("result", "result",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);

	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		e_error(cctx->event, "Replicator disconnected unexpectedly");
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (line[0] != '+') {
		e_error(cctx->event, "Replicator failed: %s", line+1);
		doveadm_exit_code = EX_USAGE;
	} else {
		doveadm_print(t_strdup_printf("%s users updated", line+1));
	}
	replicator_disconnect(ctx);
}

static void cmd_replicator_add(struct doveadm_cmd_context *cctx)
{
	struct replicator_context *ctx;
	string_t *str;
	const char *line;

	ctx = cmd_replicator_init(cctx);
	if (ctx->user_mask == NULL)
		replicator_cmd_help(cctx->cmd);

	str = t_str_new(128);
	str_append(str, "ADD\t");
	str_append_tabescaped(str, ctx->user_mask);
	str_append_c(str, '\n');
	replicator_send(ctx, str_c(str));

	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		e_error(cctx->event, "Replicator disconnected unexpectedly");
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (line[0] != '+') {
		e_error(cctx->event, "Replicator failed: %s", line+1);
		doveadm_exit_code = EX_USAGE;
	}
	replicator_disconnect(ctx);
}

static void cmd_replicator_remove(struct doveadm_cmd_context *cctx)
{
	struct replicator_context *ctx;
	string_t *str;
	const char *line;

	ctx = cmd_replicator_init(cctx);
	if (ctx->username == NULL)
		replicator_cmd_help(cctx->cmd);

	str = t_str_new(128);
	str_append(str, "REMOVE\t");
	str_append_tabescaped(str, ctx->username);
	str_append_c(str, '\n');
	replicator_send(ctx, str_c(str));

	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		e_error(cctx->event, "Replicator disconnected unexpectedly");
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (line[0] != '+') {
		e_error(cctx->event, "Replicator failed: %s", line+1);
		doveadm_exit_code = EX_USAGE;
	}
	replicator_disconnect(ctx);
}

struct doveadm_cmd_ver2 doveadm_cmd_replicator[] = {
{
	.name = "replicator status",
	.cmd = cmd_replicator_status,
	.usage = "[-a <replicator socket path>] [<user mask>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user-mask", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "replicator dsync-status",
	.cmd = cmd_replicator_dsync_status,
	.usage = "[-a <replicator socket path>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "replicator replicate",
	.cmd = cmd_replicator_replicate,
	.usage = "[-a <replicator socket path>] [-f] [-p <priority>] <user mask>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('f', "full-sync", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('p', "priority", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user-mask", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "replicator add",
	.cmd = cmd_replicator_add,
	.usage = "[-a <replicator socket path>] <user mask>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user-mask", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "replicator remove",
	.cmd = cmd_replicator_remove,
	.usage = "[-a <replicator socket path>] <username>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
};

static void replicator_cmd_help(const struct doveadm_cmd_ver2 *cmd)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_replicator); i++) {
		if (doveadm_cmd_replicator[i].cmd == cmd->cmd)
			help_ver2(&doveadm_cmd_replicator[i]);
	}
	i_unreached();
}

void doveadm_register_replicator_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_replicator); i++)
		doveadm_cmd_register_ver2(&doveadm_cmd_replicator[i]);
}
