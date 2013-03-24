/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "strescape.h"
#include "istream.h"
#include "write-full.h"
#include "master-service.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

struct replicator_context {
	const char *socket_path;
	struct istream *input;
};

extern struct doveadm_cmd doveadm_cmd_replicator[];

static void replicator_cmd_help(doveadm_command_t *cmd) ATTR_NORETURN;

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

	ctx->input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	replicator_send(ctx, REPLICATOR_HANDSHAKE);

	alarm(5);
	line = i_stream_read_next_line(ctx->input);
	alarm(0);
	if (line == NULL) {
		if (ctx->input->stream_errno != 0)
			i_fatal("read(%s) failed: %m", ctx->socket_path);
		else if (ctx->input->eof)
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
	if (ctx->input->stream_errno != 0)
		i_fatal("read(%s) failed: %m", ctx->socket_path);
	i_stream_destroy(&ctx->input);
}

static struct replicator_context *
cmd_replicator_init(int argc, char *argv[], doveadm_command_t *cmd)
{
	struct replicator_context *ctx;
	int c;

	ctx = t_new(struct replicator_context, 1);
	ctx->socket_path = t_strconcat(doveadm_settings->base_dir,
				       "/replicator-doveadm", NULL);

	while ((c = getopt(argc, argv, "a:")) > 0) {
		switch (c) {
		case 'a':
			ctx->socket_path = optarg;
			break;
		default:
			replicator_cmd_help(cmd);
		}
	}
	replicator_connect(ctx);
	return ctx;
}

static const char *time_ago(time_t t)
{
	int diff = ioloop_time - t;

	if (t == 0)
		return "-";
	return t_strdup_printf("%02d:%02d:%02d", diff/3600, diff/60, diff%60);
}

static void cmd_replicator_status(int argc, char *argv[])
{
	struct replicator_context *ctx;
	const char *line, *const *args;
	time_t last_fast, last_full;

	ctx = cmd_replicator_init(argc, argv, cmd_replicator_status);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("username", "username",
			     DOVEADM_PRINT_HEADER_FLAG_EXPAND);
	doveadm_print_header_simple("priority");
	doveadm_print_header_simple("fast sync");
	doveadm_print_header_simple("full sync");
	doveadm_print_header_simple("failed");

	if (argv[1] == NULL)
		replicator_send(ctx, "STATUS\n");
	else {
		replicator_send(ctx, t_strdup_printf("STATUS\t%s\n",
						     str_tabescape(argv[1])));
	}
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			args = t_strsplit_tab(line);
			if (str_array_length(args) >= 5 &&
			    str_to_time(args[2], &last_fast) == 0 &&
			    str_to_time(args[3], &last_full) == 0) {
				doveadm_print(args[0]);
				doveadm_print(args[1]);
				doveadm_print(time_ago(last_fast));
				doveadm_print(time_ago(last_full));
				doveadm_print(args[4][0] == '0' ? "-" : "y");
			}
		} T_END;
	}
	if (line == NULL) {
		i_error("Director disconnected unexpectedly");
		doveadm_exit_code = EX_TEMPFAIL;
	}
	replicator_disconnect(ctx);
}

struct doveadm_cmd doveadm_cmd_replicator[] = {
	{ cmd_replicator_status, "replicator status",
	  "[-a <replicator socket path>] [<user mask>]" }
};

static void replicator_cmd_help(doveadm_command_t *cmd)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_replicator); i++) {
		if (doveadm_cmd_replicator[i].cmd == cmd)
			help(&doveadm_cmd_replicator[i]);
	}
	i_unreached();
}

void doveadm_register_replicator_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_replicator); i++)
		doveadm_register_cmd(&doveadm_cmd_replicator[i]);
}
