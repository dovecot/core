/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "network.h"
#include "istream.h"
#include "hash.h"
#include "doveadm.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

struct penalty_line {
	struct ip_addr ip;
	unsigned int penalty;
	time_t last_penalty, last_update;
};

struct penalty_context {
	const char *anvil_path;

	struct ip_addr net_ip;
	unsigned int net_bits;
};

static void penalty_parse_line(const char *line, struct penalty_line *line_r)
{
	const char *const *args = t_strsplit(line, "\t");
	const char *ident = args[0];
	const char *penalty_str = args[1];
	const char *last_penalty_str = args[2];
	const char *last_update_str = args[3];

	memset(line_r, 0, sizeof(*line_r));

	net_addr2ip(ident, &line_r->ip);
	line_r->penalty = strtoul(penalty_str, NULL, 10);
	line_r->last_penalty = strtoul(last_penalty_str, NULL, 10);
	line_r->last_update = strtoul(last_update_str, NULL, 10);
}

static void
penalty_print_line(struct penalty_context *ctx,
		   const struct penalty_line *line)
{
	const struct tm *tm;
	char buf[10];

	if (ctx->net_bits > 0) {
		if (!net_is_in_network(&line->ip, &ctx->net_ip, ctx->net_bits))
			return;
	}

	tm = localtime(&line->last_update);
	strftime(buf, sizeof(buf), "%H:%M:%S", tm);

	printf("%-16s %7u %s %s\n", net_ip2addr(&line->ip), line->penalty,
	       unixdate2str(line->last_penalty), buf);
}

static void penalty_lookup(struct penalty_context *ctx)
{
#define ANVIL_HANDSHAKE "VERSION\tanvil\t1\t0\n"
#define ANVIL_CMD ANVIL_HANDSHAKE"PENALTY-DUMP\n"
	struct istream *input;
	const char *line;
	int fd;

	fd = doveadm_connect(ctx->anvil_path);
	net_set_nonblock(fd, FALSE);

	input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	if (write(fd, ANVIL_CMD, strlen(ANVIL_CMD)) < 0)
		i_fatal("write(%s) failed: %m", ctx->anvil_path);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			struct penalty_line penalty_line;

			penalty_parse_line(line, &penalty_line);
			penalty_print_line(ctx, &penalty_line);
		} T_END;
	}
	if (input->stream_errno != 0)
		i_fatal("read(%s) failed: %m", ctx->anvil_path);

	i_stream_destroy(&input);
}

static void cmd_penalty(int argc, char *argv[])
{
	struct penalty_context ctx;
	int c;

	memset(&ctx, 0, sizeof(ctx));
	ctx.anvil_path = t_strconcat(doveadm_settings->base_dir, "/anvil", NULL);
	while ((c = getopt(argc, argv, "a:")) > 0) {
		switch (c) {
		case 'a':
			ctx.anvil_path = optarg;
			break;
		default:
			help(&doveadm_cmd_penalty);
		}
	}

	if (argv[1] != NULL) {
		if (net_parse_range(argv[1], &ctx.net_ip, &ctx.net_bits) == 0)
			argv++;
	}
	if (argv[1] != NULL)
		help(&doveadm_cmd_penalty);

	fprintf(stderr, "%-16s penalty last_penalty        last_update\n", "IP");
	penalty_lookup(&ctx);
}

struct doveadm_cmd doveadm_cmd_penalty = {
	cmd_penalty, "penalty",
	"[-a <anvil socket path>] [<ip/bits>]"
};
