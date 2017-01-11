/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "istream.h"
#include "hash.h"
#include "time-util.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <unistd.h>

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
	const char *const *args = t_strsplit_tab(line);
	const char *ident = args[0];
	const char *penalty_str = args[1];
	const char *last_penalty_str = args[2];
	const char *last_update_str = args[3];

	i_zero(line_r);

	(void)net_addr2ip(ident, &line_r->ip);
	if (str_to_uint(penalty_str, &line_r->penalty) < 0 ||
	    str_to_time(last_penalty_str, &line_r->last_penalty) < 0 ||
	    str_to_time(last_update_str, &line_r->last_update) < 0)
		i_fatal("Read invalid penalty line: %s", line);
}

static void
penalty_print_line(struct penalty_context *ctx,
		   const struct penalty_line *line)
{
	if (ctx->net_bits > 0) {
		if (!net_is_in_network(&line->ip, &ctx->net_ip, ctx->net_bits))
			return;
	}

	doveadm_print(net_ip2addr(&line->ip));
	doveadm_print(dec2str(line->penalty));
	doveadm_print(unixdate2str(line->last_penalty));
	doveadm_print(t_strflocaltime("%H:%M:%S", line->last_update));
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
	if (write(fd, ANVIL_CMD, strlen(ANVIL_CMD)) < 0)
		i_fatal("write(%s) failed: %m", ctx->anvil_path);

	input = i_stream_create_fd_autoclose(&fd, (size_t)-1);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			struct penalty_line penalty_line;

			penalty_parse_line(line, &penalty_line);
			penalty_print_line(ctx, &penalty_line);
		} T_END;
	}
	if (input->stream_errno != 0) {
		i_fatal("read(%s) failed: %s", ctx->anvil_path,
			i_stream_get_error(input));
	}

	i_stream_destroy(&input);
}

static void cmd_penalty(struct doveadm_cmd_context *cctx)
{
	struct penalty_context ctx;
	const char *netmask;

	i_zero(&ctx);
	if (!doveadm_cmd_param_str(cctx, "socket-path", &(ctx.anvil_path)))
		ctx.anvil_path = t_strconcat(doveadm_settings->base_dir, "/anvil", NULL);

	if (doveadm_cmd_param_str(cctx, "netmask", &netmask)) {
		if (net_parse_range(netmask, &ctx.net_ip, &ctx.net_bits) != 0) {
			doveadm_exit_code = EX_USAGE;
			i_error("Invalid netmask '%s' given", netmask);
			return;
		}
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header_simple("IP");
	doveadm_print_header_simple("penalty");
	doveadm_print_header_simple("last_penalty");
	doveadm_print_header_simple("last_update");

	penalty_lookup(&ctx);
}

struct doveadm_cmd_ver2 doveadm_cmd_penalty_ver2 = {
	.name = "penalty",
	.cmd = cmd_penalty,
	.usage = "[-a <anvil socket path>] [<ip/bits>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a',"socket-path", CMD_PARAM_STR,0)
DOVEADM_CMD_PARAM('\0',"netmask", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
