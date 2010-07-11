/* Copyright (c) 2009-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "network.h"
#include "istream.h"
#include "write-full.h"
#include "master-service.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct director_context {
	const char *socket_path;
	struct istream *input;
};

extern struct doveadm_cmd doveadm_cmd_director[];

static void
director_send(struct director_context *ctx, const char *data)
{
	if (write_full(i_stream_get_fd(ctx->input), data, strlen(data)) < 0)
		i_fatal("write(%s) failed: %m", ctx->socket_path);
}

static void director_connect(struct director_context *ctx)
{
#define DIRECTOR_HANDSHAKE "VERSION\tdirector-doveadm\t1\t0\n"
	const char *line;
	int fd;

	fd = net_connect_unix(ctx->socket_path);
	if (fd == -1)
		i_fatal("net_connect_unix(%s) failed: %m", ctx->socket_path);
	net_set_nonblock(fd, FALSE);

	ctx->input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	director_send(ctx, DIRECTOR_HANDSHAKE);

	line = i_stream_read_next_line(ctx->input);
	if (line == NULL)
		i_fatal("%s disconnected", ctx->socket_path);
	if (!version_string_verify(line, "director-doveadm", 1)) {
		i_fatal("%s not a compatible director-doveadm socket",
			ctx->socket_path);
	}
}

static void director_disconnect(struct director_context *ctx)
{
	if (ctx->input->stream_errno != 0)
		i_fatal("read(%s) failed: %m", ctx->socket_path);
	i_stream_destroy(&ctx->input);
}

static struct director_context *
cmd_director_init(int argc, char *argv[], unsigned int cmd_idx)
{
	struct director_context *ctx;
	int c;

	ctx = t_new(struct director_context, 1);
	ctx->socket_path = t_strconcat(doveadm_settings->base_dir,
				       "/director-admin", NULL);

	while ((c = getopt(argc, argv, "a:")) > 0) {
		switch (c) {
		case 'a':
			ctx->socket_path = optarg;
			break;
		default:
			help(&doveadm_cmd_director[cmd_idx]);
		}
	}
	director_connect(ctx);
	return ctx;
}

static void
cmd_director_status_user(struct director_context *ctx, const char *user)
{
	const char *line, *const *args;
	unsigned int expires;

	director_send(ctx, t_strdup_printf("USER-LOOKUP\t%s\n", user));
	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		printf("Lookup failed\n");
		return;
	}

	args = t_strsplit(line, "\t");
	if (str_array_length(args) != 4 ||
	    str_to_uint(args[1], &expires) < 0) {
		printf("Invalid reply from director\n");
		return;
	}

	if (args[0][0] != '\0') {
		printf("Current: %s (expires %s)\n",
		       args[0], unixdate2str(expires));
	} else {
		printf("Current: not assigned\n");
	}
	printf("Hashed: %s\n", args[2]);
	printf("Initial config: %s\n", args[3]);
	director_disconnect(ctx);
}

static void cmd_director_status(int argc, char *argv[])
{
	struct director_context *ctx;
	const char *line, *const *args;

	ctx = cmd_director_init(argc, argv, 0);
	if (argv[optind] != NULL) {
		cmd_director_status_user(ctx, argv[optind]);
		return;
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header_simple("mail server ip");
	doveadm_print_header("vhosts", "vhosts",
			     DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY);
	doveadm_print_header("users", "users",
			     DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY);

	director_send(ctx, "HOST-LIST\n");
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			args = t_strsplit(line, "\t");
			if (str_array_length(args) >= 3) {
				doveadm_print(args[0]);
				doveadm_print(args[1]);
				doveadm_print(args[2]);
			}
		} T_END;
	}
	director_disconnect(ctx);
}

static void cmd_director_add(int argc, char *argv[])
{
	struct director_context *ctx;
	struct ip_addr *ips;
	unsigned int i, ips_count, vhost_count = -1U;
	struct ip_addr ip;
	const char *host, *cmd, *line;

	ctx = cmd_director_init(argc, argv, 0);
	host = argv[optind++];
	if (host == NULL)
		help(&doveadm_cmd_director[1]);
	if (argv[optind] != NULL) {
		if (str_to_uint(argv[optind++], &vhost_count) < 0)
			help(&doveadm_cmd_director[1]);
	}
	if (argv[optind] != NULL)
		help(&doveadm_cmd_director[1]);

	if (net_addr2ip(host, &ip) == 0) {
		ips = &ip;
		ips_count = 1;
	} else {
		if (net_gethostbyname(host, &ips, &ips_count) < 0)
			i_fatal("gethostname(%s) failed: %m", host);
	}

	for (i = 0; i < ips_count; i++) {
		cmd = vhost_count == -1U ?
			t_strdup_printf("HOST-SET\t%s\n",
					net_ip2addr(&ips[i])) :
			t_strdup_printf("HOST-SET\t%s\t%u\n",
					net_ip2addr(&ips[i]), vhost_count);
		director_send(ctx, cmd);
	}
	for (i = 0; i < ips_count; i++) {
		line = i_stream_read_next_line(ctx->input);
		if (line == NULL || strcmp(line, "OK") != 0) {
			fprintf(stderr, "%s: %s\n", net_ip2addr(&ips[i]),
				line == NULL ? "failed" : line);
		} else if (doveadm_verbose) {
			printf("%s: OK\n", net_ip2addr(&ips[i]));
		}
	}
	if (i != ips_count)
		i_fatal("director add failed");
	director_disconnect(ctx);
}

static void cmd_director_remove(int argc, char *argv[])
{
	struct director_context *ctx;
	struct ip_addr *ips;
	unsigned int i, ips_count;
	struct ip_addr ip;
	const char *host, *line;

	ctx = cmd_director_init(argc, argv, 0);
	host = argv[optind++];
	if (host == NULL || argv[optind] != NULL)
		help(&doveadm_cmd_director[2]);

	if (net_addr2ip(host, &ip) == 0) {
		ips = &ip;
		ips_count = 1;
	} else {
		if (net_gethostbyname(host, &ips, &ips_count) < 0)
			i_fatal("gethostname(%s) failed: %m", host);
	}

	for (i = 0; i < ips_count; i++) {
		director_send(ctx,
			t_strdup_printf("HOST-REMOVE\t%s\n", net_ip2addr(&ip)));
	}
	for (i = 0; i < ips_count; i++) {
		line = i_stream_read_next_line(ctx->input);
		if (line == NULL || strcmp(line, "OK") != 0) {
			fprintf(stderr, "%s: %s\n", net_ip2addr(&ips[i]),
				line == NULL ? "failed" :
				(strcmp(line, "NOTFOUND") == 0 ?
				 "doesn't exist" : line));
		} else if (doveadm_verbose) {
			printf("%s: removed\n", net_ip2addr(&ips[i]));
		}
	}
	if (i != ips_count)
		i_fatal("director remove failed");
	director_disconnect(ctx);
}

static void cmd_director_flush_all(struct director_context *ctx)
{
	const char *line;

	director_send(ctx, "HOST-FLUSH\n");

	line = i_stream_read_next_line(ctx->input);
	if (line == NULL)
		fprintf(stderr, "failed\n");
	else if (strcmp(line, "OK") != 0)
		fprintf(stderr, "%s\n", line);
	else if (doveadm_verbose)
		printf("flushed\n");
	director_disconnect(ctx);
}

static void cmd_director_flush(int argc, char *argv[])
{
	struct director_context *ctx;
	struct ip_addr *ips;
	unsigned int i, ips_count;
	struct ip_addr ip;
	const char *host, *line;

	ctx = cmd_director_init(argc, argv, 0);
	host = argv[optind++];
	if (host == NULL || argv[optind] != NULL)
		help(&doveadm_cmd_director[2]);

	if (strcmp(host, "all") == 0) {
		cmd_director_flush_all(ctx);
		return;
	}
	if (net_addr2ip(host, &ip) == 0) {
		ips = &ip;
		ips_count = 1;
	} else {
		if (net_gethostbyname(host, &ips, &ips_count) < 0)
			i_fatal("gethostname(%s) failed: %m", host);
	}

	for (i = 0; i < ips_count; i++) {
		director_send(ctx,
			t_strdup_printf("HOST-FLUSH\t%s\n", net_ip2addr(&ip)));
	}
	for (i = 0; i < ips_count; i++) {
		line = i_stream_read_next_line(ctx->input);
		if (line == NULL || strcmp(line, "OK") != 0) {
			fprintf(stderr, "%s: %s\n", net_ip2addr(&ips[i]),
				line == NULL ? "failed" :
				(strcmp(line, "NOTFOUND") == 0 ?
				 "doesn't exist" : line));
		} else if (doveadm_verbose) {
			printf("%s: flushed\n", net_ip2addr(&ips[i]));
		}
	}
	if (i != ips_count)
		i_fatal("director flush failed");
	director_disconnect(ctx);
}

struct doveadm_cmd doveadm_cmd_director[] = {
	{ cmd_director_status, "director status",
	  "[-a <director socket path>] [<user>]", NULL },
	{ cmd_director_add, "director add",
	  "[-a <director socket path>] <host> [<vhost count>]", NULL },
	{ cmd_director_remove, "director remove",
	  "[-a <director socket path>] <host>", NULL },
	{ cmd_director_flush, "director flush",
	  "[-a <director socket path>] <host>|all", NULL }
};


void doveadm_register_director_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_director); i++)
		doveadm_register_cmd(&doveadm_cmd_director[i]);
}
