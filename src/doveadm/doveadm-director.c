/* Copyright (c) 2009-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "network.h"
#include "istream.h"
#include "doveadm.h"

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
	if (write(i_stream_get_fd(ctx->input), data, strlen(data)) < 0)
		i_fatal("write(%s) failed: %m", ctx->socket_path);
}

static void director_connect(struct director_context *ctx)
{
#define DIRECTOR_HANDSHAKE_EXPECTED "VERSION\tdirector-doveadm\t1\t"
#define DIRECTOR_HANDSHAKE DIRECTOR_HANDSHAKE_EXPECTED"0\n"
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
	if (strncmp(line, DIRECTOR_HANDSHAKE_EXPECTED,
		    strlen(DIRECTOR_HANDSHAKE_EXPECTED)) != 0) {
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
	ctx->socket_path = PKG_RUNDIR"/director-admin";

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
	const char *line;

	director_send(ctx, t_strdup_printf("USER-LOOKUP\t%s\n", user));
	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		printf("Lookup failed\n");
		return;
	}

	if (strcmp(line, "NOTFOUND") == 0)
		printf("User not assigned to any server\n");
	else
		printf("%s\n", line);
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

	fprintf(stderr, "%-20s vhosts  users\n", "mail server ip");
	director_send(ctx, "HOST-LIST\n");
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			args = t_strsplit(line, "\t");
			if (str_array_length(args) >= 3) {
				printf("%-20s %6s %6s\n",
				       args[0], args[1], args[2]);
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

struct doveadm_cmd doveadm_cmd_director[] = {
	{ cmd_director_status, "director status",
	  "[-a <director socket path>] [<username>]", NULL },
	{ cmd_director_add, "director add",
	  "[-a <director socket path>] <host> [<vhost count>]", NULL },
	{ cmd_director_remove, "director remove",
	  "[-a <director socket path>] <host>", NULL }
};


void doveadm_register_director_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_director); i++)
		doveadm_register_cmd(&doveadm_cmd_director[i]);
}
