/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "network.h"
#include "istream.h"
#include "hash.h"
#include "doveadm.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct who_user {
	const char *username;
	ARRAY_DEFINE(ips, struct ip_addr);
	ARRAY_DEFINE(pids, pid_t);
	unsigned int connection_count;
};

struct who_filter {
	const char *username;
	struct ip_addr net_ip;
	unsigned int net_bits;
};

struct who_context {
	const char *anvil_path;
	struct who_filter filter;

	pool_t pool;
	struct hash_table *users; /* username -> who_user */
};

static bool
who_user_has_ip(const struct who_user *user, const struct ip_addr *ip)
{
	const struct ip_addr *ex_ip;

	array_foreach(&user->ips, ex_ip) {
		if (net_ip_compare(ex_ip, ip))
			return TRUE;
	}
	return FALSE;
}

static void who_line(struct who_context *ctx,
		     const char *const *args)
{
	const char *ident = args[0];
	pid_t pid = strtoul(args[1], NULL, 10);
	unsigned int refcount = atoi(args[2]);
	const char *p, *service, *ip_str, *username;
	struct who_user *user;
	struct ip_addr ip;
	const pid_t *ex_pid;
	char *username_dup;

	p = strchr(ident, '/');
	service = t_strdup_until(ident, p++);
	username = strchr(p, '/');
	ip_str = t_strdup_until(p, username++);
	if (net_addr2ip(ip_str, &ip) < 0)
		memset(&ip, 0, sizeof(ip));

	user = hash_table_lookup(ctx->users, username);
	if (user == NULL) {
		user = p_new(ctx->pool, struct who_user, 1);
		username_dup = p_strdup(ctx->pool, username);
		user->username = username_dup;
		p_array_init(&user->ips, ctx->pool, 3);
		p_array_init(&user->pids, ctx->pool, 8);
		hash_table_insert(ctx->users, username_dup, user);
	}
	user->connection_count += refcount;

	if (ip.family != 0 && !who_user_has_ip(user, &ip))
		array_append(&user->ips, &ip, 1);

	array_foreach(&user->pids, ex_pid) {
		if (*ex_pid == pid)
			break;
	}
	if (*ex_pid != pid)
		array_append(&user->pids, &pid, 1);
}

static void who_lookup(struct who_context *ctx)
{
#define ANVIL_HANDSHAKE "VERSION\tanvil\t1\t0\n"
#define ANVIL_CMD ANVIL_HANDSHAKE"CONNECT-DUMP\n"
	struct istream *input;
	const char *line;
	int fd;

	fd = net_connect_unix(ctx->anvil_path);
	if (fd == -1)
		i_fatal("net_connect_unix(%s) failed: %m", ctx->anvil_path);
	net_set_nonblock(fd, FALSE);

	input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	if (write(fd, ANVIL_CMD, strlen(ANVIL_CMD)) < 0)
		i_fatal("write(%s) failed: %m", ctx->anvil_path);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			who_line(ctx, t_strsplit(line, "\t"));
		} T_END;
	}
	if (input->stream_errno != 0)
		i_fatal("read(%s) failed: %m", ctx->anvil_path);

	i_stream_destroy(&input);
}

static bool who_filter_match(const struct who_user *user,
			     const struct who_filter *filter)
{
	if (filter->username != NULL) {
		if (strstr(user->username, filter->username) == NULL)
			return FALSE;
	}
	if (filter->net_bits > 0) {
		const struct ip_addr *ip;
		bool ret = FALSE;

		array_foreach(&user->ips, ip) {
			if (net_is_in_network(ip, &filter->net_ip,
					      filter->net_bits)) {
				ret = TRUE;
				break;
			}
		}
		if (!ret)
			return FALSE;
	}
	return TRUE;
}

static void who_print(struct who_context *ctx)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	fprintf(stderr, "%-30s  # (ips) (pids)\n", "username");

	iter = hash_table_iterate_init(ctx->users);
	while (hash_table_iterate(iter, &key, &value)) {
		struct who_user *user = value;
		const struct ip_addr *ip;
		const pid_t *pid;
		bool first = TRUE;

		if (!who_filter_match(user, &ctx->filter))
			continue;

		printf("%-30s %2u ", user->username, user->connection_count);

		printf("(");
		array_foreach(&user->ips, ip) T_BEGIN {
			if (first)
				first = FALSE;
			else
				printf(" ");
			printf("%s", net_ip2addr(ip));
		} T_END;
		printf(") (");
		first = TRUE;
		array_foreach(&user->pids, pid) T_BEGIN {
			if (first)
				first = FALSE;
			else
				printf(" ");
			printf("%ld", (long)*pid);
		} T_END;
		printf(")\n");
	};
	hash_table_iterate_deinit(&iter);
}

static void cmd_who(int argc, char *argv[])
{
	struct who_context ctx;
	struct ip_addr net_ip;
	unsigned int net_bits;
	int c;

	memset(&ctx, 0, sizeof(ctx));
	ctx.anvil_path = PKG_RUNDIR"/anvil";
	ctx.pool = pool_alloconly_create("who users", 10240);
	ctx.users = hash_table_create(default_pool, ctx.pool, 0, str_hash,
				      (hash_cmp_callback_t *)strcmp);

	while ((c = getopt(argc, argv, "a:")) > 0) {
		switch (c) {
		case 'a':
			ctx.anvil_path = optarg;
			break;
		default:
			help(&doveadm_cmd_who);
		}
	}

	argv += optind - 1;
	while (argv[1] != NULL) {
		if (net_parse_range(argv[1], &net_ip, &net_bits) == 0) {
			if (ctx.filter.net_bits != 0)
				usage();
			ctx.filter.net_ip = net_ip;
			ctx.filter.net_bits = net_bits;
		} else {
			if (ctx.filter.username != NULL)
				usage();
			ctx.filter.username = argv[1];
		}
		argv++;
	}

	who_lookup(&ctx);
	who_print(&ctx);

	hash_table_destroy(&ctx.users);
	pool_unref(&ctx.pool);
}

struct doveadm_cmd doveadm_cmd_who = {
	cmd_who, "who",
	"[-a <anvil socket path>] [<user>] [<ip/bits>]", NULL
};
