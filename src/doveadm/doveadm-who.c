/* Copyright (c) 2009-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "network.h"
#include "istream.h"
#include "wildcard-match.h"
#include "hash.h"
#include "str.h"
#include "doveadm.h"
#include "doveadm-print.h"
#include "doveadm-who.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct who_user {
	const char *username;
	const char *service;
	ARRAY_DEFINE(ips, struct ip_addr);
	ARRAY_DEFINE(pids, pid_t);
	unsigned int connection_count;
};

static unsigned int who_user_hash(const void *p)
{
	const struct who_user *user = p;

	return str_hash(user->username) + str_hash(user->service);
}

static int who_user_cmp(const void *p1, const void *p2)
{
	const struct who_user *user1 = p1, *user2 = p2;

	if (strcmp(user1->username, user2->username) != 0)
		return 1;
	if (strcmp(user1->service, user2->service) != 0)
		return 1;
	return 0;
}

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

static void who_parse_line(const char *line, struct who_line *line_r)
{
	const char *const *args = t_strsplit(line, "\t");
	const char *ident = args[0];
	const char *pid_str = args[1];
	const char *refcount_str = args[2];
	const char *p, *ip_str;

	memset(line_r, 0, sizeof(*line_r));

	p = strchr(ident, '/');
	line_r->pid = strtoul(pid_str, NULL, 10);
	line_r->service = t_strdup_until(ident, p++);
	line_r->username = strchr(p, '/');
	line_r->refcount = atoi(refcount_str);
	ip_str = t_strdup_until(p, line_r->username++);
	(void)net_addr2ip(ip_str, &line_r->ip);
}

static bool who_user_has_pid(struct who_user *user, pid_t pid)
{
	const pid_t *ex_pid;

	array_foreach(&user->pids, ex_pid) {
		if (*ex_pid == pid)
			return TRUE;
	}
	return FALSE;
}

static void who_aggregate_line(struct who_context *ctx,
			       const struct who_line *line)
{
	struct who_user *user, lookup_user;

	lookup_user.username = line->username;
	lookup_user.service = line->service;

	user = hash_table_lookup(ctx->users, &lookup_user);
	if (user == NULL) {
		user = p_new(ctx->pool, struct who_user, 1);
		user->username = p_strdup(ctx->pool, line->username);
		user->service = p_strdup(ctx->pool, line->service);
		p_array_init(&user->ips, ctx->pool, 3);
		p_array_init(&user->pids, ctx->pool, 8);
		hash_table_insert(ctx->users, user, user);
	}
	user->connection_count += line->refcount;

	if (line->ip.family != 0 && !who_user_has_ip(user, &line->ip))
		array_append(&user->ips, &line->ip, 1);

	if (!who_user_has_pid(user, line->pid))
		array_append(&user->pids, &line->pid, 1);
}

void who_parse_args(struct who_context *ctx, char **args)
{
	struct ip_addr net_ip;
	unsigned int net_bits;

	while (args[1] != NULL) {
		if (net_parse_range(args[1], &net_ip, &net_bits) == 0) {
			if (ctx->filter.net_bits != 0)
				usage();
			ctx->filter.net_ip = net_ip;
			ctx->filter.net_bits = net_bits;
		} else {
			if (ctx->filter.username != NULL)
				usage();
			ctx->filter.username = args[1];
		}
		args++;
	}
}

void who_lookup(struct who_context *ctx, who_callback_t *callback)
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
			struct who_line who_line;

			who_parse_line(line, &who_line);
			callback(ctx, &who_line);
		} T_END;
	}
	if (input->stream_errno != 0)
		i_fatal("read(%s) failed: %m", ctx->anvil_path);

	i_stream_destroy(&input);
}

static bool who_user_filter_match(const struct who_user *user,
				  const struct who_filter *filter)
{
	if (filter->username != NULL) {
		if (!wildcard_match_icase(user->username, filter->username))
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

static void who_print_user(const struct who_user *user)
{
	const struct ip_addr *ip;
	const pid_t *pid;
	string_t *str = t_str_new(256);

	doveadm_print(user->username);
	doveadm_print(dec2str(user->connection_count));
	doveadm_print(user->service);

	str_append_c(str, '(');
	array_foreach(&user->pids, pid)
		str_printfa(str, "%ld ", (long)*pid);
	if (str_len(str) > 1)
		str_truncate(str, str_len(str)-1);
	str_append_c(str, ')');
	doveadm_print(str_c(str));

	str_truncate(str, 0);
	str_append_c(str, '(');
	array_foreach(&user->ips, ip)
		str_printfa(str, "%s ", net_ip2addr(ip));
	if (str_len(str) > 1)
		str_truncate(str, str_len(str)-1);
	str_append_c(str, ')');
	doveadm_print(str_c(str));
}

static void who_print(struct who_context *ctx)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	doveadm_print_header("username", "username", 0);
	doveadm_print_header("connections", "#",
			     DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY);
	doveadm_print_header("service", "proto", 0);
	doveadm_print_header("pids", "(pids)", 0);
	doveadm_print_header("ips", "(ips)", 0);

	iter = hash_table_iterate_init(ctx->users);
	while (hash_table_iterate(iter, &key, &value)) {
		struct who_user *user = value;

		if (who_user_filter_match(user, &ctx->filter)) T_BEGIN {
			who_print_user(user);
		} T_END;
	}
	hash_table_iterate_deinit(&iter);
}

bool who_line_filter_match(const struct who_line *line,
			   const struct who_filter *filter)
{
	if (filter->username != NULL) {
		if (!wildcard_match_icase(line->username, filter->username))
			return FALSE;
	}
	if (filter->net_bits > 0) {
		if (!net_is_in_network(&line->ip, &filter->net_ip,
				       filter->net_bits))
			return FALSE;
	}
	return TRUE;
}

static void who_print_line(struct who_context *ctx,
			   const struct who_line *line)
{
	unsigned int i;

	if (!who_line_filter_match(line, &ctx->filter))
		return;

	for (i = 0; i < line->refcount; i++) T_BEGIN {
		doveadm_print(line->username);
		doveadm_print(line->service);
		doveadm_print(dec2str(line->pid));
		doveadm_print(net_ip2addr(&line->ip));
	} T_END;
}

static void cmd_who(int argc, char *argv[])
{
	struct who_context ctx;
	bool separate_connections = FALSE;
	int c;

	memset(&ctx, 0, sizeof(ctx));
	ctx.anvil_path = t_strconcat(doveadm_settings->base_dir, "/anvil", NULL);
	ctx.pool = pool_alloconly_create("who users", 10240);
	ctx.users = hash_table_create(default_pool, ctx.pool, 0,
				      who_user_hash, who_user_cmp);

	while ((c = getopt(argc, argv, "1a:")) > 0) {
		switch (c) {
		case '1':
			separate_connections = TRUE;
			break;
		case 'a':
			ctx.anvil_path = optarg;
			break;
		default:
			help(&doveadm_cmd_who);
		}
	}

	argv += optind - 1;
	who_parse_args(&ctx, argv);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	if (!separate_connections) {
		who_lookup(&ctx, who_aggregate_line);
		who_print(&ctx);
	} else {
		doveadm_print_header_simple("username");
		doveadm_print_header_simple("service");
		doveadm_print_header_simple("pid");
		doveadm_print_header_simple("ip");
		who_lookup(&ctx, who_print_line);
	}

	hash_table_destroy(&ctx.users);
	pool_unref(&ctx.pool);
}

struct doveadm_cmd doveadm_cmd_who = {
	cmd_who, "who",
	"[-a <anvil socket path>] [-1] [<user mask>] [<ip/bits>]", NULL
};
