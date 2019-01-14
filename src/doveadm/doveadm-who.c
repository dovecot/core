/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "istream.h"
#include "wildcard-match.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "doveadm.h"
#include "doveadm-print.h"
#include "doveadm-who.h"

#include <stdio.h>
#include <unistd.h>

struct who_user {
	const char *username;
	const char *service;
	ARRAY(struct ip_addr) ips;
	ARRAY(pid_t) pids;
	unsigned int connection_count;
};

static void who_user_ip(const struct who_user *user, struct ip_addr *ip_r)
{
	if (array_count(&user->ips) == 0)
		i_zero(ip_r);
	else {
		const struct ip_addr *ip = array_front(&user->ips);
		*ip_r = *ip;
	}
}

static unsigned int who_user_hash(const struct who_user *user)
{
	struct ip_addr ip;
	unsigned int hash = str_hash(user->service);

	if (user->username[0] != '\0')
		hash += str_hash(user->username);
	else {
		who_user_ip(user, &ip);
		hash += net_ip_hash(&ip);
	}
	return hash;
}

static int who_user_cmp(const struct who_user *user1,
			const struct who_user *user2)
{
	if (strcmp(user1->username, user2->username) != 0)
		return 1;
	if (strcmp(user1->service, user2->service) != 0)
		return 1;

	if (user1->username[0] == '\0') {
		/* tracking only IP addresses, not usernames */
		struct ip_addr ip1, ip2;

		who_user_ip(user1, &ip1);
		who_user_ip(user2, &ip2);
		return net_ip_cmp(&ip1, &ip2);
	}
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

static int who_parse_line(const char *line, struct who_line *line_r)
{
	const char *const *args = t_strsplit_tabescaped(line);
	const char *ident = args[0];
	const char *pid_str = args[1];
	const char *refcount_str = args[2];
	const char *p, *ip_str;

	i_zero(line_r);

	/* ident = service/ip/username (imap, pop3)
	   or      service/username (lmtp) */
	p = strchr(ident, '/');
	if (p == NULL)
		return -1;
	if (str_to_pid(pid_str, &line_r->pid) < 0)
		return -1;
	line_r->service = t_strdup_until(ident, p++);
	line_r->username = strchr(p, '/');
	if (line_r->username == NULL) {
		/* no IP */
		line_r->username = p;
	} else {
		ip_str = t_strdup_until(p, line_r->username++);
		(void)net_addr2ip(ip_str, &line_r->ip);
	}
	if (str_to_uint(refcount_str, &line_r->refcount) < 0)
		return -1;
	return 0;
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
		array_push_back(&user->ips, &line->ip);

	if (!who_user_has_pid(user, line->pid))
		array_push_back(&user->pids, &line->pid);
}

int who_parse_args(struct who_context *ctx, const char *const *masks)
{
	struct ip_addr net_ip;
	unsigned int i, net_bits;

	for (i = 0; masks[i] != NULL; i++) {
		if (net_parse_range(masks[i], &net_ip, &net_bits) == 0) {
			if (ctx->filter.net_bits != 0) {
				i_error("Multiple network masks not supported");
				doveadm_exit_code = EX_USAGE;
				return -1;
			}
			ctx->filter.net_ip = net_ip;
			ctx->filter.net_bits = net_bits;
		} else {
			if (ctx->filter.username != NULL) {
				i_error("Multiple username masks not supported");
				doveadm_exit_code = EX_USAGE;
				return -1;
			}
			ctx->filter.username = masks[i];
		}
	}
	return 0;
}

void who_lookup(struct who_context *ctx, who_callback_t *callback)
{
#define ANVIL_HANDSHAKE "VERSION\tanvil\t1\t0\n"
#define ANVIL_CMD ANVIL_HANDSHAKE"CONNECT-DUMP\n"
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
			struct who_line who_line;

			if (who_parse_line(line, &who_line) < 0)
				i_error("Invalid input: %s", line);
			else
				callback(ctx, &who_line);
		} T_END;
	}
	if (input->stream_errno != 0) {
		i_fatal("read(%s) failed: %s", ctx->anvil_path,
			i_stream_get_error(input));
	}

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
	struct who_user *user;

	doveadm_print_header("username", "username", 0);
	doveadm_print_header("connections", "#",
			     DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY);
	doveadm_print_header("service", "proto", 0);
	doveadm_print_header("pids", "(pids)", 0);
	doveadm_print_header("ips", "(ips)", 0);

	iter = hash_table_iterate_init(ctx->users);
	while (hash_table_iterate(iter, ctx->users, &user, &user)) {
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

static void cmd_who(struct doveadm_cmd_context *cctx)
{
	const char *const *masks;
	struct who_context ctx;
	bool separate_connections = FALSE;

	i_zero(&ctx);
	if (!doveadm_cmd_param_str(cctx, "socket-path", &(ctx.anvil_path)))
		ctx.anvil_path = t_strconcat(doveadm_settings->base_dir, "/anvil", NULL);
	(void)doveadm_cmd_param_bool(cctx, "separate-connections", &separate_connections);

	ctx.pool = pool_alloconly_create("who users", 10240);
	hash_table_create(&ctx.users, ctx.pool, 0, who_user_hash, who_user_cmp);

	if (doveadm_cmd_param_array(cctx, "mask", &masks)) {
		if (who_parse_args(&ctx, masks) != 0) {
			hash_table_destroy(&ctx.users);
			pool_unref(&ctx.pool);
			return;
		}
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	if (!separate_connections) {
		who_lookup(&ctx, who_aggregate_line);
		who_print(&ctx);
	} else {
		doveadm_print_header("username", "username",
				     DOVEADM_PRINT_HEADER_FLAG_EXPAND);
		doveadm_print_header("service", "proto", 0);
		doveadm_print_header_simple("pid");
		doveadm_print_header_simple("ip");
		who_lookup(&ctx, who_print_line);
	}

	hash_table_destroy(&ctx.users);
	pool_unref(&ctx.pool);
}

struct doveadm_cmd_ver2 doveadm_cmd_who_ver2 = {
	.name = "who",
	.cmd = cmd_who,
	.usage = "[-a <anvil socket path>] [-1] [<user mask>] [<ip/bits>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a',"socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('1',"separate-connections", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0',"mask", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
