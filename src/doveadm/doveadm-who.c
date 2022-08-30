/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "net.h"
#include "istream.h"
#include "wildcard-match.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "master-service.h"
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

struct doveadm_who_iter {
	struct istream *input;
	pool_t pool, line_pool;

	unsigned int alt_username_fields_count;
	const char **alt_username_fields;
	const char *error;
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

static int who_parse_line(struct doveadm_who_iter *iter,
			  const char *line, struct who_line *line_r)
{
	const char *const *args = t_strsplit_tabescaped(line);
	i_zero(line_r);

	/* <pid> <username> <service> <ip> <conn-guid> <dest-ip>
	   [alt usernames] */
	if (str_array_length(args) < 6)
		return -1;

	p_clear(iter->line_pool);
	if (str_to_pid(args[0], &line_r->pid) < 0)
		return -1;
	line_r->username = p_strdup(iter->line_pool, args[1]);
	line_r->service = p_strdup(iter->line_pool, args[2]);
	if (args[3][0] != '\0') {
		if (net_addr2ip(args[3], &line_r->ip) < 0)
			return -1;
	}
	if (guid_128_from_string(args[4], line_r->conn_guid) < 0)
		return -1;
	if (args[5][0] != '\0') {
		if (net_addr2ip(args[5], &line_r->dest_ip) < 0)
			return -1;
	}
	line_r->alt_usernames = p_strarray_dup(iter->line_pool, args + 6);
	return 0;
}

static bool who_user_has_pid(struct who_user *user, pid_t pid)
{
	pid_t ex_pid;

	array_foreach_elem(&user->pids, ex_pid) {
		if (ex_pid == pid)
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
	user->connection_count++;

	if (line->ip.family != 0 && !who_user_has_ip(user, &line->ip))
		array_push_back(&user->ips, &line->ip);

	if (!who_user_has_pid(user, line->pid))
		array_push_back(&user->pids, &line->pid);
}

static int
who_parse_masks(struct who_context *ctx, const char *const *masks)
{
	struct ip_addr net_ip;
	unsigned int i, net_bits;

	for (i = 0; masks[i] != NULL; i++) {
		if (!str_is_numeric(masks[i], '\0') &&
		    net_parse_range(masks[i], &net_ip, &net_bits) == 0) {
			if (ctx->filter.net_bits != 0) {
				e_error(ctx->event,
					"Multiple network masks not supported");
				doveadm_exit_code = EX_USAGE;
				return -1;
			}
			ctx->filter.net_ip = net_ip;
			ctx->filter.net_bits = net_bits;
		} else {
			if (ctx->filter.username != NULL) {
				e_error(ctx->event,
					"Multiple username masks not supported");
				doveadm_exit_code = EX_USAGE;
				return -1;
			}
			ctx->filter.username = masks[i];
		}
	}
	return 0;
}

int who_parse_args(struct who_context *ctx, const char *alt_username_field,
		   const struct ip_addr *dest_ip, const char *const *masks)
{
	if (dest_ip != NULL)
		ctx->filter.dest_ip = *dest_ip;

	if (masks != NULL) {
		if (who_parse_masks(ctx, masks) < 0)
			return -1;
	}
	if (alt_username_field != NULL && ctx->filter.username == NULL) {
		e_error(ctx->event,
			"Username must be given with passdb-field parameter");
		doveadm_exit_code = EX_USAGE;
		return -1;
	}
	ctx->filter.alt_username_field = alt_username_field;
	ctx->filter.alt_username_idx = UINT_MAX;
	return 0;
}

struct doveadm_who_iter *doveadm_who_iter_init(const char *anvil_path)
{
#define ANVIL_HANDSHAKE "VERSION\tanvil-client\t2\t0\n\n"
#define ANVIL_CMD ANVIL_HANDSHAKE"CONNECT-DUMP\n"
	struct doveadm_who_iter *iter;
	const char *line;
	int fd;
	pool_t pool;

	pool = pool_alloconly_create("doveadm who iter", 256);
	iter = p_new(pool, struct doveadm_who_iter, 1);
	iter->pool = pool;
	iter->line_pool = pool_alloconly_create("doveadm who line", 256);

	fd = doveadm_connect(anvil_path);
	net_set_nonblock(fd, FALSE);
	if (write(fd, ANVIL_CMD, strlen(ANVIL_CMD)) < 0) {
		iter->error = p_strdup_printf(iter->pool,
					      "write(%s) failed: %m", anvil_path);
		i_close_fd(&fd);
		return iter;
	}

	iter->input = i_stream_create_fd_autoclose(&fd, SIZE_MAX);
	i_stream_set_name(iter->input, anvil_path);
	if ((line = i_stream_read_next_line(iter->input)) == NULL) {
		iter->error = p_strdup_printf(iter->pool,
					      "anvil didn't send VERSION line");
	} else if (!version_string_verify(line, "anvil-server", 2)) {
		iter->error = p_strdup_printf(iter->pool,
					      "Invalid VERSION line: %s", line);
	} else if ((line = i_stream_read_next_line(iter->input)) == NULL) {
		iter->error = p_strdup_printf(iter->pool,
					      "anvil didn't send header line");
	} else {
		iter->alt_username_fields =
			(const char **)p_strsplit_tabescaped(iter->pool, line);
		iter->alt_username_fields_count =
			str_array_length(iter->alt_username_fields);
	}
	return iter;
}

bool doveadm_who_iter_init_filter(struct doveadm_who_iter *iter,
				  struct who_filter *filter)
{
	if (filter->alt_username_field == NULL)
		return TRUE;

	for (unsigned int i = 0; i < iter->alt_username_fields_count; i++) {
		if (strcmp(filter->alt_username_field,
			   iter->alt_username_fields[i]) == 0) {
			filter->alt_username_idx = i;
			return TRUE;
		}
	}
	return FALSE;
}

bool doveadm_who_iter_next(struct doveadm_who_iter *iter,
			   struct who_line *who_line_r)
{
	const char *line;
	int ret;

	if (iter->error != NULL)
		return FALSE;

	if ((line = i_stream_read_next_line(iter->input)) != NULL) {
		if (*line == '\0')
			return FALSE;
		T_BEGIN {
			ret = who_parse_line(iter, line, who_line_r);
		} T_END;
		if (ret < 0) {
			iter->error = p_strdup_printf(iter->pool,
						      "Invalid input: %s", line);
			return FALSE;
		}
		return TRUE;
	}
	if (iter->input->stream_errno != 0) {
		iter->error = p_strdup_printf(iter->pool,
			"read(%s) failed: %s", i_stream_get_name(iter->input),
			i_stream_get_error(iter->input));
	} else {
		iter->error = p_strdup_printf(iter->pool,
			"read(%s) failed: Unexpected EOF",
			i_stream_get_name(iter->input));
	}
	return FALSE;
}

int doveadm_who_iter_deinit(struct doveadm_who_iter **_iter,
			    const char **error_r)
{
	struct doveadm_who_iter *iter = *_iter;
	*_iter = NULL;

	bool failed = iter->error != NULL;
	if (failed)
		*error_r = t_strdup(iter->error);
	i_stream_destroy(&iter->input);
	pool_unref(&iter->line_pool);
	pool_unref(&iter->pool);
	return failed ? -1 : 0;
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
	pid_t pid;
	string_t *str = t_str_new(256);

	doveadm_print(user->username);
	doveadm_print(dec2str(user->connection_count));
	doveadm_print(user->service);

	str_append_c(str, '(');
	array_foreach_elem(&user->pids, pid)
		str_printfa(str, "%lu ", (unsigned long)pid);
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

	doveadm_print_flush();
}

static void who_print(struct who_context *ctx)
{
	struct hash_iterate_context *iter;
	struct who_user *user;

	doveadm_print_header("username", "username", 0);
	doveadm_print_header("connections", "#",
			     DOVEADM_PRINT_HEADER_FLAG_RIGHT_JUSTIFY);
	doveadm_print_header("service", "service", 0);
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
	unsigned int i;

	if (filter->username == NULL)
		;
	else if (filter->alt_username_field == NULL) {
		if (!wildcard_match_icase(line->username, filter->username))
			return FALSE;
	} else {
		i_assert(filter->alt_username_idx != UINT_MAX);
		if (line->alt_usernames == NULL)
			return FALSE;
		for (i = 0; line->alt_usernames[i] != NULL; i++) {
			if (i == filter->alt_username_idx)
				break;
		}
		if (i != filter->alt_username_idx ||
		    !wildcard_match_icase(line->alt_usernames[i],
					  filter->username))
			return FALSE;
	}
	if (filter->net_bits > 0) {
		if (!net_is_in_network(&line->ip, &filter->net_ip,
				       filter->net_bits))
			return FALSE;
	}
	if (filter->dest_ip.family != 0) {
		if (!net_ip_compare(&line->dest_ip, &filter->dest_ip))
			return FALSE;
	}
	return TRUE;
}

static void
who_print_line(struct who_context *ctx, struct doveadm_who_iter *iter,
	       const struct who_line *line)
{
	unsigned int alt_idx;

	if (!who_line_filter_match(line, &ctx->filter))
		return;

	doveadm_print(line->username);
	doveadm_print(line->service);
	doveadm_print(dec2str(line->pid));
	doveadm_print(net_ip2addr(&line->ip));
	doveadm_print(net_ip2addr(&line->dest_ip));

	for (alt_idx = 0; line->alt_usernames[alt_idx] != NULL; alt_idx++)
		doveadm_print(line->alt_usernames[alt_idx]);
	for (; alt_idx < iter->alt_username_fields_count; alt_idx++)
		doveadm_print("");
}

static void cmd_who(struct doveadm_cmd_context *cctx)
{
	const char *passdb_field, *const *masks;
	struct who_context ctx;
	bool separate_connections = FALSE;

	i_zero(&ctx);
	if (!doveadm_cmd_param_str(cctx, "socket-path", &(ctx.anvil_path)))
		ctx.anvil_path = t_strconcat(doveadm_settings->base_dir, "/anvil", NULL);
	if (!doveadm_cmd_param_str(cctx, "passdb-field", &passdb_field))
		passdb_field = NULL;
	(void)doveadm_cmd_param_bool(cctx, "separate-connections", &separate_connections);

	ctx.pool = pool_alloconly_create("who users", 10240);
	ctx.event = cctx->event;
	hash_table_create(&ctx.users, ctx.pool, 0, who_user_hash, who_user_cmp);

	if (doveadm_cmd_param_array(cctx, "mask", &masks)) {
		if (who_parse_args(&ctx, passdb_field, NULL, masks) != 0) {
			hash_table_destroy(&ctx.users);
			pool_unref(&ctx.pool);
			return;
		}
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	struct doveadm_who_iter *iter = doveadm_who_iter_init(ctx.anvil_path);
	struct who_line who_line;
	if (!separate_connections) {
		while (doveadm_who_iter_next(iter, &who_line))
			who_aggregate_line(&ctx, &who_line);
		who_print(&ctx);
	} else {
		doveadm_print_header("username", "username",
				     DOVEADM_PRINT_HEADER_FLAG_EXPAND);
		doveadm_print_header("service", "service", 0);
		doveadm_print_header_simple("pid");
		doveadm_print_header_simple("ip");
		doveadm_print_header_simple("dest_ip");
		for (unsigned int i = 0; i < iter->alt_username_fields_count; i++)
			doveadm_print_header_simple(iter->alt_username_fields[i]);
		if (doveadm_who_iter_init_filter(iter, &ctx.filter)) {
			while (doveadm_who_iter_next(iter, &who_line))
				who_print_line(&ctx, iter, &who_line);
		}
	}
	const char *error;
	if (doveadm_who_iter_deinit(&iter, &error) < 0) {
		e_error(cctx->event, "%s", error);
		doveadm_exit_code = EX_TEMPFAIL;
	}

	hash_table_destroy(&ctx.users);
	pool_unref(&ctx.pool);
}

#define DOVEADM_CMD_WHO_FIELDS \
	.cmd = cmd_who, \
	.usage = "[-a <anvil socket path>] [-1] [-f <passdb field>] [<user mask>] [<ip/bits>]", \
DOVEADM_CMD_PARAMS_START \
DOVEADM_CMD_PARAM('a',"socket-path", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('1',"separate-connections", CMD_PARAM_BOOL, 0) \
DOVEADM_CMD_PARAM('f',"passdb-field", CMD_PARAM_STR, 0) \
DOVEADM_CMD_PARAM('\0',"mask", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL) \
DOVEADM_CMD_PARAMS_END

struct doveadm_cmd_ver2 doveadm_cmd_who_ver2 = {
	.name = "who",
	DOVEADM_CMD_WHO_FIELDS
};

struct doveadm_cmd_ver2 doveadm_cmd_proxy_list_ver2 = {
	.name = "proxy list",
	DOVEADM_CMD_WHO_FIELDS
};
