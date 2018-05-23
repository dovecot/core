/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "md5.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "net.h"
#include "istream.h"
#include "write-full.h"
#include "master-service.h"
#include "auth-master.h"
#include "mail-user-hash.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

struct director_context {
	const char *socket_path;
	const char *users_path;
	const char *tag;
	const char *user;
	const char *host;
	const char *ip;
	const char *port;
	const char *vhost_count;
	const char *passdb_field;

	struct istream *users_input;
	struct istream *input;
	bool explicit_socket_path;
	bool hash_map, user_map, force_flush;
	int64_t max_parallel;
};

struct user_list {
	struct user_list *next;
	const char *name;
};

HASH_TABLE_DEFINE_TYPE(user_list, void *, struct user_list *);

static void director_cmd_help(const struct doveadm_cmd_ver2 *);
static int director_get_host(const char *host, struct ip_addr **ips_r,
                              unsigned int *ips_count_r) ATTR_WARN_UNUSED_RESULT;
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

	fd = doveadm_connect(ctx->socket_path);
	net_set_nonblock(fd, FALSE);

	ctx->input = i_stream_create_fd_autoclose(&fd, (size_t)-1);
	director_send(ctx, DIRECTOR_HANDSHAKE);

	alarm(5);
	line = i_stream_read_next_line(ctx->input);
	alarm(0);
	if (line == NULL) {
		if (ctx->input->stream_errno != 0) {
			i_fatal("read(%s) failed: %s", ctx->socket_path,
				i_stream_get_error(ctx->input));
		} else if (ctx->input->eof) {
			i_fatal("%s disconnected", ctx->socket_path);
		} else {
			i_fatal("read(%s) timed out (is director configured?)",
				ctx->socket_path);
		}
	}
	if (!version_string_verify(line, "director-doveadm", 1)) {
		i_fatal_status(EX_PROTOCOL,
			       "%s not a compatible director-doveadm socket",
			       ctx->socket_path);
	}
}

static void director_disconnect(struct director_context *ctx)
{
	if (ctx->input != NULL) {
		if (ctx->input->stream_errno != 0) {
			i_fatal("read(%s) failed: %s", ctx->socket_path,
				i_stream_get_error(ctx->input));
		}
		i_stream_destroy(&ctx->input);
	}
}

static struct director_context *
cmd_director_init(struct doveadm_cmd_context *cctx)
{
	struct director_context *ctx;
	ctx = t_new(struct director_context, 1);
	if (!doveadm_cmd_param_str(cctx, "socket-path", &(ctx->socket_path)))
		ctx->socket_path = t_strconcat(doveadm_settings->base_dir,
					"/director-admin", NULL);
	else
		ctx->explicit_socket_path = TRUE;
	if (!doveadm_cmd_param_bool(cctx, "user-map", &(ctx->user_map)))
		ctx->user_map = FALSE;
	if (!doveadm_cmd_param_bool(cctx, "hash-map", &(ctx->hash_map)))
		ctx->hash_map = FALSE;
	if (!doveadm_cmd_param_bool(cctx, "force-flush", &(ctx->force_flush)))
		ctx->force_flush = FALSE;
	if (!doveadm_cmd_param_istream(cctx, "users-file", &(ctx->users_input)))
		ctx->users_input = NULL;
	if (!doveadm_cmd_param_str(cctx, "tag", &(ctx->tag)))
		ctx->tag = NULL;
	if (!doveadm_cmd_param_str(cctx, "user", &(ctx->user)))
		ctx->user = NULL;
	if (!doveadm_cmd_param_str(cctx, "host", &(ctx->host)))
		ctx->host = NULL;
	if (!doveadm_cmd_param_str(cctx, "ip", &(ctx->ip)))
		ctx->ip = NULL;
	if (!doveadm_cmd_param_str(cctx, "port", &(ctx->port)))
		ctx->port = NULL;
	if (!doveadm_cmd_param_str(cctx, "vhost-count", &(ctx->vhost_count)))
		ctx->vhost_count = NULL;
	if (!doveadm_cmd_param_str(cctx, "passdb-field", &(ctx->passdb_field)))
		ctx->passdb_field = NULL;
	if (!doveadm_cmd_param_int64(cctx, "max-parallel", &(ctx->max_parallel)))
		ctx->max_parallel = 0;
	if (!ctx->user_map)
		director_connect(ctx);
	return ctx;
}

static void director_disconnected(struct director_context *ctx)
{
	i_assert(ctx->input->eof);
	if (ctx->input->stream_errno != 0) {
		i_error("read(%s) failed: %s", ctx->socket_path,
			i_stream_get_error(ctx->input));
	} else {
		i_error("%s unexpectedly disconnected", ctx->socket_path);
	}
	doveadm_exit_code = EX_TEMPFAIL;
}

static void
cmd_director_status_user(struct director_context *ctx)
{
	const char *line, *const *args;
	time_t expires;

	director_send(ctx, t_strdup_printf("USER-LOOKUP\t%s\t%s\n", ctx->user,
					   ctx->tag != NULL ? ctx->tag : ""));
	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		director_disconnected(ctx);
		return;
	}

	args = t_strsplit_tabescaped(line);
	if (str_array_length(args) != 4 ||
	    str_to_time(args[1], &expires) < 0) {
		i_error("Invalid reply from director");
		doveadm_exit_code = EX_PROTOCOL;
		return;
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_FORMATTED);

	doveadm_print_header_simple("status");
	doveadm_print_header_simple("expires");
	doveadm_print_header_simple("hashed");
	doveadm_print_header_simple("initial-config");

	doveadm_print_formatted_set_format("Current: %{status} (expires %{expires})\n" \
					   "Hashed: %{hashed}\n" \
					   "Initial config: %{initial-config}\n");

	if (args[0][0] != '\0') {
		doveadm_print(args[0]);
		doveadm_print(unixdate2str(expires));
	} else {
		doveadm_print("n/a");
		doveadm_print("-1");
	}
	doveadm_print(args[2]);
	doveadm_print(args[3]);

	director_disconnect(ctx);
}

static void cmd_director_status(struct doveadm_cmd_context *cctx)
{
	struct director_context *ctx;
	const char *line, *const *args;

	ctx = cmd_director_init(cctx);
	if (ctx->user != NULL) {
		cmd_director_status_user(ctx);
		return;
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header_simple("mail server ip");
	doveadm_print_header_simple("tag");
	doveadm_print_header_simple("vhosts");
	doveadm_print_header_simple("state");
	doveadm_print_header("state-changed", "state changed", 0);
	doveadm_print_header_simple("users");

	director_send(ctx, "HOST-LIST\n");
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			unsigned int arg_count;
			time_t ts;

			args = t_strsplit_tabescaped(line);
			arg_count = str_array_length(args);
			if (arg_count >= 6) {
				/* ip vhosts users tag updown updown-ts */
				doveadm_print(args[0]); 
				doveadm_print(args[3]);
				doveadm_print(args[1]);
				doveadm_print(args[4][0] == 'D' ? "down" : "up");
				if (str_to_time(args[5], &ts) < 0 ||
				    ts <= 0)
					doveadm_print("-");
				else
					doveadm_print(unixdate2str(ts));
				doveadm_print(args[2]);
			}
		} T_END;
	}
	if (line == NULL)
		director_disconnected(ctx);
	director_disconnect(ctx);
}

static bool user_hash_expand(const char *username, unsigned int *hash_r)
{
	const char *error;

	if (!mail_user_hash(username, doveadm_settings->director_username_hash,
			    hash_r, &error)) {
		i_error("Failed to expand director_username_hash=%s: %s",
			doveadm_settings->director_username_hash, error);
		return FALSE;
	}
	return TRUE;
}

static void
user_list_add(const char *username, pool_t pool,
	      HASH_TABLE_TYPE(user_list) users)
{
	struct user_list *user, *old_user;
	unsigned int user_hash;

	if (!user_hash_expand(username, &user_hash))
		return;

	user = p_new(pool, struct user_list, 1);
	user->name = p_strdup(pool, username);

	old_user = hash_table_lookup(users, POINTER_CAST(user_hash));
	if (old_user != NULL)
		user->next = old_user;
	hash_table_update(users, POINTER_CAST(user_hash), user);
}

static void ATTR_NULL(1)
userdb_get_user_list(const char *auth_socket_path, pool_t pool,
		     HASH_TABLE_TYPE(user_list) users)
{
	struct auth_master_user_list_ctx *ctx;
	struct auth_master_connection *conn;
	const char *username;

	if (auth_socket_path == NULL) {
		auth_socket_path = t_strconcat(doveadm_settings->base_dir,
					       "/auth-userdb", NULL);
	}

	conn = auth_master_init(auth_socket_path, 0);
	ctx = auth_master_user_list_init(conn, "", NULL);
	while ((username = auth_master_user_list_next(ctx)) != NULL)
		user_list_add(username, pool, users);
	if (auth_master_user_list_deinit(&ctx) < 0) {
		i_error("user listing failed");
		doveadm_exit_code = EX_TEMPFAIL;
	}
	auth_master_deinit(&conn);
}

static void
user_file_get_user_list(struct istream *input, pool_t pool,
			HASH_TABLE_TYPE(user_list) users)
{
	const char *username;

	while ((username = i_stream_read_next_line(input)) != NULL)
		user_list_add(username, pool, users);
}

static int director_get_host(const char *host, struct ip_addr **ips_r,
			      unsigned int *ips_count_r)
{
	struct ip_addr ip;
	int ret = 0;

	if (net_addr2ip(host, &ip) == 0) {
		*ips_r = t_new(struct ip_addr, 1);
		**ips_r = ip;
		*ips_count_r = 1;
	} else {
		ret = net_gethostbyname(host, ips_r, ips_count_r);
		if (ret != 0) {
			i_error("gethostname(%s) failed: %s", host,
				net_gethosterror(ret));
			doveadm_exit_code = EX_TEMPFAIL;
			return ret;
		}
	}

	return ret;
}

static bool ip_find(const struct ip_addr *ips, unsigned int ips_count,
		    const struct ip_addr *match_ip)
{
	unsigned int i;

	for (i = 0; i < ips_count; i++) {
		if (net_ip_compare(&ips[i], match_ip))
			return TRUE;
	}
	return FALSE;
}

static void cmd_director_map(struct doveadm_cmd_context *cctx)
{
	struct director_context *ctx;
	const char *line, *const *args;
	struct ip_addr *ips, user_ip;
	pool_t pool;
	HASH_TABLE_TYPE(user_list) users;
	struct user_list *user;
	unsigned int ips_count, user_hash;
	time_t expires;

	ctx = cmd_director_init(cctx);

	if ((ctx->hash_map || ctx->user_map) && ctx->host == NULL) {
		director_cmd_help(cctx->cmd);
	return;
	}

	if (ctx->user_map) {
		/* user -> hash mapping */
		if (user_hash_expand(ctx->host, &user_hash)) {
			doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
			doveadm_print_header("hash", "hash", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
			doveadm_print(t_strdup_printf("%u", user_hash));
		}
		director_disconnect(ctx);
		return;
	}

	if (ctx->host == NULL || ctx->hash_map)
		ips_count = 0;
	else if (director_get_host(ctx->host, &ips, &ips_count) != 0) {
		director_disconnect(ctx);
		return;
	}

	pool = pool_alloconly_create("director map users", 1024*128);
	hash_table_create_direct(&users, pool, 0);
	if (ctx->users_input == NULL)
		userdb_get_user_list(NULL, pool, users);
	else
		user_file_get_user_list(ctx->users_input, pool, users);

	if (ctx->hash_map) {
		/* hash -> usernames mapping */
		if (str_to_uint(ctx->host, &user_hash) < 0)
			i_fatal("Invalid username hash: %s", ctx->host);

		doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
		doveadm_print_header("user", "user", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
		user = hash_table_lookup(users, POINTER_CAST(user_hash));
		for (; user != NULL; user = user->next)
			doveadm_print(user->name);
		goto deinit;
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header("user", "user", DOVEADM_PRINT_HEADER_FLAG_EXPAND);
	doveadm_print_header_simple("hash");
	doveadm_print_header_simple("mail server ip");
	doveadm_print_header_simple("expire time");

	if (ips_count != 1)
		director_send(ctx, "USER-LIST\n");
	else {
		director_send(ctx, t_strdup_printf(
			"USER-LIST\t%s\n", net_ip2addr(&ips[0])));
	}
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			args = t_strsplit_tabescaped(line);
			if (str_array_length(args) < 3 ||
			    str_to_uint(args[0], &user_hash) < 0 ||
			    str_to_time(args[1], &expires) < 0 ||
			    net_addr2ip(args[2], &user_ip) < 0) {
				i_error("Invalid USER-LIST reply: %s", line);
				doveadm_exit_code = EX_PROTOCOL;
			} else if (ips_count == 0 ||
				 ip_find(ips, ips_count, &user_ip)) {
				user = hash_table_lookup(users,
							 POINTER_CAST(user_hash));
				if (user == NULL) {
					doveadm_print("<unknown>");
					doveadm_print(args[0]);
					doveadm_print(args[2]);
					doveadm_print(unixdate2str(expires));
				}
				for (; user != NULL; user = user->next) {
					doveadm_print(user->name);
					doveadm_print(args[0]);
					doveadm_print(args[2]);
					doveadm_print(unixdate2str(expires));
				}
			}
		} T_END;
	}
	if (line == NULL)
		director_disconnected(ctx);
deinit:
	director_disconnect(ctx);
	hash_table_destroy(&users);
	pool_unref(&pool);
}

static void
cmd_director_add_or_update(struct doveadm_cmd_context *cctx, bool update)
{
	const char *director_cmd = update ? "HOST-UPDATE" : "HOST-SET";
	struct director_context *ctx;
	struct ip_addr *ips;
	unsigned int i, ips_count, vhost_count = UINT_MAX;
	const char *line, *host;
	string_t *cmd;

	ctx = cmd_director_init(cctx);
	if (ctx->tag != NULL && ctx->tag[0] == '\0')
		ctx->tag = NULL;
	if (ctx->host == NULL) {
		director_cmd_help(cctx->cmd);
		return;
	}
	if (ctx->vhost_count != NULL) {
		if (str_to_uint(ctx->vhost_count, &vhost_count) < 0) {
			director_cmd_help(cctx->cmd);
			return;
		}
	} else if (update) {
		director_cmd_help(cctx->cmd);
		return;
	}
	if (str_to_uint(ctx->host, &i) == 0) {
		/* host is a number. this would translate to an IP address,
		   which is probably a mistake. */
		i_error("Invalid host '%s'", ctx->host);
		director_cmd_help(cctx->cmd);
		return;
	}

	host = ctx->host;
	if (ctx->tag == NULL) {
		ctx->tag = strchr(ctx->host, '@');
		if (ctx->tag != NULL)
			host = t_strdup_until(ctx->host, ctx->tag++);
	}
	if (director_get_host(host, &ips, &ips_count) != 0) {
		director_disconnect(ctx);
		return;
	}
	cmd = t_str_new(128);
	for (i = 0; i < ips_count; i++) {
		str_truncate(cmd, 0);
		str_printfa(cmd, "%s\t%s", director_cmd, net_ip2addr(&ips[i]));
		if (ctx->tag != NULL)
			str_printfa(cmd, "@%s", ctx->tag);
		if (vhost_count != UINT_MAX)
			str_printfa(cmd, "\t%u", vhost_count);
		str_append_c(cmd, '\n');
		director_send(ctx, str_c(cmd));
	}
	for (i = 0; i < ips_count; i++) {
		line = i_stream_read_next_line(ctx->input);
		if (line == NULL)
			director_disconnected(ctx);
		else if (strcmp(line, "OK") != 0) {
			i_error("%s: %s", net_ip2addr(&ips[i]),
				strcmp(line, "NOTFOUND") == 0 ?
				"doesn't exist" : line);
			doveadm_exit_code = EX_TEMPFAIL;
		} else if (doveadm_verbose) {
			i_info("%s: OK", net_ip2addr(&ips[i]));
		}
	}
	director_disconnect(ctx);
}

static void cmd_director_add(struct doveadm_cmd_context *cctx)
{
	cmd_director_add_or_update(cctx, FALSE);
}

static void cmd_director_update(struct doveadm_cmd_context *cctx)
{
	cmd_director_add_or_update(cctx, TRUE);
}

static void
cmd_director_ipcmd(const char *cmd_name, const char *success_result,
	struct doveadm_cmd_context *cctx)
{
	struct director_context *ctx;
	struct ip_addr *ips;
	unsigned int i, ips_count;
	const char *host, *line;

	ctx = cmd_director_init(cctx);
	host = ctx->host;
	if (host == NULL) {
		director_cmd_help(cctx->cmd);
		return;
	}

	if (director_get_host(host, &ips, &ips_count) != 0) {
		director_disconnect(ctx);
		return;
	}
	for (i = 0; i < ips_count; i++) {
		director_send(ctx, t_strdup_printf(
			"%s\t%s\n", cmd_name, net_ip2addr(&ips[i])));
	}
	for (i = 0; i < ips_count; i++) {
		line = i_stream_read_next_line(ctx->input);
		if (line != NULL && strcmp(line, "NOTFOUND") == 0) {
			i_error("%s: doesn't exist",
				net_ip2addr(&ips[i]));
			if (doveadm_exit_code == 0)
				doveadm_exit_code = DOVEADM_EX_NOTFOUND;
		} else if (line == NULL) {
			director_disconnected(ctx);
		} else if (strcmp(line, "OK") != 0) {
			i_error("%s: %s", net_ip2addr(&ips[i]), line);
			doveadm_exit_code = EX_TEMPFAIL;
		} else if (doveadm_verbose) {
			i_info("%s: %s", net_ip2addr(&ips[i]), success_result);
		}
	}
	director_disconnect(ctx);
}

static void cmd_director_remove(struct doveadm_cmd_context *cctx)
{
	cmd_director_ipcmd("HOST-REMOVE", "removed", cctx);
}

static void cmd_director_up(struct doveadm_cmd_context *cctx)
{
	cmd_director_ipcmd("HOST-UP", "up", cctx);
}

static void cmd_director_down(struct doveadm_cmd_context *cctx)
{
	cmd_director_ipcmd("HOST-DOWN", "down", cctx);
}

static void cmd_director_move(struct doveadm_cmd_context *cctx)
{
	struct director_context *ctx;
	struct ip_addr *ips;
	unsigned int ips_count, user_hash;
	const char *line, *ip_str;

	ctx = cmd_director_init(cctx);
	if (ctx->user == NULL || ctx->host == NULL) {
		director_cmd_help(cctx->cmd);
		return;
	}

	if (!user_hash_expand(ctx->user, &user_hash) ||
	    director_get_host(ctx->host, &ips, &ips_count) != 0) {
		director_disconnect(ctx);
		return;
	}
	ip_str = net_ip2addr(&ips[0]);
	director_send(ctx, t_strdup_printf(
		"USER-MOVE\t%u\t%s\n", user_hash, ip_str));
	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		director_disconnected(ctx);
	} else if (strcmp(line, "OK") == 0) {
		if (doveadm_verbose)
			i_info("User hash %u moved to %s", user_hash, ip_str);
	} else if (strcmp(line, "NOTFOUND") == 0) {
		i_error("Host '%s' doesn't exist", ip_str);
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	} else if (strcmp(line, "TRYAGAIN") == 0) {
		i_error("User is already being moved, "
			"wait a while for it to be finished");
		doveadm_exit_code = EX_TEMPFAIL;
	} else {
		i_error("failed: %s", line);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	director_disconnect(ctx);
}

static void cmd_director_kick(struct doveadm_cmd_context *cctx)
{
	struct director_context *ctx;
	const char *line;
	string_t *cmd = t_str_new(64);

	ctx = cmd_director_init(cctx);
	if (ctx->user == NULL) {
		director_cmd_help(cctx->cmd);
		return;
	}

	if (ctx->passdb_field == NULL) {
		str_append(cmd, "USER-KICK\t");
		str_append_tabescaped(cmd, ctx->user);
		str_append_c(cmd, '\n');
	} else {
		str_append(cmd, "USER-KICK-ALT\t");
		str_append_tabescaped(cmd, ctx->passdb_field);
		str_append_c(cmd, '\t');
		str_append_tabescaped(cmd, ctx->user);
		str_append_c(cmd, '\n');
	}
	director_send(ctx, str_c(cmd));

	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		director_disconnected(ctx);
	} else if (strcmp(line, "OK") == 0) {
		if (doveadm_verbose)
			i_info("User %s kicked", ctx->user);
	} else {
		i_error("failed: %s", line);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	director_disconnect(ctx);
}

static void cmd_director_flush_all(struct director_context *ctx)
{
	const char *line;

	if (ctx->force_flush)
		line = "HOST-FLUSH\n";
	else if (ctx->max_parallel > 0) {
		line = t_strdup_printf("HOST-RESET-USERS\t\t%lld\n",
				       (long long)ctx->max_parallel);
	} else {
		line = "HOST-RESET-USERS\n";
	}
	director_send(ctx, line);

	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		director_disconnected(ctx);
	} else if (strcmp(line, "OK") != 0) {
		i_error("failed: %s", line);
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (doveadm_verbose)
		i_info("flushed");
	director_disconnect(ctx);
}

static void cmd_director_flush(struct doveadm_cmd_context *cctx)
{
	struct director_context *ctx;
	struct ip_addr *ips;
	unsigned int i, ips_count;
	struct ip_addr ip;
	const char *line;
	string_t *cmd;

	ctx = cmd_director_init(cctx);
	if (ctx->host == NULL) {
		director_cmd_help(cctx->cmd);
		return;
	}

	if (strcmp(ctx->host, "all") == 0) {
		cmd_director_flush_all(ctx);
		return;
	}
	if (net_addr2ip(ctx->host, &ip) == 0) {
		ips = &ip;
		ips_count = 1;
	} else if (director_get_host(ctx->host, &ips, &ips_count) != 0) {
		director_disconnect(ctx);
		return;
	}

	cmd = t_str_new(64);
	for (i = 0; i < ips_count; i++) {
		ip = ips[i];
		str_truncate(cmd, 0);
		if (ctx->force_flush)
			str_printfa(cmd, "HOST-FLUSH\t%s\n", net_ip2addr(&ip));
		else {
			str_printfa(cmd, "HOST-RESET-USERS\t%s", net_ip2addr(&ip));
			if (ctx->max_parallel > 0) {
				str_printfa(cmd, "\t%lld",
					    (long long)ctx->max_parallel);
			}
			str_append_c(cmd, '\n');
		}
		director_send(ctx, str_c(cmd));
	}
	for (i = 0; i < ips_count; i++) {
		line = i_stream_read_next_line(ctx->input);
		if (line != NULL && strcmp(line, "NOTFOUND") == 0) {
			i_warning("%s: doesn't exist",
				net_ip2addr(&ips[i]));
			if (doveadm_exit_code == 0)
				doveadm_exit_code = DOVEADM_EX_NOTFOUND;
		} else if (line == NULL) {
			director_disconnected(ctx);
		} else if (strcmp(line, "OK") != 0) {
			i_warning("%s: %s", net_ip2addr(&ips[i]), line);
			doveadm_exit_code = EX_TEMPFAIL;
		} else if (doveadm_verbose) {
			i_info("%s: flushed", net_ip2addr(&ips[i]));
		}
	}
	director_disconnect(ctx);
}

static void cmd_director_dump(struct doveadm_cmd_context *cctx)
{
	struct director_context *ctx;
	const char *line, *const *args;

	ctx = cmd_director_init(cctx);

	doveadm_print_init(DOVEADM_PRINT_TYPE_FORMATTED);
	if (ctx->explicit_socket_path)
		doveadm_print_formatted_set_format("doveadm director %{command} -a %{socket-path} %{host} %{vhost_count}\n");
	else
		doveadm_print_formatted_set_format("doveadm director %{command} %{host} %{vhost_count}\n");

	doveadm_print_header_simple("command");
	doveadm_print_header_simple("socket-path");
	doveadm_print_header_simple("host");
	doveadm_print_header_simple("vhost_count");

	director_send(ctx, "HOST-LIST\n");
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			args = t_strsplit_tabescaped(line);
			if (str_array_length(args) >= 2) {
				const char *host = args[0];
				const char *tag = args[3];
				/* this is guaranteed to be at least NULL */
				if (tag != NULL &&
				    *tag != '\0')
					host = t_strdup_printf("%s@%s", host,
							       tag);
				doveadm_print("add");
				doveadm_print(ctx->socket_path);
				doveadm_print(host);
				doveadm_print(args[1]);
			}
		} T_END;
	}

	director_send(ctx, "HOST-LIST-REMOVED\n");
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		doveadm_print("remove");
		doveadm_print(ctx->socket_path);
		doveadm_print(line);
		doveadm_print("");
	}
	if (line == NULL)
		director_disconnected(ctx);
	director_disconnect(ctx);
}


static void director_read_ok_reply(struct director_context *ctx)
{
	const char *line;

	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		director_disconnected(ctx);
	} else if (strcmp(line, "NOTFOUND") == 0) {
		i_error("Not found");
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	} else if (strcmp(line, "OK") != 0) {
		i_error("Failed: %s", line);
		doveadm_exit_code = EX_TEMPFAIL;
	}
}

static void cmd_director_ring_add(struct doveadm_cmd_context *cctx)
{
	struct director_context *ctx;
	struct ip_addr ip;
	in_port_t port = 0;
	string_t *str = t_str_new(64);

	ctx = cmd_director_init(cctx);
	if (ctx->ip == NULL ||
	    net_addr2ip(ctx->ip, &ip) < 0 ||
	    (ctx->port != 0 && net_str2port(ctx->port, &port) < 0)) {
		director_cmd_help(cctx->cmd);
		return;
	}

	str_printfa(str, "DIRECTOR-ADD\t%s", net_ip2addr(&ip));
	if (port != 0)
		str_printfa(str, "\t%u", port);
	str_append_c(str, '\n');
	director_send(ctx, str_c(str));
	director_read_ok_reply(ctx);
	director_disconnect(ctx);
}

static void cmd_director_ring_remove(struct doveadm_cmd_context *cctx)
{
	struct director_context *ctx;
	struct ip_addr ip;
	string_t *str = t_str_new(64);
	in_port_t port = 0;

	ctx = cmd_director_init(cctx);
	if (ctx->ip == NULL ||
	    net_addr2ip(ctx->ip, &ip) < 0 ||
	    (ctx->port != NULL && net_str2port(ctx->port, &port) < 0)) {
		director_cmd_help(cctx->cmd);
		return;
	}

	str_printfa(str, "DIRECTOR-REMOVE\t%s", net_ip2addr(&ip));
	if (port != 0)
		str_printfa(str, "\t%u", port);
	str_append_c(str, '\n');
	director_send(ctx, str_c(str));
	director_read_ok_reply(ctx);
	director_disconnect(ctx);
}

static void cmd_director_ring_status(struct doveadm_cmd_context *cctx)
{
	struct director_context *ctx;
	const char *line, *const *args;

	ctx = cmd_director_init(cctx);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header_simple("director ip");
	doveadm_print_header_simple("port");
	doveadm_print_header_simple("type");
	doveadm_print_header_simple("last failed");
	doveadm_print_header_simple("status");
	doveadm_print_header_simple("ping ms");
	doveadm_print_header_simple("input");
	doveadm_print_header_simple("output");
	doveadm_print_header_simple("buffered");
	doveadm_print_header_simple("buffered peak");
	doveadm_print_header_simple("last read");
	doveadm_print_header_simple("last write");

	director_send(ctx, "DIRECTOR-LIST\n");
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			unsigned int i;
			time_t ts;

			args = t_strsplit_tabescaped(line);
			for (i = 0; i < 12 && args[i] != NULL; i++) {
				if ((i == 3 || i == 10 || i == 11) &&
				    str_to_time(args[i], &ts) == 0) {
					if (ts == 0)
						doveadm_print("never");
					else
						doveadm_print(unixdate2str(ts));
				} else {
					doveadm_print(args[i]);
				}
			}
			for (; i < 12; i++)
				doveadm_print("-");
		} T_END;
	}
	if (line == NULL)
		director_disconnected(ctx);
	director_disconnect(ctx);
}

struct doveadm_cmd_ver2 doveadm_cmd_director[] = {
{
	.name = "director status",
	.cmd = cmd_director_status,
	.usage = "[-a <director socket path>] [<user>] [<tag>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "tag", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director map",
	.cmd = cmd_director_map,
	.usage = "[-a <director socket path>] [-f <users file>] [-h | -u] [<host>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('f', "users-file", CMD_PARAM_ISTREAM, 0)
DOVEADM_CMD_PARAM('h', "hash-map", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('u', "user-map", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "host", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director add",
	.cmd = cmd_director_add,
	.usage = "[-a <director socket path>] [-t <tag>] <host> [<vhost count>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('t', "tag", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "host", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "vhost-count", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director update",
	.cmd = cmd_director_update,
	.usage = "[-a <director socket path>] <host> <vhost count>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "host", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "vhost-count", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director up",
	.cmd = cmd_director_up,
	.usage = "[-a <director socket path>] <host>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "host", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director down",
	.cmd = cmd_director_down,
	.usage = "[-a <director socket path>] <host>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "host", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director remove",
	.cmd = cmd_director_remove,
	.usage = "[-a <director socket path>] <host>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "host", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director move",
	.cmd = cmd_director_move,
	.usage = "[-a <director socket path>] <user> <host>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "host", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director kick",
	.cmd = cmd_director_kick,
	.usage = "[-a <director socket path>] [-f <passdb field>] <user>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('f', "passdb-field", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "user", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director flush",
	.cmd = cmd_director_flush,
	.usage = "[-a <director socket path>] [-F] [--max-parallel <n>] <host>|all",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('F', "force-flush", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "max-parallel", CMD_PARAM_INT64, 0)
DOVEADM_CMD_PARAM('\0', "host", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director dump",
	.cmd = cmd_director_dump,
	.usage = "[-a <director socket path>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director ring add",
	.cmd = cmd_director_ring_add,
	.usage = "[-a <director socket path>] <ip> [<port>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "ip", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "port", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director ring remove",
	.cmd = cmd_director_ring_remove,
	.usage = "[-a <director socket path>] <ip> [<port>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAM('\0', "ip", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "port", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
},
{
	.name = "director ring status",
	.cmd = cmd_director_ring_status,
	.usage = "[-a <director socket path>]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('a', "socket-path", CMD_PARAM_STR, 0)
DOVEADM_CMD_PARAMS_END
}
};

static void director_cmd_help(const struct doveadm_cmd_ver2 *cmd)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_director); i++) {
		if (doveadm_cmd_director[i].cmd == cmd->cmd)
			help_ver2(&doveadm_cmd_director[i]);
	}
	i_unreached();
}

void doveadm_register_director_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_director); i++)
		doveadm_cmd_register_ver2(&doveadm_cmd_director[i]);
}
