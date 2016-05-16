/* Copyright (c) 2009-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "md5.h"
#include "hash.h"
#include "str.h"
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
	struct istream *input;
	bool explicit_socket_path;
	bool hash_map, user_map, force_flush;
};

struct user_list {
	struct user_list *next;
	const char *name;
};

HASH_TABLE_DEFINE_TYPE(user_list, void *, struct user_list *);

extern struct doveadm_cmd doveadm_cmd_director[];

static void director_cmd_help(doveadm_command_t *cmd) ATTR_NORETURN;

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
cmd_director_init(int argc, char *argv[], const char *getopt_args,
		  doveadm_command_t *cmd)
{
	struct director_context *ctx;
	int c;

	ctx = t_new(struct director_context, 1);
	ctx->socket_path = t_strconcat(doveadm_settings->base_dir,
				       "/director-admin", NULL);

	while ((c = getopt(argc, argv, getopt_args)) > 0) {
		switch (c) {
		case 'a':
			ctx->socket_path = optarg;
			ctx->explicit_socket_path = TRUE;
			break;
		case 'f':
			ctx->users_path = optarg;
			break;
		case 'F':
			ctx->force_flush = TRUE;
			break;
		case 'h':
			ctx->hash_map = TRUE;
			break;
		case 'u':
			ctx->user_map = TRUE;
			break;
		case 't':
			ctx->tag = optarg;
			break;
		default:
			director_cmd_help(cmd);
		}
	}
	if (!ctx->user_map)
		director_connect(ctx);
	return ctx;
}

static void
cmd_director_status_user(struct director_context *ctx, char *argv[])
{
	const char *user = argv[0], *tag = argv[1];
	const char *line, *const *args;
	unsigned int expires;

	director_send(ctx, t_strdup_printf("USER-LOOKUP\t%s\t%s\n", user,
					   tag != NULL ? tag : ""));
	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		i_error("Lookup failed");
		doveadm_exit_code = EX_TEMPFAIL;
		return;
	}

	args = t_strsplit_tab(line);
	if (str_array_length(args) != 4 ||
	    str_to_uint(args[1], &expires) < 0) {
		i_error("Invalid reply from director");
		doveadm_exit_code = EX_PROTOCOL;
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

	ctx = cmd_director_init(argc, argv, "a:t:", cmd_director_status);
	if (argv[optind] != NULL) {
		cmd_director_status_user(ctx, argv+optind);
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

			args = t_strsplit_tab(line);
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
	if (line == NULL) {
		i_error("Director disconnected unexpectedly");
		doveadm_exit_code = EX_TEMPFAIL;
	}
	director_disconnect(ctx);
}

static void
user_list_add(const char *username, pool_t pool,
	      HASH_TABLE_TYPE(user_list) users)
{
	struct user_list *user, *old_user;
	unsigned int user_hash;

	user = p_new(pool, struct user_list, 1);
	user->name = p_strdup(pool, username);
	user_hash = mail_user_hash(username, doveadm_settings->director_username_hash);

	old_user = hash_table_lookup(users, POINTER_CAST(user_hash));
	if (old_user != NULL)
		user->next = old_user;
	hash_table_insert(users, POINTER_CAST(user_hash), user);
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
user_file_get_user_list(const char *path, pool_t pool,
			HASH_TABLE_TYPE(user_list) users)
{
	struct istream *input;
	const char *username;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	input = i_stream_create_fd_autoclose(&fd, (size_t)-1);
	while ((username = i_stream_read_next_line(input)) != NULL)
		user_list_add(username, pool, users);
	i_stream_unref(&input);
}

static void director_get_host(const char *host, struct ip_addr **ips_r,
			      unsigned int *ips_count_r)
{
	struct ip_addr ip;
	int ret;

	if (net_addr2ip(host, &ip) == 0) {
		*ips_r = t_new(struct ip_addr, 1);
		**ips_r = ip;
		*ips_count_r = 1;
	} else {
		ret = net_gethostbyname(host, ips_r, ips_count_r);
		if (ret != 0) {
			i_fatal("gethostname(%s) failed: %s", host,
				net_gethosterror(ret));
		}
	}
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

static void cmd_director_map(int argc, char *argv[])
{
	struct director_context *ctx;
	const char *line, *const *args;
	struct ip_addr *ips, user_ip;
	pool_t pool;
	HASH_TABLE_TYPE(user_list) users;
	struct user_list *user;
	unsigned int ips_count, user_hash, expires;

	ctx = cmd_director_init(argc, argv, "a:f:hu", cmd_director_map);
	argc -= optind;
	argv += optind;
	if (argc > 1 ||
	    (ctx->hash_map && ctx->user_map) ||
	    ((ctx->hash_map || ctx->user_map) && argc == 0))
		director_cmd_help(cmd_director_map);

	if (ctx->user_map) {
		/* user -> hash mapping */
		user_hash = mail_user_hash(argv[0], doveadm_settings->director_username_hash);
		doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
		doveadm_print_header("hash", "hash", DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
		doveadm_print(t_strdup_printf("%u", user_hash));
		director_disconnect(ctx);
		return;
	}

	if (argv[0] == NULL || ctx->hash_map)
		ips_count = 0;
	else
		director_get_host(argv[0], &ips, &ips_count);

	pool = pool_alloconly_create("director map users", 1024*128);
	hash_table_create_direct(&users, pool, 0);
	if (ctx->users_path == NULL)
		userdb_get_user_list(NULL, pool, users);
	else
		user_file_get_user_list(ctx->users_path, pool, users);

	if (ctx->hash_map) {
		/* hash -> usernames mapping */
		if (str_to_uint(argv[0], &user_hash) < 0)
			i_fatal("Invalid username hash: %s", argv[0]);

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
			args = t_strsplit_tab(line);
			if (str_array_length(args) < 3 ||
			    str_to_uint(args[0], &user_hash) < 0 ||
			    str_to_uint(args[1], &expires) < 0 ||
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
	if (line == NULL) {
		i_error("Director disconnected unexpectedly");
		doveadm_exit_code = EX_TEMPFAIL;
	}
deinit:
	director_disconnect(ctx);
	hash_table_destroy(&users);
	pool_unref(&pool);
}

static void
cmd_director_add_or_update(int argc, char *argv[], doveadm_command_t *cmd_func,
			   bool update)
{
	const char *director_cmd = update ? "HOST-UPDATE" : "HOST-SET";
	struct director_context *ctx;
	struct ip_addr *ips;
	unsigned int i, ips_count, vhost_count = UINT_MAX;
	const char *host, *line;
	string_t *cmd;

	ctx = cmd_director_init(argc, argv, update ? "a:" : "a:t:", cmd_func);
	if (ctx->tag != NULL && ctx->tag[0] == '\0')
		ctx->tag = NULL;
	host = argv[optind++];
	if (host == NULL)
		director_cmd_help(cmd_func);
	if (argv[optind] != NULL) {
		if (str_to_uint(argv[optind++], &vhost_count) < 0)
			director_cmd_help(cmd_func);
	} else if (strcmp(director_cmd, "HOST-UPDATE") == 0)
		director_cmd_help(cmd_func);

	if (argv[optind] != NULL)
		director_cmd_help(cmd_func);

	if (ctx->tag == NULL) {
		ctx->tag = strchr(host, '@');
		if (ctx->tag != NULL)
			host = t_strdup_until(host, ctx->tag++);
	}
	director_get_host(host, &ips, &ips_count);
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
		if (line == NULL || strcmp(line, "OK") != 0) {
			fprintf(stderr, "%s: %s\n", net_ip2addr(&ips[i]),
				line == NULL ? "failed" :
				strcmp(line, "NOTFOUND") == 0 ?
				"doesn't exist" : line);
			doveadm_exit_code = EX_TEMPFAIL;
		} else if (doveadm_verbose) {
			printf("%s: OK\n", net_ip2addr(&ips[i]));
		}
	}
	director_disconnect(ctx);
}

static void cmd_director_add(int argc, char *argv[])
{
	cmd_director_add_or_update(argc, argv, cmd_director_add, FALSE);
}

static void cmd_director_update(int argc, char *argv[])
{
	cmd_director_add_or_update(argc, argv, cmd_director_update, TRUE);
}

static void
cmd_director_ipcmd(const char *cmd_name, doveadm_command_t *cmd,
		   const char *success_result, int argc, char *argv[])
{
	struct director_context *ctx;
	struct ip_addr *ips;
	unsigned int i, ips_count;
	const char *host, *line;

	ctx = cmd_director_init(argc, argv, "a:", cmd);
	host = argv[optind++];
	if (host == NULL || argv[optind] != NULL)
		director_cmd_help(cmd);

	director_get_host(host, &ips, &ips_count);
	for (i = 0; i < ips_count; i++) {
		director_send(ctx, t_strdup_printf(
			"%s\t%s\n", cmd_name, net_ip2addr(&ips[i])));
	}
	for (i = 0; i < ips_count; i++) {
		line = i_stream_read_next_line(ctx->input);
		if (line != NULL && strcmp(line, "NOTFOUND") == 0) {
			fprintf(stderr, "%s: doesn't exist\n",
				net_ip2addr(&ips[i]));
			if (doveadm_exit_code == 0)
				doveadm_exit_code = DOVEADM_EX_NOTFOUND;
		} else if (line == NULL || strcmp(line, "OK") != 0) {
			fprintf(stderr, "%s: %s\n", net_ip2addr(&ips[i]),
				line == NULL ? "failed" : line);
			doveadm_exit_code = EX_TEMPFAIL;
		} else if (doveadm_verbose) {
			printf("%s: %s\n", net_ip2addr(&ips[i]), success_result);
		}
	}
	director_disconnect(ctx);
}

static void cmd_director_remove(int argc, char *argv[])
{
	cmd_director_ipcmd("HOST-REMOVE", cmd_director_remove,
			   "removed", argc, argv);
}

static void cmd_director_up(int argc, char *argv[])
{
	cmd_director_ipcmd("HOST-UP", cmd_director_up,
			   "up", argc, argv);
}

static void cmd_director_down(int argc, char *argv[])
{
	cmd_director_ipcmd("HOST-DOWN", cmd_director_down,
			   "down", argc, argv);
}

static void cmd_director_move(int argc, char *argv[])
{
	struct director_context *ctx;
	struct ip_addr *ips;
	unsigned int ips_count, user_hash;
	const char *host, *line, *ip_str;

	ctx = cmd_director_init(argc, argv, "a:", cmd_director_move);
	if (argv[optind] == NULL || argv[optind+1] == NULL ||
	    argv[optind+2] != NULL)
		director_cmd_help(cmd_director_move);

	user_hash = mail_user_hash(argv[optind++], doveadm_settings->director_username_hash);
	host = argv[optind];

	director_get_host(host, &ips, &ips_count);
	ip_str = net_ip2addr(&ips[0]);
	director_send(ctx, t_strdup_printf(
		"USER-MOVE\t%u\t%s\n", user_hash, ip_str));
	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		i_error("failed");
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (strcmp(line, "OK") == 0) {
		if (doveadm_verbose)
			printf("User hash %u moved to %s\n", user_hash, ip_str);
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

static void cmd_director_kick(int argc, char *argv[])
{
	struct director_context *ctx;
	const char *username, *line;

	ctx = cmd_director_init(argc, argv, "a:", cmd_director_kick);
	if (argv[optind] == NULL || argv[optind+1] != NULL)
		director_cmd_help(cmd_director_kick);

	username = argv[optind];

	director_send(ctx, t_strdup_printf("USER-KICK\t%s\n", username));
	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		i_error("failed");
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (strcmp(line, "OK") == 0) {
		if (doveadm_verbose)
			printf("User %s kicked\n", username);
	} else {
		i_error("failed: %s", line);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	director_disconnect(ctx);
}

static void cmd_director_flush_all(struct director_context *ctx)
{
	const char *line;

	director_send(ctx, ctx->force_flush ?
		      "HOST-FLUSH\n" : "HOST-RESET-USERS\n");

	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		i_error("failed");
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (strcmp(line, "OK") != 0) {
		i_error("failed: %s", line);
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (doveadm_verbose)
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
	int ret;

	ctx = cmd_director_init(argc, argv, "a:F", cmd_director_flush);
	host = argv[optind++];
	if (host == NULL || argv[optind] != NULL)
		director_cmd_help(cmd_director_flush);

	if (strcmp(host, "all") == 0) {
		cmd_director_flush_all(ctx);
		return;
	}
	if (net_addr2ip(host, &ip) == 0) {
		ips = &ip;
		ips_count = 1;
	} else {
		ret = net_gethostbyname(host, &ips, &ips_count);
		if (ret != 0) {
			i_fatal("gethostname(%s) failed: %s", host,
				net_gethosterror(ret));
		}
	}

	for (i = 0; i < ips_count; i++) {
		director_send(ctx, t_strdup_printf("%s\t%s\n",
			ctx->force_flush ? "HOST-FLUSH" : "HOST-RESET-USERS",
			net_ip2addr(&ip)));
	}
	for (i = 0; i < ips_count; i++) {
		line = i_stream_read_next_line(ctx->input);
		if (line != NULL && strcmp(line, "NOTFOUND") == 0) {
			fprintf(stderr, "%s: doesn't exist\n",
				net_ip2addr(&ips[i]));
			if (doveadm_exit_code == 0)
				doveadm_exit_code = DOVEADM_EX_NOTFOUND;
		} else if (line == NULL || strcmp(line, "OK") != 0) {
			fprintf(stderr, "%s: %s\n", net_ip2addr(&ips[i]),
				line == NULL ? "failed" : line);
			doveadm_exit_code = EX_TEMPFAIL;
		} else if (doveadm_verbose) {
			printf("%s: flushed\n", net_ip2addr(&ips[i]));
		}
	}
	director_disconnect(ctx);
}

static void ATTR_FORMAT(3, 4)
director_dump_cmd(struct director_context *ctx,
		  const char *cmd, const char *args, ...)
{
	va_list va;

	va_start(va, args);
	printf("doveadm director %s ", cmd);
	if (ctx->explicit_socket_path)
		printf("-a %s ", ctx->socket_path);
	vprintf(args, va);
	putchar('\n');
	va_end(va);
}

static void cmd_director_dump(int argc, char *argv[])
{
	struct director_context *ctx;
	const char *line, *const *args;

	ctx = cmd_director_init(argc, argv, "a:", cmd_director_dump);

	director_send(ctx, "HOST-LIST\n");
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			args = t_strsplit_tab(line);
			if (str_array_length(args) >= 2) {
				director_dump_cmd(ctx, "add", "%s %s",
						  args[0], args[1]);
			}
		} T_END;
	}

	director_send(ctx, "HOST-LIST-REMOVED\n");
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		director_dump_cmd(ctx, "remove", "%s", line);
	}
	if (line == NULL) {
		i_error("Director disconnected unexpectedly");
		doveadm_exit_code = EX_TEMPFAIL;
	}
	director_disconnect(ctx);
}


static void director_read_ok_reply(struct director_context *ctx)
{
	const char *line;

	line = i_stream_read_next_line(ctx->input);
	if (line == NULL) {
		i_error("Director disconnected unexpectedly");
		doveadm_exit_code = EX_TEMPFAIL;
	} else if (strcmp(line, "NOTFOUND") == 0) {
		i_error("Not found");
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	} else if (strcmp(line, "OK") != 0) {
		i_error("Failed: %s", line);
		doveadm_exit_code = EX_TEMPFAIL;
	}
}

static void cmd_director_ring_add(int argc, char *argv[])
{
	struct director_context *ctx;
	struct ip_addr ip;
	in_port_t port = 0;
	string_t *str = t_str_new(64);

	ctx = cmd_director_init(argc, argv, "a:", cmd_director_ring_add);
	if (argv[optind] == NULL ||
	    net_addr2ip(argv[optind], &ip) < 0 ||
	    (argv[optind+1] != NULL && net_str2port(argv[optind+1], &port) < 0))
		director_cmd_help(cmd_director_ring_add);

	str_printfa(str, "DIRECTOR-ADD\t%s", net_ip2addr(&ip));
	if (port != 0)
		str_printfa(str, "\t%u", port);
	str_append_c(str, '\n');
	director_send(ctx, str_c(str));
	director_read_ok_reply(ctx);
	director_disconnect(ctx);
}

static void cmd_director_ring_remove(int argc, char *argv[])
{
	struct director_context *ctx;
	struct ip_addr ip;
	string_t *str = t_str_new(64);
	in_port_t port = 0;

	ctx = cmd_director_init(argc, argv, "a:", cmd_director_ring_remove);
	if (argv[optind] == NULL ||
	    net_addr2ip(argv[optind], &ip) < 0 ||
	    (argv[optind+1] != NULL && net_str2port(argv[optind+1], &port) < 0))
		director_cmd_help(cmd_director_ring_remove);

	str_printfa(str, "DIRECTOR-REMOVE\t%s", net_ip2addr(&ip));
	if (port != 0)
		str_printfa(str, "\t%u", port);
	str_append_c(str, '\n');
	director_send(ctx, str_c(str));
	director_read_ok_reply(ctx);
	director_disconnect(ctx);
}

static void cmd_director_ring_status(int argc, char *argv[])
{
	struct director_context *ctx;
	const char *line, *const *args;
	unsigned long l;

	ctx = cmd_director_init(argc, argv, "a:", cmd_director_ring_status);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header_simple("director ip");
	doveadm_print_header_simple("port");
	doveadm_print_header_simple("type");
	doveadm_print_header_simple("last failed");
	doveadm_print_header_simple("status");

	director_send(ctx, "DIRECTOR-LIST\n");
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			args = t_strsplit_tab(line);
			if (str_array_length(args) >= 5 &&
			    str_to_ulong(args[3], &l) == 0) {
				doveadm_print(args[0]);
				doveadm_print(args[1]);
				doveadm_print(args[2]);
				if (l == 0)
					doveadm_print("never");
				else
					doveadm_print(unixdate2str(l));
				doveadm_print(args[4]);
			}
		} T_END;
	}
	if (line == NULL) {
		i_error("Director disconnected unexpectedly");
		doveadm_exit_code = EX_TEMPFAIL;
	}
	director_disconnect(ctx);
}

struct doveadm_cmd doveadm_cmd_director[] = {
	{ cmd_director_status, "director status",
	  "[-a <director socket path>] [<user>]" },
	{ cmd_director_map, "director map",
	  "[-a <director socket path>] [-f <users file>] [-h | -u] [<host>]" },
	{ cmd_director_add, "director add",
	  "[-a <director socket path>] [-t <tag>] <host> [<vhost count>]" },
	{ cmd_director_update, "director update",
	  "[-a <director socket path>] <host> <vhost count>" },
	{ cmd_director_up, "director up",
	  "[-a <director socket path>] <host>" },
	{ cmd_director_down, "director down",
	  "[-a <director socket path>] <host>" },
	{ cmd_director_remove, "director remove",
	  "[-a <director socket path>] <host>" },
	{ cmd_director_move, "director move",
	  "[-a <director socket path>] <user> <host>" },
	{ cmd_director_kick, "director kick",
	  "[-a <director socket path>] <user>" },
	{ cmd_director_flush, "director flush",
	  "[-a <director socket path>] [-f] <host>|all" },
	{ cmd_director_dump, "director dump",
	  "[-a <director socket path>]" },
	{ cmd_director_ring_add, "director ring add",
	  "[-a <director socket path>] <ip> [<port>]" },
	{ cmd_director_ring_remove, "director ring remove",
	  "[-a <director socket path>] <ip> [<port>]" },
	{ cmd_director_ring_status, "director ring status",
	  "[-a <director socket path>]" }
};

static void director_cmd_help(doveadm_command_t *cmd)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_director); i++) {
		if (doveadm_cmd_director[i].cmd == cmd)
			help(&doveadm_cmd_director[i]);
	}
	i_unreached();
}

void doveadm_register_director_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_director); i++)
		doveadm_register_cmd(&doveadm_cmd_director[i]);
}
