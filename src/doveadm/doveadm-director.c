/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "md5.h"
#include "hash.h"
#include "network.h"
#include "istream.h"
#include "write-full.h"
#include "master-service.h"
#include "auth-master.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

struct director_context {
	const char *socket_path;
	const char *users_path;
	struct istream *input;
	bool explicit_socket_path;
};

struct user_list {
	struct user_list *next;
	const char *name;
};

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

	ctx->input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	director_send(ctx, DIRECTOR_HANDSHAKE);

	alarm(5);
	line = i_stream_read_next_line(ctx->input);
	alarm(0);
	if (line == NULL) {
		if (ctx->input->stream_errno != 0)
			i_fatal("read(%s) failed: %m", ctx->socket_path);
		else if (ctx->input->eof)
			i_fatal("%s disconnected", ctx->socket_path);
		else {
			i_fatal("read(%s) timed out (is director configured?)",
				ctx->socket_path);
		}
	}
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
		default:
			director_cmd_help(cmd);
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

	ctx = cmd_director_init(argc, argv, "a:", cmd_director_status);
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

static unsigned int director_username_hash(const char *username)
{
	unsigned char md5[MD5_RESULTLEN];
	unsigned int i, hash = 0;

	md5_get_digest(username, strlen(username), md5);
	for (i = 0; i < sizeof(hash); i++)
		hash = (hash << CHAR_BIT) | md5[i];
	return hash;
}

static void
user_list_add(const char *username, pool_t pool, struct hash_table *users)
{
	struct user_list *user, *old_user;
	unsigned int user_hash;

	user = p_new(pool, struct user_list, 1);
	user->name = p_strdup(pool, username);
	user_hash = director_username_hash(username);

	old_user = hash_table_lookup(users, POINTER_CAST(user_hash));
	if (old_user != NULL)
		user->next = old_user;
	hash_table_insert(users, POINTER_CAST(user_hash), user);
}

static void
userdb_get_user_list(const char *auth_socket_path, pool_t pool,
		     struct hash_table *users)
{
	struct auth_master_user_list_ctx *ctx;
	struct auth_master_connection *conn;
	const char *username;

	if (auth_socket_path == NULL) {
		auth_socket_path = t_strconcat(doveadm_settings->base_dir,
					       "/auth-userdb", NULL);
	}

	conn = auth_master_init(auth_socket_path, 0);
	ctx = auth_master_user_list_init(conn);
	while ((username = auth_master_user_list_next(ctx)) != NULL)
		user_list_add(username, pool, users);
	if (auth_master_user_list_deinit(&ctx) < 0) {
		i_error("user listing failed");
		exit(1);
	}
	auth_master_deinit(&conn);
}

static void
user_file_get_user_list(const char *path, pool_t pool, struct hash_table *users)
{
	struct istream *input;
	const char *username;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	input = i_stream_create_fd(fd, (size_t)-1, TRUE);
	while ((username = i_stream_read_next_line(input)) != NULL)
		user_list_add(username, pool, users);
	i_stream_unref(&input);
}

static void director_get_host(const char *host, struct ip_addr **ips_r,
			      unsigned int *ips_count_r)
{
	struct ip_addr ip;

	if (net_addr2ip(host, &ip) == 0) {
		*ips_r = t_new(struct ip_addr, 1);
		**ips_r = ip;
		*ips_count_r = 1;
	} else {
		if (net_gethostbyname(host, ips_r, ips_count_r) < 0)
			i_fatal("gethostname(%s) failed: %m", host);
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
	struct hash_table *users;
	struct user_list *user;
	unsigned int ips_count, user_hash, expires;

	ctx = cmd_director_init(argc, argv, "a:f:", cmd_director_map);
	if (argv[optind] == NULL)
		ips_count = 0;
	else if (argv[optind+1] != NULL)
		director_cmd_help(cmd_director_map);
	else
		director_get_host(argv[optind], &ips, &ips_count);

	pool = pool_alloconly_create("director map users", 1024*128);
	users = hash_table_create(default_pool, pool, 0, NULL, NULL);
	if (ctx->users_path == NULL)
		userdb_get_user_list(NULL, pool, users);
	else
		user_file_get_user_list(ctx->users_path, pool, users);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header_simple("user");
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
			args = t_strsplit(line, "\t");
			if (str_array_length(args) < 3 ||
			    str_to_uint(args[0], &user_hash) < 0 ||
			    str_to_uint(args[1], &expires) < 0 ||
			    net_addr2ip(args[2], &user_ip) < 0)
				i_error("Invalid USER-LIST reply: %s", line);
			else if (ips_count == 0 ||
				 ip_find(ips, ips_count, &user_ip)) {
				user = hash_table_lookup(users,
						POINTER_CAST(user_hash));
				if (user == NULL) {
					doveadm_print("<unknown>");
					doveadm_print(args[2]);
					doveadm_print(unixdate2str(expires));
				}
				for (; user != NULL; user = user->next) {
					doveadm_print(user->name);
					doveadm_print(args[2]);
					doveadm_print(unixdate2str(expires));
				}
			}
		} T_END;
	}
	director_disconnect(ctx);
	hash_table_destroy(&users);
	pool_unref(&pool);
}

static void cmd_director_add(int argc, char *argv[])
{
	struct director_context *ctx;
	struct ip_addr *ips;
	unsigned int i, ips_count, vhost_count = -1U;
	const char *host, *cmd, *line;

	ctx = cmd_director_init(argc, argv, "a:", cmd_director_add);
	host = argv[optind++];
	if (host == NULL)
		director_cmd_help(cmd_director_add);
	if (argv[optind] != NULL) {
		if (str_to_uint(argv[optind++], &vhost_count) < 0)
			director_cmd_help(cmd_director_add);
	}
	if (argv[optind] != NULL)
		director_cmd_help(cmd_director_add);

	director_get_host(host, &ips, &ips_count);
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
	const char *host, *line;

	ctx = cmd_director_init(argc, argv, "a:", cmd_director_remove);
	host = argv[optind++];
	if (host == NULL || argv[optind] != NULL)
		director_cmd_help(cmd_director_remove);

	director_get_host(host, &ips, &ips_count);
	for (i = 0; i < ips_count; i++) {
		director_send(ctx, t_strdup_printf(
			"HOST-REMOVE\t%s\n", net_ip2addr(&ips[i])));
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

	user_hash = director_username_hash(argv[optind++]);
	host = argv[optind];

	director_get_host(host, &ips, &ips_count);
	ip_str = net_ip2addr(&ips[0]);
	director_send(ctx, t_strdup_printf(
		"USER-MOVE\t%u\t%s\n", user_hash, ip_str));
	line = i_stream_read_next_line(ctx->input);
	if (line == NULL)
		fprintf(stderr, "failed\n");
	else if (strcmp(line, "OK") == 0) {
		if (doveadm_verbose)
			printf("User hash %u moved to %s\n", user_hash, ip_str);
	} else if (strcmp(line, "NOTFOUND") == 0) {
		fprintf(stderr, "Host '%s' doesn't exist\n", ip_str);
	} else if (strcmp(line, "TRYAGAIN") == 0) {
		fprintf(stderr, "User is already being moved, "
			"wait a while for it to be finished\n");
	} else {
		fprintf(stderr, "failed: %s\n", line);
	}
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

	ctx = cmd_director_init(argc, argv, "a:", cmd_director_flush);
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
			args = t_strsplit(line, "\t");
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
	director_disconnect(ctx);
}

static void cmd_director_ring_status(int argc, char *argv[])
{
	struct director_context *ctx;
	const char *line, *const *args;
	unsigned long l;

	ctx = cmd_director_init(argc, argv, "a:", cmd_director_status);

	doveadm_print_init(DOVEADM_PRINT_TYPE_TABLE);
	doveadm_print_header_simple("director ip");
	doveadm_print_header_simple("port");
	doveadm_print_header_simple("type");
	doveadm_print_header_simple("last failed");

	director_send(ctx, "DIRECTOR-LIST\n");
	while ((line = i_stream_read_next_line(ctx->input)) != NULL) {
		if (*line == '\0')
			break;
		T_BEGIN {
			args = t_strsplit(line, "\t");
			if (str_array_length(args) >= 4 &&
			    str_to_ulong(args[3], &l) == 0) {
				doveadm_print(args[0]);
				doveadm_print(args[1]);
				doveadm_print(args[2]);
				if (l == 0)
					doveadm_print("never");
				else
					doveadm_print(unixdate2str(l));
			}
		} T_END;
	}
	director_disconnect(ctx);
}

struct doveadm_cmd doveadm_cmd_director[] = {
	{ cmd_director_status, "director status",
	  "[-a <director socket path>] [<user>]" },
	{ cmd_director_map, "director map",
	  "[-a <director socket path>] [-f <users file>] [<host>]" },
	{ cmd_director_add, "director add",
	  "[-a <director socket path>] <host> [<vhost count>]" },
	{ cmd_director_remove, "director remove",
	  "[-a <director socket path>] <host>" },
	{ cmd_director_move, "director move",
	  "[-a <director socket path>] <user> <host>" },
	{ cmd_director_flush, "director flush",
	  "[-a <director socket path>] <host>|all" },
	{ cmd_director_dump, "director dump",
	  "[-a <director socket path>]" },
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
