/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "ioloop.h"
#include "master-service.h"
#include "auth-master.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "server-connection.h"
#include "doveadm-settings.h"
#include "doveadm-print.h"
#include "doveadm-server.h"
#include "doveadm-mail.h"

#define DOVEADM_SERVER_CONNECTIONS_MAX 4
#define DOVEADM_SERVER_QUEUE_MAX 16

#define DOVEADM_MAIL_SERVER_FAILED() \
	(internal_failure || master_service_is_killed(master_service))

struct doveadm_mail_server_cmd {
	struct server_connection *conn;
	char *username;
};

static HASH_TABLE(char *, struct doveadm_server *) servers;
static pool_t server_pool;
static struct doveadm_mail_cmd_context *cmd_ctx;
static bool internal_failure = FALSE;

static void doveadm_mail_server_handle(struct server_connection *conn,
				       const char *username);

static struct doveadm_server *
doveadm_server_get(struct doveadm_mail_cmd_context *ctx, const char *name)
{
	struct doveadm_server *server;
	const char *p;
	char *dup_name;

	if (!hash_table_is_created(servers)) {
		server_pool = pool_alloconly_create("doveadm servers", 1024*16);
		hash_table_create(&servers, server_pool, 0, str_hash, strcmp);
	}
	server = hash_table_lookup(servers, name);
	if (server == NULL) {
		server = p_new(server_pool, struct doveadm_server, 1);
		server->name = dup_name = p_strdup(server_pool, name);
		p = strrchr(server->name, ':');
		server->hostname = p == NULL ? server->name :
			p_strdup_until(server_pool, server->name, p);

		p_array_init(&server->connections, server_pool,
			     ctx->set->doveadm_worker_count);
		p_array_init(&server->queue, server_pool,
			     DOVEADM_SERVER_QUEUE_MAX);
		hash_table_insert(servers, dup_name, server);
	}
	return server;
}

static struct server_connection *
doveadm_server_find_unused_conn(struct doveadm_server *server)
{
	struct server_connection *const *connp;

	array_foreach(&server->connections, connp) {
		if (server_connection_is_idle(*connp))
			return *connp;
	}
	return NULL;
}

static bool doveadm_server_have_used_connections(struct doveadm_server *server)
{
	struct server_connection *const *connp;

	array_foreach(&server->connections, connp) {
		if (!server_connection_is_idle(*connp))
			return TRUE;
	}
	return FALSE;
}

static void doveadm_cmd_callback(int exit_code, const char *error,
				 void *context)
{
	struct doveadm_mail_server_cmd *servercmd = context;
	struct doveadm_server *server =
		server_connection_get_server(servercmd->conn);
	const char *username = t_strdup(servercmd->username);

	i_free(servercmd->username);
	i_free(servercmd);

	switch (exit_code) {
	case 0:
		break;
	case SERVER_EXIT_CODE_DISCONNECTED:
		i_error("%s: Command %s failed for %s: %s",
			server->name, cmd_ctx->cmd->name, username, error);
		internal_failure = TRUE;
		io_loop_stop(current_ioloop);
		return;
	case EX_NOUSER:
		i_error("%s: No such user: %s", server->name, username);
		if (cmd_ctx->exit_code == 0)
			cmd_ctx->exit_code = EX_NOUSER;
		break;
	default:
		if (cmd_ctx->exit_code == 0 || exit_code == EX_TEMPFAIL)
			cmd_ctx->exit_code = exit_code;
		break;
	}

	if (array_count(&server->queue) > 0) {
		struct server_connection *conn;
		char *const *usernamep = array_front(&server->queue);
		char *username = *usernamep;

		conn = doveadm_server_find_unused_conn(server);
		if (conn != NULL) {
			array_pop_front(&server->queue);
			doveadm_mail_server_handle(conn, username);
			i_free(username);
		}
	}

	io_loop_stop(current_ioloop);
}

static void doveadm_mail_server_handle(struct server_connection *conn,
				       const char *username)
{
	struct doveadm_mail_server_cmd *servercmd;
	string_t *cmd;
	unsigned int i;

	/* <flags> <username> <command> [<args>] */
	cmd = t_str_new(256);
	if (doveadm_debug)
		str_append_c(cmd, 'D');
	else if (doveadm_verbose)
		str_append_c(cmd, 'v');
	str_append_c(cmd, '\t');

	str_append_tabescaped(cmd, username);
	str_append_c(cmd, '\t');
	str_append_tabescaped(cmd, cmd_ctx->cmd->name);
	for (i = 0; cmd_ctx->full_args[i] != NULL; i++) {
		str_append_c(cmd, '\t');
		str_append_tabescaped(cmd, cmd_ctx->full_args[i]);
	}
	str_append_c(cmd, '\n');

	servercmd = i_new(struct doveadm_mail_server_cmd, 1);
	servercmd->conn = conn;
	servercmd->username = i_strdup(username);
	server_connection_cmd(conn, str_c(cmd), cmd_ctx->cmd_input,
			      doveadm_cmd_callback, servercmd);
}

static void doveadm_server_flush_one(struct doveadm_server *server)
{
	unsigned int count = array_count(&server->queue);

	do {
		io_loop_run(current_ioloop);
	} while (array_count(&server->queue) == count &&
		 doveadm_server_have_used_connections(server) &&
		 !DOVEADM_MAIL_SERVER_FAILED());
}

static int
doveadm_mail_server_user_get_host(struct doveadm_mail_cmd_context *ctx,
				  const struct mail_storage_service_input *input,
				  const char **user_r, const char **host_r,
				  struct ip_addr *hostip_r, in_port_t *port_r,
				  enum doveadm_proxy_ssl_flags *ssl_flags_r,
				  const char **error_r)
{
	struct auth_master_connection *auth_conn;
	struct auth_user_info info;
	pool_t pool;
	const char *auth_socket_path, *proxy_host, *proxy_hostip, *const *fields;
	unsigned int i;
	in_port_t proxy_port;
	bool proxying;
	int ret;

	*user_r = input->username;
	*host_r = ctx->set->doveadm_socket_path;

	if (ctx->set->doveadm_port == 0)
		return 0;

	/* make sure we have an auth connection */
	mail_storage_service_init_settings(ctx->storage_service, input);

	i_zero(&info);
	info.service = master_service_get_name(master_service);
	info.local_ip = input->local_ip;
	info.remote_ip = input->remote_ip;
	info.local_port = input->local_port;
	info.remote_port = input->remote_port;

	pool = pool_alloconly_create("auth lookup", 1024);
	auth_conn = mail_storage_service_get_auth_conn(ctx->storage_service);
	auth_socket_path = auth_master_get_socket_path(auth_conn);
	ret = auth_master_pass_lookup(auth_conn, input->username, &info,
				      pool, &fields);
	if (ret < 0) {
		*error_r = fields[0] != NULL ?
			t_strdup(fields[0]) : "passdb lookup failed";
		*error_r = t_strdup_printf("%s: %s (to see if user is proxied, "
					   "because doveadm_port is set)",
					   auth_socket_path, *error_r);
	} else if (ret == 0) {
		/* user not found from passdb. it could be in userdb though,
		   so just continue with the default host */
	} else {
		proxy_host = NULL; proxy_hostip = NULL; proxying = FALSE;
		proxy_port = ctx->set->doveadm_port;
		for (i = 0; fields[i] != NULL; i++) {
			if (str_begins(fields[i], "proxy") &&
			    (fields[i][5] == '\0' || fields[i][5] == '='))
				proxying = TRUE;
			else if (str_begins(fields[i], "host="))
				proxy_host = fields[i]+5;
			else if (str_begins(fields[i], "hostip="))
				proxy_hostip = fields[i]+7;
			else if (str_begins(fields[i], "user="))
				*user_r = t_strdup(fields[i]+5);
			else if (str_begins(fields[i], "destuser="))
				*user_r = t_strdup(fields[i]+9);
			else if (str_begins(fields[i], "port=")) {
				if (net_str2port(fields[i]+5, &proxy_port) < 0)
					proxy_port = 0;
	                } else if (str_begins(fields[i], "ssl=")) {
	                        *ssl_flags_r |= PROXY_SSL_FLAG_YES;
	                        if (strcmp(fields[i]+4, "any-cert") == 0)
	                               *ssl_flags_r |= PROXY_SSL_FLAG_ANY_CERT;
	                } else if (str_begins(fields[i], "starttls=")) {
	                        *ssl_flags_r |= PROXY_SSL_FLAG_YES |
	                                PROXY_SSL_FLAG_STARTTLS;
	                        if (strcmp(fields[i]+9, "any-cert") == 0)
	                                *ssl_flags_r |= PROXY_SSL_FLAG_ANY_CERT;
			}
		}
		if (proxy_hostip != NULL &&
		    net_addr2ip(proxy_hostip, hostip_r) < 0) {
			*error_r = t_strdup_printf("%s Invalid hostip value '%s'",
						   auth_socket_path, proxy_hostip);
			ret = -1;
		}
		if (!proxying)
			ret = 0;
		else if (proxy_host == NULL) {
			*error_r = t_strdup_printf("%s: Proxy is missing destination host",
						   auth_socket_path);
			if (strstr(auth_socket_path, "/auth-userdb") != NULL) {
				*error_r = t_strdup_printf(
					"%s (maybe set auth_socket_path=director-userdb)",
					*error_r);
			}
			ret = -1;
		} else {
			*port_r = proxy_port;
			*host_r = t_strdup_printf("%s:%u", proxy_host, proxy_port);
		}
	}
	pool_unref(&pool);
	return ret;
}

int doveadm_mail_server_user(struct doveadm_mail_cmd_context *ctx,
			     const struct mail_storage_service_input *input,
			     const char **error_r)
{
	struct doveadm_server *server;
	struct server_connection *conn;
	const char *user, *host;
	struct ip_addr hostip;
	enum doveadm_proxy_ssl_flags ssl_flags = 0;
	char *username_dup;
	int ret;
	in_port_t port;

	i_assert(cmd_ctx == ctx || cmd_ctx == NULL);
	cmd_ctx = ctx;

	i_zero(&hostip);
	ret = doveadm_mail_server_user_get_host(ctx, input, &user, &host, &hostip,
						&port, &ssl_flags, error_r);
	if (ret < 0)
		return ret;
	if (ret == 0 &&
	    (ctx->set->doveadm_worker_count == 0 || doveadm_server)) {
		/* run it ourself */
		return 0;
	}

	/* server sends the sticky headers for each row as well,
	   so undo any sticks we might have added already */
	doveadm_print_unstick_headers();

	server = doveadm_server_get(ctx, host);
	server->ip = hostip;
	server->ssl_flags = ssl_flags;
	server->port = port;
	conn = doveadm_server_find_unused_conn(server);
	if (conn != NULL)
		doveadm_mail_server_handle(conn, user);
	else if (array_count(&server->connections) <
		 	I_MAX(ctx->set->doveadm_worker_count, 1)) {
		if (server_connection_create(server, &conn, error_r) < 0) {
			internal_failure = TRUE;
			return -1;
		} else {
			doveadm_mail_server_handle(conn, user);
		}
	} else {
		if (array_count(&server->queue) >= DOVEADM_SERVER_QUEUE_MAX)
			doveadm_server_flush_one(server);

		username_dup = i_strdup(user);
		array_push_back(&server->queue, &username_dup);
	}
	*error_r = "doveadm server failure";
	return DOVEADM_MAIL_SERVER_FAILED() ? -1 : 1;
}

static struct doveadm_server *doveadm_server_find_used(void)
{
	struct hash_iterate_context *iter;
	struct doveadm_server *ret = NULL;
	char *key;
	struct doveadm_server *server;

	iter = hash_table_iterate_init(servers);
	while (hash_table_iterate(iter, servers, &key, &server)) {
		if (doveadm_server_have_used_connections(server)) {
			ret = server;
			break;
		}
	}
	hash_table_iterate_deinit(&iter);
	return ret;
}

static void doveadm_servers_destroy_all_connections(void)
{
	struct hash_iterate_context *iter;
	char *key;
	struct doveadm_server *server;

	iter = hash_table_iterate_init(servers);
	while (hash_table_iterate(iter, servers, &key, &server)) {
		while (array_count(&server->connections) > 0) {
			struct server_connection *const *connp, *conn;

			connp = array_front(&server->connections);
			conn = *connp;
			server_connection_destroy(&conn);
		}
	}
	hash_table_iterate_deinit(&iter);
}

void doveadm_mail_server_flush(void)
{
	struct doveadm_server *server;

	if (!hash_table_is_created(servers)) {
		cmd_ctx = NULL;
		return;
	}

	while ((server = doveadm_server_find_used()) != NULL &&
	       !DOVEADM_MAIL_SERVER_FAILED())
		doveadm_server_flush_one(server);

	doveadm_servers_destroy_all_connections();
	if (master_service_is_killed(master_service))
		i_error("Aborted");
	if (DOVEADM_MAIL_SERVER_FAILED())
		doveadm_mail_failed_error(cmd_ctx, MAIL_ERROR_TEMP);

	hash_table_destroy(&servers);
	pool_unref(&server_pool);
	cmd_ctx = NULL;
}
