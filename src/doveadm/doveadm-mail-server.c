/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "ioloop.h"
#include "istream.h"
#include "master-service.h"
#include "iostream-ssl.h"
#include "auth-proxy.h"
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

struct doveadm_proxy_redirect {
	struct ip_addr ip;
	in_port_t port;
};

struct doveadm_mail_server_cmd {
	struct server_connection *conn;
	char *username;

	int proxy_ttl;
	ARRAY(struct doveadm_proxy_redirect) redirect_path;

	char *cmdline;
	struct istream *input;
};

static HASH_TABLE(char *, struct doveadm_server *) servers;
static pool_t server_pool;
static struct doveadm_mail_cmd_context *cmd_ctx;
static bool internal_failure = FALSE;

static void doveadm_cmd_callback(const struct doveadm_server_reply *reply,
				 void *context);
static void doveadm_mail_server_handle(struct server_connection *conn,
				       const char *username);

static struct doveadm_server *doveadm_server_get(const char *name)
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
			     doveadm_settings->doveadm_worker_count);
		p_array_init(&server->queue, server_pool,
			     DOVEADM_SERVER_QUEUE_MAX);
		hash_table_insert(servers, dup_name, server);
	}
	return server;
}

static struct server_connection *
doveadm_server_find_unused_conn(struct doveadm_server *server)
{
	struct server_connection *conn;

	array_foreach_elem(&server->connections, conn) {
		if (server_connection_is_idle(conn))
			return conn;
	}
	return NULL;
}

static bool doveadm_server_have_used_connections(struct doveadm_server *server)
{
	struct server_connection *conn;

	array_foreach_elem(&server->connections, conn) {
		if (!server_connection_is_idle(conn))
			return TRUE;
	}
	return FALSE;
}

static void doveadm_mail_server_cmd_free(struct doveadm_mail_server_cmd **_cmd)
{
	struct doveadm_mail_server_cmd *cmd = *_cmd;

	*_cmd = NULL;
	if (cmd == NULL)
		return;

	i_stream_unref(&cmd->input);
	array_free(&cmd->redirect_path);
	i_free(cmd->cmdline);
	i_free(cmd->username);
	i_free(cmd);
}

static int
doveadm_cmd_pass_lookup(struct doveadm_mail_cmd_context *ctx, pool_t pool,
			const char *const **fields_r,
			const char **auth_socket_path_r)
{
	struct auth_master_connection *auth_conn;
	struct auth_user_info info;

	/* make sure we have an auth connection */
	struct mail_storage_service_input input = {
		.service = master_service_get_name(master_service),
	};
	mail_storage_service_init_settings(ctx->storage_service, &input);

	i_zero(&info);
	info.service = master_service_get_name(master_service);
	info.local_ip = ctx->cctx->local_ip;
	info.remote_ip = ctx->cctx->remote_ip;
	info.local_port = ctx->cctx->local_port;
	info.remote_port = ctx->cctx->remote_port;

	auth_conn = mail_storage_service_get_auth_conn(ctx->storage_service);
	*auth_socket_path_r = auth_master_get_socket_path(auth_conn);
	return auth_master_pass_lookup(auth_conn, ctx->cctx->username, &info,
				       pool, fields_r);
}

static int
doveadm_cmd_pass_reply_parse(struct doveadm_mail_cmd_context *ctx,
			     const char *auth_socket_path,
			     const char *const *fields,
			     struct auth_proxy_settings *proxy_set,
			     bool *nologin_r, const char **error_r)
{
	const char *orig_user = proxy_set->username;
	const char *error;
	int ret;

	proxy_set->username = NULL;
	proxy_set->host = NULL;

	*nologin_r = FALSE;
	for (unsigned int i = 0; fields[i] != NULL; i++) {
		const char *p, *key, *value;

		p = strchr(fields[i], '=');
		if (p == NULL) {
			key = fields[i];
			value = "";
		} else {
			key = t_strdup_until(fields[i], p);
			value = p + 1;
		}

		ret = auth_proxy_settings_parse(proxy_set,
			unsafe_data_stack_pool, key, value, &error);
		if (ret < 0) {
			*error_r = t_strdup_printf(
				"%s: Invalid %s value '%s': %s",
				auth_socket_path, key, value, error);
			return -1;
		}
		if (ret > 0)
			continue;

		if (strcmp(key, "nologin") == 0)
			*nologin_r = TRUE;
		else if (strcmp(key, "user") == 0) {
			if (proxy_set->username == NULL)
				proxy_set->username = t_strdup(value);
		}
	}
	if (proxy_set->username == NULL)
		proxy_set->username = orig_user;
	if (!proxy_set->proxy)
		return 0;

	if (proxy_set->host == NULL) {
		*error_r = t_strdup_printf(
			"%s: Proxy is missing destination host",
			auth_socket_path);
		if (strstr(auth_socket_path, "/auth-userdb") != NULL) {
			*error_r = t_strdup_printf(
				"%s (maybe set auth_socket_path=director-userdb)",
				*error_r);
		}
		return -1;
	}
	if (proxy_set->ssl_flags != 0)
		;
	else if (strcmp(ctx->set->doveadm_ssl, "ssl") == 0)
		proxy_set->ssl_flags |= AUTH_PROXY_SSL_FLAG_YES;
	else if (strcmp(ctx->set->doveadm_ssl, "starttls") == 0) {
		proxy_set->ssl_flags |= AUTH_PROXY_SSL_FLAG_YES |
			AUTH_PROXY_SSL_FLAG_STARTTLS;
	}
	return 0;
}

static bool
doveadm_proxy_cmd_have_connected(struct doveadm_mail_server_cmd *servercmd,
				 const struct ip_addr *ip, in_port_t port)
{
	const struct doveadm_proxy_redirect *redirect;
	struct ip_addr conn_ip;
	in_port_t conn_port;

	server_connection_get_dest(servercmd->conn, &conn_ip, &conn_port);
	i_assert(conn_ip.family != 0);

	if (net_ip_compare(&conn_ip, ip) && conn_port == port)
		return TRUE;
	if (!array_is_created(&servercmd->redirect_path))
		return FALSE;

	array_foreach(&servercmd->redirect_path, redirect) {
		if (net_ip_compare(&redirect->ip, ip) && redirect->port == port)
			return TRUE;
	}
	return FALSE;
}

static int doveadm_cmd_redirect(struct doveadm_mail_server_cmd *servercmd,
				const char *destination)
{
	struct doveadm_server *orig_server, *new_server;
	struct server_connection *conn;
	struct doveadm_proxy_redirect *redirect;
	struct ip_addr ip;
	in_port_t port;
	const char *destuser, *host, *error;

	orig_server = server_connection_get_server(servercmd->conn);
	if (!auth_proxy_parse_redirect(destination, &destuser,
				       &host, &ip, &port)) {
		i_error("%s: Invalid redirect destination: %s",
			orig_server->name, destination);
		return -1;
	}

	if (doveadm_proxy_cmd_have_connected(servercmd, &ip,
					     orig_server->port)) {
		i_error("%s: Proxying loops - already connected to %s:%u",
			orig_server->name, net_ip2addr(&ip), orig_server->port);
		return -1;
	}

	i_assert(servercmd->proxy_ttl > 0);
	servercmd->proxy_ttl--;

	/* Add current ip/port to redirect path */
	if (!array_is_created(&servercmd->redirect_path))
		i_array_init(&servercmd->redirect_path, 2);
	redirect = array_append_space(&servercmd->redirect_path);
	redirect->ip = ip;
	redirect->port = orig_server->port;

	new_server = doveadm_server_get(destination);
	new_server->ip = ip;
	new_server->ssl_flags = orig_server->ssl_flags;
	new_server->port = port != 0 ? port : orig_server->port;

	conn = doveadm_server_find_unused_conn(new_server);
	if (conn == NULL) {
		if (server_connection_create(new_server, &conn, &error) < 0) {
			i_error("%s: Failed to create redirect connection: %s",
				new_server->name, error);
			return -1;
		}
	}

	servercmd->conn = conn;
	if (servercmd->input != NULL)
		i_stream_seek(servercmd->input, 0);
	server_connection_cmd(conn, servercmd->proxy_ttl,
			      servercmd->cmdline, servercmd->input,
			      doveadm_cmd_callback, servercmd);
	return 0;
}

static void doveadm_cmd_callback(const struct doveadm_server_reply *reply,
				 void *context)
{
	struct doveadm_mail_server_cmd *servercmd = context;
	struct doveadm_server *server =
		server_connection_get_server(servercmd->conn);

	switch (reply->exit_code) {
	case 0:
		break;
	case SERVER_EXIT_CODE_DISCONNECTED:
		i_error("%s: Command %s failed for %s: %s",
			server->name, cmd_ctx->cmd->name, servercmd->username,
			reply->error);
		internal_failure = TRUE;
		io_loop_stop(current_ioloop);
		doveadm_mail_server_cmd_free(&servercmd);
		return;
	case EX_NOUSER:
		i_error("%s: No such user: %s", server->name,
			servercmd->username);
		if (cmd_ctx->exit_code == 0)
			cmd_ctx->exit_code = EX_NOUSER;
		break;
	case DOVEADM_EX_REFERRAL:
		if (doveadm_cmd_redirect(servercmd, reply->error) < 0) {
			internal_failure = TRUE;
			io_loop_stop(current_ioloop);
			doveadm_mail_server_cmd_free(&servercmd);
		}
		return;
	default:
		if (cmd_ctx->exit_code == 0 || reply->exit_code == EX_TEMPFAIL)
			cmd_ctx->exit_code = reply->exit_code;
		break;
	}
	doveadm_mail_server_cmd_free(&servercmd);

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
	servercmd->proxy_ttl = cmd_ctx->proxy_ttl;
	servercmd->cmdline = i_strdup(str_c(cmd));
	servercmd->input = cmd_ctx->cmd_input;
	if (servercmd->input != NULL)
		i_stream_ref(servercmd->input);
	server_connection_cmd(conn, cmd_ctx->proxy_ttl,
			      str_c(cmd), cmd_ctx->cmd_input,
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
				  struct auth_proxy_settings *proxy_set_r,
				  const char **referral_r,
				  const char **error_r)
{
	pool_t pool;
	const char *auth_socket_path, *const *fields;
	bool nologin;
	int ret;

	i_zero(proxy_set_r);
	proxy_set_r->username = ctx->cctx->username;
	/* Note that doveadm_socket_path can come from --socket-path
	   parameter. */
	if (net_str2hostport(ctx->set->doveadm_socket_path,
			     ctx->set->doveadm_port,
			     &proxy_set_r->host, &proxy_set_r->port) < 0) {
		*error_r = t_strdup_printf("Invalid socket path '%s'",
					   ctx->set->doveadm_socket_path);
		return -1;
	}
	*referral_r = NULL;

	if (ctx->set->doveadm_port == 0) {
		/* no proxying to another server, but possibly run the command
		   via doveadm-server UNIX socket. */
		return 0;
	}

	pool = pool_alloconly_create("auth lookup", 1024);
	ret = doveadm_cmd_pass_lookup(ctx, pool, &fields, &auth_socket_path);
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
		const char *orig_host = proxy_set_r->host;

		if (doveadm_cmd_pass_reply_parse(ctx, auth_socket_path, fields,
						 proxy_set_r, &nologin,
						 error_r) < 0)
			ret = -1;
		else if (proxy_set_r->proxy)
			ret = 1;
		else if (!nologin) {
			proxy_set_r->host = orig_host;
			ret = 0;
		} else if (proxy_set_r->host == NULL) {
			/* Allow accessing nologin users via doveadm
			   protocol, since it's only admins that access
			   them. */
			proxy_set_r->host = orig_host;
			ret = 0;
		} else {
			/* Referral */
			*referral_r = t_strdup_printf("%s@%s",
				proxy_set_r->username, proxy_set_r->host);
			ret = 1;
		}
	}
	pool_unref(&pool);
	return ret;
}

int doveadm_mail_server_user(struct doveadm_mail_cmd_context *ctx,
			     const char **error_r)
{
	struct doveadm_server *server;
	struct server_connection *conn;
	struct auth_proxy_settings proxy_set;
	const char *server_name, *referral;
	char *username_dup;
	int ret;

	i_assert(cmd_ctx == ctx || cmd_ctx == NULL);
	cmd_ctx = ctx;

	ret = doveadm_mail_server_user_get_host(ctx, &proxy_set,
						&referral, error_r);
	if (ret < 0)
		return ret;
	if (ret == 0 &&
	    (ctx->set->doveadm_worker_count == 0 || doveadm_server)) {
		/* run it ourself */
		return 0;
	}
	if (ctx->proxy_ttl <= 1) {
		*error_r = "TTL reached zero - proxies appear to be looping?";
		return -1;
	}
	if (referral != NULL) {
		ctx->cctx->referral = referral;
		return 1;
	}
	i_assert(proxy_set.host != NULL);
	i_assert(proxy_set.port != 0);
	i_assert(proxy_set.username != NULL);

	/* server sends the sticky headers for each row as well,
	   so undo any sticks we might have added already */
	doveadm_print_unstick_headers();

	server_name = t_strdup_printf("%s:%u", proxy_set.host, proxy_set.port);
	server = doveadm_server_get(server_name);
	server->ip = proxy_set.host_ip;
	server->ssl_flags = proxy_set.ssl_flags;
	server->port = proxy_set.port;
	conn = doveadm_server_find_unused_conn(server);
	if (conn != NULL)
		doveadm_mail_server_handle(conn, proxy_set.username);
	else if (array_count(&server->connections) <
		 	I_MAX(ctx->set->doveadm_worker_count, 1)) {
		if (server_connection_create(server, &conn, error_r) < 0) {
			internal_failure = TRUE;
			return -1;
		} else {
			doveadm_mail_server_handle(conn, proxy_set.username);
		}
	} else {
		if (array_count(&server->queue) >= DOVEADM_SERVER_QUEUE_MAX)
			doveadm_server_flush_one(server);

		username_dup = i_strdup(proxy_set.username);
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
		ssl_iostream_context_unref(&server->ssl_ctx);
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
