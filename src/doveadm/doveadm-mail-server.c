/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

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

static struct hash_table *servers;
static pool_t server_pool;
static struct doveadm_mail_cmd_context *cmd_ctx;
static bool internal_failure = FALSE;

static void doveadm_mail_server_handle(struct server_connection *conn,
				       const char *username);

static struct doveadm_server *
doveadm_server_get(struct doveadm_mail_cmd_context *ctx, const char *name)
{
	struct doveadm_server *server;
	char *dup_name;

	if (servers == NULL) {
		server_pool = pool_alloconly_create("doveadm servers", 1024*16);
		servers = hash_table_create(default_pool, server_pool, 0,
					    str_hash,
					    (hash_cmp_callback_t *)strcmp);
	}
	server = hash_table_lookup(servers, name);
	if (server == NULL) {
		server = p_new(server_pool, struct doveadm_server, 1);
		server->name = dup_name = p_strdup(server_pool, name);
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

static void doveadm_cmd_callback(enum server_cmd_reply reply, void *context)
{
	struct server_connection *conn = context;
	struct doveadm_server *server;

	if (reply == SERVER_CMD_REPLY_INTERNAL_FAILURE) {
		internal_failure = TRUE;
		master_service_stop(master_service);
		return;
	}

	if (reply != SERVER_CMD_REPLY_OK)
		cmd_ctx->failed = TRUE;

	server = server_connection_get_server(conn);
	if (array_count(&server->queue) > 0) {
		char *const *usernamep = array_idx(&server->queue, 0);
		char *username = *usernamep;

		conn = doveadm_server_find_unused_conn(server);
		if (conn != NULL) {
			array_delete(&server->queue, 0, 1);
			doveadm_mail_server_handle(conn, username);
			i_free(username);
		}
	}

	master_service_stop(master_service);
}

static void doveadm_mail_server_handle(struct server_connection *conn,
				       const char *username)
{
	string_t *cmd;
	unsigned int i;

	/* <flags> <username> <command> [<args>] */
	cmd = t_str_new(256);
	if (doveadm_debug)
		str_append_c(cmd, 'D');
	else if (doveadm_verbose)
		str_append_c(cmd, 'v');
	str_append_c(cmd, '\t');

	str_tabescape_write(cmd, username);
	str_append_c(cmd, '\t');
	str_tabescape_write(cmd, cmd_ctx->cmd->name);
	for (i = 0; cmd_ctx->args[i] != NULL; i++) {
		str_append_c(cmd, '\t');
		str_tabescape_write(cmd, cmd_ctx->args[i]);
	}
	str_append_c(cmd, '\n');
	server_connection_cmd(conn, str_c(cmd), doveadm_cmd_callback, conn);
}

static void doveadm_server_flush_one(struct doveadm_server *server)
{
	unsigned int count = array_count(&server->queue);

	do {
		master_service_run(master_service, NULL);
	} while (array_count(&server->queue) == count &&
		 doveadm_server_have_used_connections(server) &&
		 !DOVEADM_MAIL_SERVER_FAILED());
}

static int
doveadm_mail_server_user_get_host(struct doveadm_mail_cmd_context *ctx,
				  const struct mail_storage_service_input *input,
				  const char **host_r, const char **error_r)
{
	struct auth_master_connection *auth_conn;
	struct auth_user_info info;
	pool_t pool;
	const char *proxy_host, *const *fields;
	unsigned int i;
	bool proxying;
	int ret;

	*host_r = ctx->set->doveadm_socket_path;

	if (ctx->set->doveadm_proxy_port == 0)
		return 0;

	/* make sure we have an auth connection */
	mail_storage_service_init_settings(ctx->storage_service, input);

	memset(&info, 0, sizeof(info));
	info.service = master_service_get_name(master_service);

	pool = pool_alloconly_create("auth lookup", 1024);
	auth_conn = mail_storage_service_get_auth_conn(ctx->storage_service);
	ret = auth_master_pass_lookup(auth_conn, input->username, &info,
				      pool, &fields);
	if (ret < 0) {
		*error_r = fields[0] != NULL ?
			t_strdup(fields[0]) : "passdb lookup failed";
	} else if (ret == 0) {
		/* user not found from passdb. it could be in userdb though,
		   so just continue with the default host */
	} else {
		proxy_host = NULL; proxying = FALSE;
		for (i = 0; fields[i] != NULL; i++) {
			if (strncmp(fields[i], "proxy", 5) == 0 &&
			    (fields[i][5] == '\0' || fields[i][5] == '='))
				proxying = TRUE;
			else if (strncmp(fields[i], "host=", 5) == 0)
				proxy_host = fields[i]+5;
		}
		if (!proxying)
			ret = 0;
		else if (proxy_host == NULL) {
			*error_r = "Proxy is missing destination host";
			ret = -1;
		} else {
			*host_r = t_strdup_printf("%s:%u", proxy_host,
						  ctx->set->doveadm_proxy_port);
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
	const char *host;
	char *username_dup;
	int ret;

	i_assert(cmd_ctx == ctx || cmd_ctx == NULL);
	cmd_ctx = ctx;

	ret = doveadm_mail_server_user_get_host(ctx, input, &host, error_r);
	if (ret < 0)
		return -1;
	if (ret == 0 &&
	    (ctx->set->doveadm_worker_count == 0 || doveadm_server)) {
		/* run it ourself */
		return 0;
	}

	/* server sends the sticky headers for each row as well,
	   so undo any sticks we might have added already */
	doveadm_print_unstick_headers();

	server = doveadm_server_get(ctx, host);
	conn = doveadm_server_find_unused_conn(server);
	if (conn != NULL)
		doveadm_mail_server_handle(conn, input->username);
	else if (array_count(&server->connections) <
		 	I_MAX(ctx->set->doveadm_worker_count, 1)) {
		conn = server_connection_create(server);
		doveadm_mail_server_handle(conn, input->username);
	} else {
		if (array_count(&server->queue) >= DOVEADM_SERVER_QUEUE_MAX)
			doveadm_server_flush_one(server);

		username_dup = i_strdup(input->username);
		array_append(&server->queue, &username_dup, 1);
	}
	*error_r = "doveadm server failure";
	return DOVEADM_MAIL_SERVER_FAILED() ? -1 : 1;
}

static struct doveadm_server *doveadm_server_find_used(void)
{
	struct hash_iterate_context *iter;
	struct doveadm_server *ret = NULL;
	void *key, *value;

	iter = hash_table_iterate_init(servers);
	while (hash_table_iterate(iter, &key, &value)) {
		struct doveadm_server *server = value;

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
	void *key, *value;

	iter = hash_table_iterate_init(servers);
	while (hash_table_iterate(iter, &key, &value)) {
		struct doveadm_server *server = value;

		while (array_count(&server->connections) > 0) {
			struct server_connection *const *connp, *conn;

			connp = array_idx(&server->connections, 0);
			conn = *connp;
			server_connection_destroy(&conn);
		}
	}
	hash_table_iterate_deinit(&iter);
}

void doveadm_mail_server_flush(void)
{
	struct doveadm_server *server;

	if (servers == NULL) {
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
		cmd_ctx->failed = TRUE;

	hash_table_destroy(&servers);
	pool_unref(&server_pool);
	cmd_ctx = NULL;
}
