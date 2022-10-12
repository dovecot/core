/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "connection.h"
#include "ioloop.h"
#include "istream.h"
#include "master-service.h"
#include "iostream-ssl.h"
#include "auth-proxy.h"
#include "auth-master.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "doveadm-client.h"
#include "doveadm-settings.h"
#include "doveadm-print.h"
#include "doveadm-mail.h"

#define DOVEADM_SERVER_QUEUE_MAX 16

#define DOVEADM_MAIL_SERVER_FAILED() \
	(internal_failure || master_service_is_killed(master_service))

struct doveadm_server {
	/* hostname:port or UNIX socket path. Used mainly for logging. */
	const char *name;
};

struct doveadm_proxy_redirect {
	struct ip_addr ip;
	in_port_t port;
};

struct doveadm_mail_server_cmd {
	struct doveadm_server *server;
	struct doveadm_client *conn;
	struct doveadm_mail_cmd_context *cmd_ctx;
	char *username;

	ARRAY(struct doveadm_proxy_redirect) redirect_path;

	char *cmdline;
	struct istream *input;
	bool streaming;
	bool print_username;
};

struct doveadm_server_request {
	pool_t pool;
	struct doveadm_server *server;
	struct doveadm_client_settings set;
	const char *username;
	bool print_username;
};

static HASH_TABLE(char *, struct doveadm_server *) servers;
static pool_t server_pool;
static bool internal_failure = FALSE;
static ARRAY(struct doveadm_server_request) doveadm_server_request_queue;

static void doveadm_cmd_callback(const struct doveadm_server_reply *reply,
				 void *context);

static void doveadm_server_request_free(struct doveadm_server_request *request)
{
	ssl_iostream_context_unref(&request->set.ssl_ctx);
	pool_unref(&request->pool);
}

struct doveadm_server *doveadm_server_get(const char *name)
{
	struct doveadm_server *server;
	char *dup_name;

	if (!hash_table_is_created(servers)) {
		server_pool = pool_alloconly_create("doveadm servers", 1024*16);
		hash_table_create(&servers, server_pool, 0, str_hash, strcmp);

		i_assert(!array_is_created(&doveadm_server_request_queue));
		i_array_init(&doveadm_server_request_queue,
			     DOVEADM_SERVER_QUEUE_MAX);
	}
	server = hash_table_lookup(servers, name);
	if (server == NULL) {
		server = p_new(server_pool, struct doveadm_server, 1);
		server->name = dup_name = p_strdup(server_pool, name);

		hash_table_insert(servers, dup_name, server);
	}
	return server;
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

int doveadm_cmd_pass_lookup(struct doveadm_mail_cmd_context *ctx,
			    const char *const *extra_fields, pool_t pool,
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

	if (extra_fields != NULL) {
		unsigned int count = str_array_length(extra_fields);
		t_array_init(&info.extra_fields, count);
		array_append(&info.extra_fields, extra_fields, count);
	}
	info.forward_fields = doveadm_mail_get_forward_fields(ctx);

	auth_conn = mail_storage_service_get_auth_conn(ctx->storage_service);
	*auth_socket_path_r = auth_master_get_socket_path(auth_conn);
	return auth_master_pass_lookup(auth_conn, ctx->cctx->username, &info,
				       pool, fields_r);
}

int doveadm_cmd_pass_reply_parse(struct doveadm_mail_cmd_context *ctx,
				 const char *auth_socket_path,
				 const char *const *fields,
				 struct auth_proxy_settings *proxy_set,
				 bool *nologin_r, const char **error_r)
{
	const char *orig_user = proxy_set->username;
	const char *error, *mend;
	int ret;

	proxy_set->username = NULL;
	proxy_set->host = NULL;

	if (array_is_created(&ctx->auth_proxy_forward_fields))
		array_clear(&ctx->auth_proxy_forward_fields);

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
		} else if (str_begins(key, "forward_", &mend)) {
			if (!array_is_created(&ctx->auth_proxy_forward_fields)) {
				p_array_init(&ctx->auth_proxy_forward_fields,
					     ctx->pool, 8);
			}
			value = p_strdup_printf(ctx->pool, "%s=%s",
						mend, value);
			array_push_back(&ctx->auth_proxy_forward_fields, &value);
		}
	}
	if (proxy_set->username == NULL)
		proxy_set->username = orig_user;

	/* These ssl_flags can also be used by doveadm CLI client when
	   connecting to doveadm-server (i.e. without proxy=y) */
	if (proxy_set->ssl_flags != 0)
		;
	else if (strcmp(ctx->set->doveadm_ssl, "ssl") == 0)
		proxy_set->ssl_flags |= AUTH_PROXY_SSL_FLAG_YES;
	else if (strcmp(ctx->set->doveadm_ssl, "starttls") == 0) {
		proxy_set->ssl_flags |= AUTH_PROXY_SSL_FLAG_YES |
			AUTH_PROXY_SSL_FLAG_STARTTLS;
	}

	if (!proxy_set->proxy)
		return 0;

	if (proxy_set->host == NULL) {
		*error_r = t_strdup_printf(
			"%s: Proxy is missing destination host",
			auth_socket_path);
		if (strstr(auth_socket_path, "/auth-userdb") != NULL) {
			*error_r = t_strdup_printf(
				"%s (maybe set auth_socket_path=cluster-userdb)",
				*error_r);
		}
		return -1;
	}
	if (proxy_set->host_ip.family == 0 &&
	    net_addr2ip(proxy_set->host, &proxy_set->host_ip) < 0) {
		*error_r = t_strdup_printf(
			"%s: Proxy host is not a valid IP address: %s",
			auth_socket_path, proxy_set->host);
		return -1;
	}
	return 0;
}

static void
doveadm_proxy_cmd_get_redirect_path(struct doveadm_mail_server_cmd *servercmd,
				    string_t *str)
{
	const struct doveadm_proxy_redirect *redirect;
	struct ip_addr ip;
	in_port_t port;

	doveadm_client_get_dest(servercmd->conn, &ip, &port);
	i_assert(ip.family != 0);

	str_printfa(str, "%s:%u", net_ip2addr(&ip), port);
	if (!array_is_created(&servercmd->redirect_path))
		return;
	array_foreach(&servercmd->redirect_path, redirect) {
		str_printfa(str, ",%s:%u",
			    net_ip2addr(&redirect->ip), redirect->port);
	}
}

static bool
doveadm_proxy_cmd_have_connected(struct doveadm_mail_server_cmd *servercmd,
				 const struct ip_addr *ip, in_port_t port)
{
	const struct doveadm_proxy_redirect *redirect;
	struct ip_addr conn_ip;
	in_port_t conn_port;

	doveadm_client_get_dest(servercmd->conn, &conn_ip, &conn_port);
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

static const char *const *
doveadm_mail_get_outgoing_forward_fields(struct doveadm_mail_cmd_context *ctx)
{
	if (!array_is_created(&ctx->auth_proxy_forward_fields) ||
	    array_is_empty(&ctx->auth_proxy_forward_fields))
		return NULL;

	array_append_zero(&ctx->auth_proxy_forward_fields);
	array_pop_back(&ctx->auth_proxy_forward_fields);
	return array_front(&ctx->auth_proxy_forward_fields);
}

static int
doveadm_cmd_redirect_finish(struct doveadm_mail_server_cmd *servercmd,
			    const struct ip_addr *ip, in_port_t port,
			    enum auth_proxy_ssl_flags ssl_flags,
			    const char **error_r)
{
	struct doveadm_mail_cmd_context *cmd_ctx = servercmd->cmd_ctx;
	struct doveadm_server *new_server;
	struct doveadm_client *conn;
	struct doveadm_proxy_redirect *redirect;
	const char *server_name, *error;

	i_assert(ip->family != 0);

	if (port == 0)
		port = doveadm_client_get_settings(servercmd->conn)->port;

	if (doveadm_proxy_cmd_have_connected(servercmd, ip, port)) {
		*error_r = t_strdup_printf(
			"Proxying loops - already connected to %s:%u",
			net_ip2addr(ip), port);
		return -1;
	}

	i_assert(cmd_ctx->proxy_ttl > 0);
	cmd_ctx->proxy_ttl--;

	/* Add current ip/port to redirect path */
	if (!array_is_created(&servercmd->redirect_path))
		i_array_init(&servercmd->redirect_path, 2);
	redirect = array_append_space(&servercmd->redirect_path);
	redirect->ip = *ip;
	redirect->port = port;

	server_name = t_strdup_printf("%s:%u", net_ip2addr(ip), port);
	new_server = doveadm_server_get(server_name);

	struct doveadm_client_settings conn_set = {
		.hostname = net_ip2addr(ip),
		.ip = *ip,
		.port = port,
		.username = doveadm_settings->doveadm_username,
		.password = doveadm_settings->doveadm_password,
		.ssl_flags = ssl_flags,
		.log_passthrough = TRUE,
	};

	if (doveadm_client_create(&conn_set, &conn, &error) < 0) {
		*error_r = t_strdup_printf(
			"Failed to create redirect connection to %s: %s",
			new_server->name, error);
		return -1;
	}

	servercmd->conn = conn;
	servercmd->server = new_server;
	if (servercmd->input != NULL)
		i_stream_seek(servercmd->input, 0);

	struct doveadm_client_cmd_settings cmd_set = {
		.proxy_ttl = cmd_ctx->proxy_ttl,
	};
	cmd_set.forward_fields = doveadm_mail_get_outgoing_forward_fields(cmd_ctx);
	doveadm_client_cmd(conn, &cmd_set, servercmd->cmdline, servercmd->input,
			   doveadm_cmd_callback, servercmd);
	doveadm_client_unref(&conn);
	return 1;
}

static int
doveadm_cmd_redirect_relookup(struct doveadm_mail_server_cmd *servercmd,
			      const char *host, in_port_t port,
			      const char *destuser, const char **error_r)
{
	struct doveadm_mail_cmd_context *cmd_ctx = servercmd->cmd_ctx;
	struct auth_proxy_settings proxy_set;
	const char *const *fields, *auth_socket_path;
	pool_t auth_pool;
	bool nologin;
	int ret;

	i_zero(&proxy_set);

	string_t *hosts_attempted = t_str_new(64);
	str_append(hosts_attempted, "proxy_redirect_host_attempts=");
	doveadm_proxy_cmd_get_redirect_path(servercmd, hosts_attempted);
	const char *const extra_fields[] = {
		t_strdup_printf("proxy_redirect_host_next=%s:%u", host, port),
		str_c(hosts_attempted),
		destuser == NULL ? NULL :
			t_strdup_printf("destuser=%s", str_tabescape(destuser)),
		NULL
	};

	auth_pool = pool_alloconly_create("auth lookup", 1024);
	ret = doveadm_cmd_pass_lookup(cmd_ctx, extra_fields, auth_pool, &fields,
				      &auth_socket_path);
	if (ret <= 0) {
		if (ret == 0 || fields[0] == NULL)
			*error_r = "Redirect lookup unexpectedly failed";
		else {
			*error_r = t_strdup_printf(
				"Redirect lookup unexpectedly failed: %s",
				fields[0]);
		}
		ret = -1;
	} else if (doveadm_cmd_pass_reply_parse(cmd_ctx, auth_socket_path, fields,
						&proxy_set, &nologin, error_r) < 0)
		ret = -1;
	else if (proxy_set.proxy) {
		ret = doveadm_cmd_redirect_finish(servercmd, &proxy_set.host_ip,
						  proxy_set.port,
						  proxy_set.ssl_flags, error_r);
	} else if (!nologin || proxy_set.host == NULL) {
		*error_r = "Redirect authentication is missing proxy or nologin field";
		ret = -1;
	} else {
		/* Send referral back to the TCP client */
		cmd_ctx->cctx->referral = p_strdup_printf(cmd_ctx->cctx->pool,
			"%s@%s", proxy_set.username, proxy_set.host);
		ret = 0;
	}
	pool_unref(&auth_pool);
	return ret;
}

static int doveadm_cmd_redirect(struct doveadm_mail_server_cmd *servercmd,
				const char *destination)
{
	struct doveadm_server *orig_server = servercmd->server;
	struct doveadm_mail_cmd_context *cmd_ctx = servercmd->cmd_ctx;
	const struct doveadm_client_settings *client_set =
		doveadm_client_get_settings(servercmd->conn);
	struct ip_addr ip;
	in_port_t port;
	const char *destuser, *host, *error;
	int ret;

	if (!auth_proxy_parse_redirect(destination, &destuser, &host, &port)) {
		e_error(cmd_ctx->cctx->event,
			"%s: Invalid redirect destination: %s",
			orig_server->name, destination);
		return -1;
	}
	if (port == 0)
		port = client_set->port;

	if (cmd_ctx->cctx->proxy_redirect_reauth) {
		ret = doveadm_cmd_redirect_relookup(servercmd, host, port,
						    destuser, &error);
	} else {
		if (net_addr2ip(host, &ip) < 0) {
			e_error(cmd_ctx->cctx->event,
				"%s: Redirect destination host is not an IP: %s",
				orig_server->name, destination);
			return -1;
		}
		ret = doveadm_cmd_redirect_finish(servercmd, &ip, port,
						  client_set->ssl_flags,
						  &error);
	}
	if (ret < 0) {
		e_error(cmd_ctx->cctx->event,
			"%s: %s", orig_server->name, error);
		return -1;
	}
	return ret;
}

static void
doveadm_cmd_print_callback(const unsigned char *data,
			   size_t size, bool finished,
			   struct doveadm_mail_server_cmd *servercmd)
{
	string_t *str = t_str_new(size);
	if (servercmd->print_username) {
		doveadm_print_sticky("username", servercmd->username);
		servercmd->print_username = FALSE;
	}
	if (!finished) {
		servercmd->streaming = TRUE;
		str_append_tabunescaped(str, data, size);
		doveadm_print_stream(str->data, str->used);
	} else if (servercmd->streaming) {
		servercmd->streaming = FALSE;
		if (size > 0) {
			str_append_tabunescaped(str, data, size);
			doveadm_print_stream(str->data, str->used);
		}
		doveadm_print_stream("", 0);
	} else {
		str_append_tabunescaped(str, data, size);
		doveadm_print(str_c(str));
	}
}

static void doveadm_cmd_callback(const struct doveadm_server_reply *reply,
				 void *context)
{
	struct doveadm_mail_server_cmd *servercmd = context;
	struct doveadm_client *conn = servercmd->conn;
	struct doveadm_mail_cmd_context *cmd_ctx = servercmd->cmd_ctx;
	struct doveadm_server *server = servercmd->server;
	struct doveadm_server_request *request;
	int ret;

	switch (reply->exit_code) {
	case 0:
		break;
	case DOVEADM_CLIENT_EXIT_CODE_DISCONNECTED:
		e_error(cmd_ctx->cctx->event,
			"%s: Command %s failed for %s: %s",
			server->name, cmd_ctx->cmd->name, servercmd->username,
			reply->error);
		internal_failure = TRUE;
		io_loop_stop(current_ioloop);
		doveadm_mail_server_cmd_free(&servercmd);
		return;
	case EX_NOUSER:
		e_error(cmd_ctx->cctx->event,
			"%s: No such user: %s", server->name,
			servercmd->username);
		if (cmd_ctx->exit_code == 0)
			cmd_ctx->exit_code = EX_NOUSER;
		break;
	case DOVEADM_EX_REFERRAL:
		ret = doveadm_cmd_redirect(servercmd, reply->error);
		if (ret <= 0) {
			if (ret < 0)
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

	/* See if there are any more requests queued for this same server.
	   If we can continue it here, we can reuse the same doveadm
	   connection. */
	array_foreach_modifiable(&doveadm_server_request_queue, request) {
		if (request->server == server) {
			struct doveadm_server_request request_copy = *request;
			unsigned int idx =
				array_foreach_idx(&doveadm_server_request_queue,
						  request);
			array_delete(&doveadm_server_request_queue, idx, 1);

			doveadm_mail_server_handle(server, conn, cmd_ctx,
						   request_copy.username,
						   request_copy.print_username);
			doveadm_server_request_free(&request_copy);
			doveadm_client_unref(&conn);
			break;
		}
	}
	io_loop_stop(current_ioloop);
}

void doveadm_mail_server_handle(struct doveadm_server *server,
				struct doveadm_client *conn,
				struct doveadm_mail_cmd_context *cmd_ctx,
				const char *username, bool print_username)
{
	struct doveadm_mail_server_cmd *servercmd;
	string_t *cmd;

	/* <flags> <username> <command> [<args>] */
	cmd = t_str_new(256);
	if (doveadm_debug)
		str_append_c(cmd, DOVEADM_PROTOCOL_CMD_FLAG_DEBUG);
	else if (doveadm_verbose)
		str_append_c(cmd, DOVEADM_PROTOCOL_CMD_FLAG_VERBOSE);
	str_append_c(cmd, '\t');

	str_append_tabescaped(cmd, username);
	str_append_c(cmd, '\t');
	str_append_tabescaped(cmd, cmd_ctx->cmd->name);

	const char *const *args = doveadm_cmdv2_wrapper_generate_args(cmd_ctx);
	for (; *args != NULL; args++) {
	 	str_append_c(cmd, '\t');
	 	str_append_tabescaped(cmd, *args);
	}
	str_append_c(cmd, '\n');

	servercmd = i_new(struct doveadm_mail_server_cmd, 1);
	servercmd->conn = conn;
	servercmd->server = server;
	servercmd->cmd_ctx = cmd_ctx;
	servercmd->username = i_strdup(username);
	servercmd->cmdline = i_strdup(str_c(cmd));
	servercmd->input = cmd_ctx->cmd_input;
	servercmd->print_username = print_username;
	if (servercmd->input != NULL)
		i_stream_ref(servercmd->input);
	doveadm_client_set_print(conn, doveadm_cmd_print_callback,
				 servercmd);
	struct doveadm_client_cmd_settings cmd_set = {
		.proxy_ttl = cmd_ctx->proxy_ttl,
	};
	cmd_set.forward_fields = doveadm_mail_get_outgoing_forward_fields(cmd_ctx);
	doveadm_client_cmd(conn, &cmd_set, str_c(cmd), cmd_ctx->cmd_input,
			   doveadm_cmd_callback, servercmd);
}

static int
doveadm_mail_server_request_queue_handle_next(struct doveadm_mail_cmd_context *cmd_ctx,
					      const char **error_r)
{
	struct doveadm_server_request *request, request_copy;
	struct doveadm_client *conn;

	request = array_front_modifiable(&doveadm_server_request_queue);
	request_copy = *request;
	array_pop_front(&doveadm_server_request_queue);

	doveadm_get_ssl_settings(&request_copy.set.ssl_set,
				 pool_datastack_create());
	if (doveadm_client_create(&request_copy.set, &conn, error_r) < 0) {
		internal_failure = TRUE;
		return -1;
	}
	doveadm_mail_server_handle(request_copy.server, conn, cmd_ctx,
				   request_copy.username,
				   request_copy.print_username);
	doveadm_server_request_free(&request_copy);
	doveadm_client_unref(&conn);
	return 0;
}

static int
doveadm_mail_server_user_get_host(struct doveadm_mail_cmd_context *ctx,
				  struct auth_proxy_settings *proxy_set_r,
				  const char **socket_path_r,
				  const char **referral_r,
				  const char **error_r)
{
	pool_t pool;
	const char *auth_socket_path, *const *fields;
	bool nologin;
	int ret;

	*socket_path_r = NULL;
	i_zero(proxy_set_r);
	proxy_set_r->username = ctx->cctx->username;
	/* Note that doveadm_socket_path can come from --socket-path
	   parameter. */
	if (strchr(ctx->set->doveadm_socket_path, '/') != NULL) {
		*socket_path_r = ctx->set->doveadm_socket_path;
		/* initialize the default port already, since socket_path may
		   still change into host. */
		proxy_set_r->port = ctx->set->doveadm_port;
	} else if (net_str2hostport(ctx->set->doveadm_socket_path,
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
	ret = doveadm_cmd_pass_lookup(ctx, NULL, pool, &fields,
				      &auth_socket_path);
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
		else if (proxy_set_r->proxy) {
			*socket_path_r = NULL;
			ret = 1;
		} else if (!nologin) {
			proxy_set_r->host = orig_host;
			ret = 0;
		} else if (proxy_set_r->host == NULL) {
			/* Allow accessing nologin users via doveadm
			   protocol, since it's only admins that access
			   them. */
			proxy_set_r->host = orig_host;
			ret = 0;
		} else if (proxy_set_r->host[0] == '\0') {
			*error_r = "Referral host is empty";
			ret = -1;
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

static void
doveadm_mail_cmd_extra_fields_parse(struct doveadm_mail_cmd_context *ctx)
{
	const char *key, *value;

	if (ctx->cctx->extra_fields == NULL)
		return;
	for (unsigned int i = 0; ctx->cctx->extra_fields[i] != NULL; i++) {
		key = ctx->cctx->extra_fields[i];
		value = strchr(key, '=');
		if (value != NULL)
			key = t_strdup_until(key, value++);
		else
			value = "";
		if (strcmp(key, "proxy-ttl") == 0) {
			if (str_to_int(value, &ctx->proxy_ttl) < 0 ||
			    ctx->proxy_ttl <= 0)
				e_error(ctx->cctx->event,
					"Invalid proxy-ttl value: %s", value);
		} else if (strcmp(key, "forward") == 0) {
			if (!array_is_created(&ctx->proxy_forward_fields)) {
				p_array_init(&ctx->proxy_forward_fields,
					     ctx->pool, 8);
			}
			value = p_strdup(ctx->pool, value);
			array_push_back(&ctx->proxy_forward_fields, &value);
		}
	}
}

int doveadm_mail_server_user(struct doveadm_mail_cmd_context *ctx,
			     const char **error_r)
{
	struct doveadm_server *server;
	struct doveadm_client *conn;
	struct doveadm_server_request *request;
	struct auth_proxy_settings proxy_set;
	const char *server_name, *socket_path, *referral;
	bool print_username =
		doveadm_print_is_initialized() && !ctx->iterate_single_user;
	int ret;

	doveadm_mail_cmd_extra_fields_parse(ctx);
	ret = doveadm_mail_server_user_get_host(ctx, &proxy_set, &socket_path,
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
		ctx->cctx->referral = p_strdup(ctx->cctx->pool, referral);
		return 1;
	}
	i_assert(proxy_set.host != NULL || socket_path != NULL);
	i_assert(proxy_set.port != 0 || socket_path != NULL);
	i_assert(proxy_set.username != NULL);

	ctx->cctx->proxy_redirect_reauth = proxy_set.redirect_reauth;

	struct doveadm_client_settings conn_set = {
		.socket_path = socket_path,
		.hostname = proxy_set.host,
		.ip = proxy_set.host_ip,
		.port = proxy_set.port,
		.username = ctx->set->doveadm_username,
		.password = ctx->set->doveadm_password,
		.ssl_flags = proxy_set.ssl_flags,
		.log_passthrough = TRUE,
	};

	server_name = socket_path != NULL ? socket_path :
		t_strdup_printf("%s:%u", proxy_set.host, proxy_set.port);
	server = doveadm_server_get(server_name);

	unsigned int limit = I_MAX(ctx->set->doveadm_worker_count, 1);
	/* Make sure there's space for the new request. Either by creating a
	   new connection or in the queue. */
	while (!DOVEADM_MAIL_SERVER_FAILED()) {
		/* try to flush existing queue if there are available
		   connections. */
		if (doveadm_clients_count() < limit &&
		    array_count(&doveadm_server_request_queue) > 0) {
			if (doveadm_mail_server_request_queue_handle_next(ctx, error_r) < 0)
				return -1;
			continue;
		}
		/* make sure there is space in the queue */
		if (array_count(&doveadm_server_request_queue) <
		    DOVEADM_SERVER_QUEUE_MAX)
			break;

		/* wait for an existing request to finish */
		io_loop_run(current_ioloop);
	}

	if (doveadm_clients_count() <= limit) {
		doveadm_get_ssl_settings(&conn_set.ssl_set,
					 pool_datastack_create());
		if (doveadm_client_create(&conn_set, &conn, error_r) < 0) {
			internal_failure = TRUE;
			return -1;
		} else {
			doveadm_mail_server_handle(server, conn, ctx,
						   proxy_set.username,
						   print_username);
			doveadm_client_unref(&conn);
		}
	} else {
		request = array_append_space(&doveadm_server_request_queue);
		request->pool = pool_alloconly_create("doveadm server request", 256);
		request->server = server;
		request->username = p_strdup(request->pool, proxy_set.username);
		request->print_username = print_username;
		doveadm_client_settings_dup(&conn_set, &request->set, request->pool);
	}
	*error_r = "doveadm server failure";
	return DOVEADM_MAIL_SERVER_FAILED() ? -1 : 1;
}

void doveadm_mail_server_flush(struct doveadm_mail_cmd_context *ctx)
{
	struct doveadm_server_request *request;
	const char *error;

	if (!hash_table_is_created(servers))
		return;

	/* flush the queue */
	unsigned int limit = I_MAX(doveadm_settings->doveadm_worker_count, 1);
	while (!DOVEADM_MAIL_SERVER_FAILED()) {
		/* If there are too many connections, flush away one so queue
		   can be eaten. */
		if (doveadm_clients_count() >= limit) {
			io_loop_run(current_ioloop);
			continue;
		}

		if (array_count(&doveadm_server_request_queue) == 0)
			break;
		if (doveadm_mail_server_request_queue_handle_next(ctx, &error) < 0) {
			e_error(ctx->cctx->event, "%s", error);
			break;
		}
	}
	/* flush the final connections */
	while (!DOVEADM_MAIL_SERVER_FAILED() &&
	       doveadm_clients_count() > 0)
		io_loop_run(current_ioloop);

	doveadm_clients_destroy_all();
	if (master_service_is_killed(master_service))
		e_error(ctx->cctx->event, "Aborted");
	if (DOVEADM_MAIL_SERVER_FAILED())
		doveadm_mail_failed_error(ctx, MAIL_ERROR_TEMP);

	/* queue may not be empty if something failed */
	array_foreach_modifiable(&doveadm_server_request_queue, request)
		doveadm_server_request_free(request);
	array_free(&doveadm_server_request_queue);
	hash_table_destroy(&servers);
	pool_unref(&server_pool);
}
