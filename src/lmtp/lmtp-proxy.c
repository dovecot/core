/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "istream-sized.h"
#include "ostream.h"
#include "iostream-ssl.h"
#include "str.h"
#include "time-util.h"
#include "smtp-common.h"
#include "smtp-params.h"
#include "smtp-address.h"
#include "smtp-server.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"
#include "smtp-client-transaction.h"
#include "auth-master.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-ssl-settings.h"
#include "mail-storage-service.h"
#include "lda-settings.h"
#include "client.h"
#include "main.h"
#include "lmtp-common.h"
#include "lmtp-settings.h"
#include "lmtp-proxy.h"

#define LMTP_MAX_REPLY_SIZE 4096
#define LMTP_PROXY_DEFAULT_TIMEOUT_MSECS (1000*125)

enum lmtp_proxy_ssl_flags {
	/* Use SSL/TLS enabled */
	PROXY_SSL_FLAG_YES	= 0x01,
	/* Don't do SSL handshake immediately after connected */
	PROXY_SSL_FLAG_STARTTLS	= 0x02,
	/* Don't require that the received certificate is valid */
	PROXY_SSL_FLAG_ANY_CERT	= 0x04
};

struct lmtp_proxy_rcpt_settings {
	enum smtp_protocol protocol;
	const char *host;
	struct ip_addr hostip, source_ip;
	in_port_t port;
	enum lmtp_proxy_ssl_flags ssl_flags;
	unsigned int timeout_msecs;
	struct smtp_params_rcpt params;

	bool proxy_not_trusted:1;
};

struct lmtp_proxy_recipient {
	struct lmtp_recipient rcpt;
	struct lmtp_proxy_connection *conn;

	struct smtp_address *address;

	bool rcpt_to_failed:1;
	bool data_reply_received:1;
};

struct lmtp_proxy_connection {
	struct lmtp_proxy *proxy;
	struct lmtp_proxy_rcpt_settings set;
	char *host;

	struct smtp_client_transaction *lmtp_trans;
	struct istream *data_input;
	struct timeout *to;

	bool finished:1;
	bool failed:1;
};

struct lmtp_proxy {
	struct client *client;

	struct smtp_server_transaction *trans;

	struct smtp_client *lmtp_client;

	ARRAY(struct lmtp_proxy_connection *) connections;
	ARRAY(struct lmtp_proxy_recipient *) rcpt_to;
	unsigned int next_data_reply_idx;

	struct timeout *to_finish;
	struct istream *data_input;

	unsigned int max_timeout_msecs;

	struct smtp_server_cmd_ctx *pending_data_cmd;

	bool finished:1;
};

static void
lmtp_proxy_data_cb(const struct smtp_reply *reply,
		   struct lmtp_proxy_recipient *lprcpt);

/*
 * LMTP proxy
 */

static struct lmtp_proxy *
lmtp_proxy_init(struct client *client,
		struct smtp_server_transaction *trans)
{
	struct smtp_client_settings lmtp_set;
	struct lmtp_proxy *proxy;

	proxy = i_new(struct lmtp_proxy, 1);
	proxy->client = client;
	proxy->trans = trans;
	i_array_init(&proxy->rcpt_to, 32);
	i_array_init(&proxy->connections, 32);

	i_zero(&lmtp_set);
	lmtp_set.my_hostname = client->my_domain;
	lmtp_set.dns_client_socket_path = dns_client_socket_path;
	lmtp_set.max_reply_size = LMTP_MAX_REPLY_SIZE;
	lmtp_set.rawlog_dir = client->lmtp_set->lmtp_proxy_rawlog_dir;

	smtp_server_connection_get_proxy_data(client->conn,
					      &lmtp_set.proxy_data);
	lmtp_set.proxy_data.source_ip = client->remote_ip;
	lmtp_set.proxy_data.source_port = client->remote_port;
	if (lmtp_set.proxy_data.ttl_plus_1 == 0)
		lmtp_set.proxy_data.ttl_plus_1 = LMTP_PROXY_DEFAULT_TTL + 1;
	else
		lmtp_set.proxy_data.ttl_plus_1--;

	proxy->lmtp_client = smtp_client_init(&lmtp_set);

	return proxy;
}

static void
lmtp_proxy_connection_deinit(struct lmtp_proxy_connection *conn)
{
	if (conn->lmtp_trans != NULL)
		smtp_client_transaction_destroy(&conn->lmtp_trans);
	timeout_remove(&conn->to);
	i_stream_unref(&conn->data_input);
	i_free(conn->host);
	i_free(conn);
}

void lmtp_proxy_deinit(struct lmtp_proxy **_proxy)
{
	struct lmtp_proxy *proxy = *_proxy;
	struct lmtp_proxy_connection *const *conns;

	*_proxy = NULL;

	array_foreach(&proxy->connections, conns)
		lmtp_proxy_connection_deinit(*conns);

	smtp_client_deinit(&proxy->lmtp_client);
	i_stream_unref(&proxy->data_input);
	timeout_remove(&proxy->to_finish);
	array_free(&proxy->rcpt_to);
	array_free(&proxy->connections);
	i_free(proxy);
}

static void
lmtp_proxy_mail_cb(const struct smtp_reply *proxy_reply ATTR_UNUSED,
		   struct lmtp_proxy_connection *conn ATTR_UNUSED)
{
	/* nothing */
}

static void
lmtp_proxy_connection_finish(struct lmtp_proxy_connection *conn)
{
	conn->finished = TRUE;
	conn->lmtp_trans = NULL;
}

static void
lmtp_proxy_connection_init_ssl(struct lmtp_proxy_connection *conn,
			       struct ssl_iostream_settings *ssl_set_r,
			       enum smtp_client_connection_ssl_mode *ssl_mode_r)
{
	const struct master_service_ssl_settings *master_ssl_set;

	i_zero(ssl_set_r);
	*ssl_mode_r = SMTP_CLIENT_SSL_MODE_NONE;

	if ((conn->set.ssl_flags & PROXY_SSL_FLAG_YES) == 0)
		return;

	master_ssl_set = master_service_ssl_settings_get(master_service);
	master_service_ssl_settings_to_iostream_set(
		master_ssl_set, pool_datastack_create(),
		MASTER_SERVICE_SSL_SETTINGS_TYPE_CLIENT, ssl_set_r);
	if ((conn->set.ssl_flags & PROXY_SSL_FLAG_ANY_CERT) != 0)
		ssl_set_r->allow_invalid_cert = TRUE;

	if ((conn->set.ssl_flags & PROXY_SSL_FLAG_STARTTLS) == 0)
		*ssl_mode_r = SMTP_CLIENT_SSL_MODE_IMMEDIATE;
	else
		*ssl_mode_r = SMTP_CLIENT_SSL_MODE_STARTTLS;
}

static struct lmtp_proxy_connection *
lmtp_proxy_get_connection(struct lmtp_proxy *proxy,
			  const struct lmtp_proxy_rcpt_settings *set)
{
	struct smtp_client_settings lmtp_set;
	struct smtp_client_connection *lmtp_conn;
	struct smtp_server_transaction *trans = proxy->trans;
	struct lmtp_proxy_connection *const *conns, *conn;
	enum smtp_client_connection_ssl_mode ssl_mode;
	struct ssl_iostream_settings ssl_set;

	i_assert(set->timeout_msecs > 0);

	array_foreach(&proxy->connections, conns) {
		conn = *conns;

		if (conn->set.protocol == set->protocol &&
		    conn->set.port == set->port &&
		    strcmp(conn->set.host, set->host) == 0 &&
		    net_ip_compare(&conn->set.hostip, &set->hostip) &&
		    net_ip_compare(&conn->set.source_ip, &set->source_ip) &&
		    conn->set.ssl_flags == set->ssl_flags)
			return conn;
	}

	conn = i_new(struct lmtp_proxy_connection, 1);
	conn->proxy = proxy;
	conn->set.protocol = set->protocol;
	conn->set.hostip = set->hostip;
	conn->host = i_strdup(set->host);
	conn->set.host = conn->host;
	conn->set.source_ip = set->source_ip;
	conn->set.port = set->port;
	conn->set.ssl_flags = set->ssl_flags;
	conn->set.timeout_msecs = set->timeout_msecs;
	array_append(&proxy->connections, &conn, 1);

	lmtp_proxy_connection_init_ssl(conn, &ssl_set, &ssl_mode);

	i_zero(&lmtp_set);
	lmtp_set.my_ip = conn->set.source_ip;
	lmtp_set.ssl = &ssl_set;
	lmtp_set.peer_trusted = !conn->set.proxy_not_trusted;
	lmtp_set.forced_capabilities = SMTP_CAPABILITY__ORCPT;

	if (conn->set.hostip.family != 0) {
		lmtp_conn = smtp_client_connection_create_ip(proxy->lmtp_client,
			set->protocol, &conn->set.hostip, conn->set.port,
			conn->set.host, ssl_mode, &lmtp_set);
	} else {
		lmtp_conn = smtp_client_connection_create(proxy->lmtp_client,
			set->protocol, conn->set.host, conn->set.port,
			ssl_mode, &lmtp_set);
	}
	smtp_client_connection_connect(lmtp_conn, NULL, NULL);

	conn->lmtp_trans = smtp_client_transaction_create(lmtp_conn,
		trans->mail_from, &trans->params,
		lmtp_proxy_connection_finish, conn);
	smtp_client_connection_unref(&lmtp_conn);

	smtp_client_transaction_start(conn->lmtp_trans,
				      lmtp_proxy_mail_cb, conn);

	if (proxy->max_timeout_msecs < set->timeout_msecs)
		proxy->max_timeout_msecs = set->timeout_msecs;
	return conn;
}

static bool
lmtp_proxy_handle_reply(struct smtp_server_cmd_ctx *cmd,
			const struct smtp_reply *reply,
			struct smtp_reply *reply_r)
{
	*reply_r = *reply;

	if (!smtp_reply_is_remote(reply) ||
		reply->status == SMTP_CLIENT_COMMAND_ERROR_CONNECTION_CLOSED) {
		const char *detail = "";

		switch (reply->status) {
		case SMTP_CLIENT_COMMAND_ERROR_ABORTED:
			break;
		case SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED:
			detail = " (DNS lookup)";
			break;
		case SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED:
		case SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED:
			detail = " (connect)";
			break;
		case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST:
		case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_CLOSED:
			detail = " (connection lost)";
			break;
		case SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY:
			detail = " (bad reply)";
			break;
		case SMTP_CLIENT_COMMAND_ERROR_TIMED_OUT:
			detail = " (timed out)";
			break;
		default:
			break;
		}

		smtp_server_command_fail(cmd->cmd, 451, "4.4.0",
			"Remote server not answering%s", detail);
		return FALSE;
	}

	if (!smtp_reply_has_enhanced_code(reply)) {
		reply_r->enhanced_code =
			SMTP_REPLY_ENH_CODE(reply->status / 100, 0, 0);
	}
	return TRUE;
}

/*
 * RCPT command
 */

static bool
lmtp_proxy_rcpt_parse_fields(struct lmtp_proxy_rcpt_settings *set,
			     const char *const *args, const char **address)
{
	const char *p, *key, *value;
	bool proxying = FALSE, port_set = FALSE;

	for (; *args != NULL; args++) {
		p = strchr(*args, '=');
		if (p == NULL) {
			key = *args;
			value = "";
		} else {
			key = t_strdup_until(*args, p);
			value = p + 1;
		}

		if (strcmp(key, "proxy") == 0)
			proxying = TRUE;
		else if (strcmp(key, "host") == 0)
			set->host = value;
		else if (strcmp(key, "hostip") == 0) {
			if (net_addr2ip(value, &set->hostip) < 0) {
				i_error("proxy: Invalid hostip %s", value);
				return FALSE;
			}
		} else if (strcmp(key, "source_ip") == 0) {
			if (net_addr2ip(value, &set->source_ip) < 0) {
				i_error("proxy: Invalid source_ip %s", value);
				return FALSE;
			}
		} else if (strcmp(key, "port") == 0) {
			if (net_str2port(value, &set->port) < 0) {
				i_error("proxy: Invalid port number %s", value);
				return FALSE;
			}
			port_set = TRUE;
		} else if (strcmp(key, "proxy_timeout") == 0) {
			if (str_to_uint(value, &set->timeout_msecs) < 0) {
				i_error("proxy: Invalid proxy_timeout value %s", value);
				return FALSE;
			}
			set->timeout_msecs *= 1000;
		} else if (strcmp(key, "proxy_not_trusted") == 0) {
			set->proxy_not_trusted = TRUE;
		} else if (strcmp(key, "protocol") == 0) {
			if (strcmp(value, "lmtp") == 0) {
				set->protocol = SMTP_PROTOCOL_LMTP;
				if (!port_set)
					set->port = 24;
			} else if (strcmp(value, "smtp") == 0) {
				set->protocol = SMTP_PROTOCOL_SMTP;
				if (!port_set)
					set->port = 25;
			} else {
				i_error("proxy: Unknown protocol %s", value);
				return FALSE;
			}
		} else if (strcmp(key, "ssl") == 0) {
			set->ssl_flags |= PROXY_SSL_FLAG_YES;
			if (strcmp(value, "any-cert") == 0)
				set->ssl_flags |= PROXY_SSL_FLAG_ANY_CERT;
		} else if (strcmp(key, "starttls") == 0) {
			set->ssl_flags |= PROXY_SSL_FLAG_YES |
				PROXY_SSL_FLAG_STARTTLS;
			if (strcmp(value, "any-cert") == 0)
				set->ssl_flags |= PROXY_SSL_FLAG_ANY_CERT;
		} else if (strcmp(key, "user") == 0 ||
			   strcmp(key, "destuser") == 0) {
			/* changing the username */
			*address = value;
		} else {
			/* just ignore it */
		}
	}
	if (proxying && set->host == NULL) {
		i_error("proxy: host not given");
		return FALSE;
	}
	return proxying;
}

static bool
lmtp_proxy_is_ourself(const struct client *client,
		      const struct lmtp_proxy_rcpt_settings *set)
{
	struct ip_addr ip;

	if (set->port != client->local_port)
		return FALSE;

	if (set->hostip.family != 0)
		ip = set->hostip;
	else {
		if (net_addr2ip(set->host, &ip) < 0)
			return FALSE;
	}
	if (!net_ip_compare(&ip, &client->local_ip))
		return FALSE;
	return TRUE;
}

static void
lmtp_proxy_rcpt_approved(struct smtp_server_recipient *rcpt ATTR_UNUSED,
			 struct lmtp_proxy_recipient *lprcpt)
{
	struct client *client = lprcpt->rcpt.client;

	lmtp_recipient_finish(&lprcpt->rcpt);

	/* add to proxy recipients */
	array_append(&client->proxy->rcpt_to, &lprcpt, 1);
}

static void
lmtp_proxy_rcpt_cb(const struct smtp_reply *proxy_reply,
		   struct lmtp_proxy_recipient *lprcpt)
{
	struct smtp_server_cmd_ctx *cmd = lprcpt->rcpt.rcpt_cmd;
	struct smtp_reply reply;

	if (!lmtp_proxy_handle_reply(cmd, proxy_reply, &reply))
		return;

	if (smtp_reply_is_success(proxy_reply)) {
		/* if backend accepts it, we accept it too */

		/* the default 2.0.0 code won't do */
		if (!smtp_reply_has_enhanced_code(proxy_reply))
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 1, 0);
	}

	/* forward reply */
	smtp_server_reply_forward(cmd, &reply);
}

int lmtp_proxy_rcpt(struct client *client,
		    struct smtp_server_cmd_ctx *cmd,
		    struct smtp_server_recipient *rcpt,
		    const char *username, const char *detail,
		    char delim)
{
	struct auth_master_connection *auth_conn;
	struct lmtp_proxy_rcpt_settings set;
	struct lmtp_proxy_connection *conn;
	struct lmtp_proxy_recipient *lprcpt;
	struct smtp_server_transaction *trans;
	struct smtp_address *address = rcpt->path;
	struct auth_user_info info;
	struct mail_storage_service_input input;
	const char *const *fields, *errstr, *orig_username = username;
	struct smtp_proxy_data proxy_data;
	struct smtp_address *user;
	pool_t auth_pool;
	int ret;

	trans = smtp_server_connection_get_transaction(cmd->conn);
	i_assert(trans != NULL); /* MAIL command is synchronous */

	i_zero(&input);
	input.module = input.service = "lmtp";
	mail_storage_service_init_settings(storage_service, &input);

	i_zero(&info);
	info.service = master_service_get_name(master_service);
	info.local_ip = client->local_ip;
	info.remote_ip = client->remote_ip;
	info.local_port = client->local_port;
	info.remote_port = client->remote_port;

	// FIXME: make this async
	auth_pool = pool_alloconly_create("auth lookup", 1024);
	auth_conn = mail_storage_service_get_auth_conn(storage_service);
	ret = auth_master_pass_lookup(auth_conn, username, &info,
				      auth_pool, &fields);
	if (ret <= 0) {
		errstr = ret < 0 && fields[0] != NULL ?
			t_strdup(fields[0]) : "Temporary user lookup failure";
		pool_unref(&auth_pool);
		if (ret < 0) {
			smtp_server_reply(cmd, 451, "4.3.0", "<%s> %s",
				smtp_address_encode(address), errstr);
			return -1;
		} else {
			/* user not found from passdb. revert to local delivery */
			return 0;
		}
	}

	i_zero(&set);
	set.port = client->local_port;
	set.protocol = SMTP_PROTOCOL_LMTP;
	set.timeout_msecs = LMTP_PROXY_DEFAULT_TIMEOUT_MSECS;

	if (!lmtp_proxy_rcpt_parse_fields(&set, fields, &username)) {
		/* not proxying this user */
		pool_unref(&auth_pool);
		return 0;
	}
	if (strcmp(username, orig_username) != 0) {
		if (smtp_address_parse_username(pool_datastack_create(),
						username, &user, &errstr) < 0) {
			i_error("%s: Username `%s' returned by passdb lookup is not a valid SMTP address",
				orig_username, username);
			smtp_server_reply(cmd, 550, "5.3.5", "<%s> "
				"Internal user lookup failure",
				smtp_address_encode(address));
			pool_unref(&auth_pool);
			return -1;
		}
		/* username changed. change the address as well */
		if (*detail == '\0') {
			address = user;
		} else {
			address = smtp_address_add_detail_temp(user, detail, delim);
		}
	} else if (lmtp_proxy_is_ourself(client, &set)) {
		i_error("Proxying to <%s> loops to itself", username);
		smtp_server_reply(cmd, 554, "5.4.6",
			"<%s> Proxying loops to itself",
			smtp_address_encode(address));
		pool_unref(&auth_pool);
		return -1;
	}

	smtp_server_connection_get_proxy_data(cmd->conn, &proxy_data);
	if (proxy_data.ttl_plus_1 == 1) {
		i_error("Proxying to <%s> appears to be looping (TTL=0)",
			username);
		smtp_server_reply(cmd, 554, "5.4.6",
			"<%s> Proxying appears to be looping (TTL=0)",
			smtp_address_encode(address));
		pool_unref(&auth_pool);
		return -1;
	}

	if (client->proxy == NULL)
		client->proxy = lmtp_proxy_init(client, trans);

	conn = lmtp_proxy_get_connection(client->proxy, &set);
	pool_unref(&auth_pool);

	lprcpt = p_new(rcpt->pool, struct lmtp_proxy_recipient, 1);
	lmtp_recipient_init(&lprcpt->rcpt, client,
			    LMTP_RECIPIENT_TYPE_PROXY, cmd, rcpt);
	lprcpt->address = smtp_address_clone(rcpt->pool, address);
	lprcpt->conn = conn;

	smtp_server_recipient_add_hook(
		rcpt, SMTP_SERVER_RECIPIENT_HOOK_APPROVED,
		lmtp_proxy_rcpt_approved, lprcpt);
	rcpt->context = lprcpt;

	smtp_client_transaction_add_rcpt(conn->lmtp_trans,
		address, &rcpt->params,
		lmtp_proxy_rcpt_cb, lmtp_proxy_data_cb, lprcpt);
	return 1;
}

/*
 * DATA command
 */

static void
lmtp_proxy_data_cb(const struct smtp_reply *proxy_reply,
		   struct lmtp_proxy_recipient *lprcpt)
{
	struct lmtp_proxy_connection *conn = lprcpt->conn;
	struct lmtp_proxy *proxy = conn->proxy;
	struct smtp_server_cmd_ctx *cmd = proxy->pending_data_cmd;
	struct smtp_server_transaction *trans = proxy->trans;
	struct smtp_address *address = lprcpt->address;
	const struct smtp_client_transaction_times *times =
		smtp_client_transaction_get_times(conn->lmtp_trans);
	unsigned int rcpt_index = lprcpt->rcpt.index;
	struct smtp_reply reply;
	string_t *msg;

	/* compose log message */
	msg = t_str_new(128);
	str_printfa(msg, "%s: ", trans->id);
	if (smtp_reply_is_success(proxy_reply))
		str_append(msg, "Sent message to");
	else
		str_append(msg, "Failed to send message to");
	str_printfa(msg, " <%s> at %s:%u: %s (%u/%u at %u ms)",
		    smtp_address_encode(address),
		    conn->set.host, conn->set.port,
		    smtp_reply_log(proxy_reply),
		    rcpt_index + 1, array_count(&trans->rcpt_to),
		    timeval_diff_msecs(&ioloop_timeval, &times->started));

	/* handle reply */
	if (smtp_reply_is_success(proxy_reply)) {
		/* if backend accepts it, we accept it too */
		i_info("%s", str_c(msg));

		/* substitute our own success message */
		smtp_reply_printf(&reply, 250, "<%s> %s Saved",
			smtp_address_encode(address), trans->id);
		/* do let the enhanced code through */
		if (!smtp_reply_has_enhanced_code(proxy_reply))
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 0, 0);
		else
			reply.enhanced_code = proxy_reply->enhanced_code;

	} else {
		if (smtp_reply_is_remote(proxy_reply)) {
			/* The problem isn't with the proxy, it's with the
			   remote side. so the remote side will log an error,
			   while for us this is just an info event */
			i_info("%s", str_c(msg));
		} else {
			i_error("%s", str_c(msg));
		}

		if (!lmtp_proxy_handle_reply(cmd, proxy_reply, &reply))
			return;
	}

	/* forward reply */
	smtp_server_reply_index_forward(cmd, rcpt_index, &reply);
}

static void
lmtp_proxy_data_dummy_cb(const struct smtp_reply *proxy_reply ATTR_UNUSED,
			 struct lmtp_proxy_connection *conn ATTR_UNUSED)
{
	/* nothing */
}

void lmtp_proxy_data(struct client *client,
		     struct smtp_server_cmd_ctx *cmd,
		     struct smtp_server_transaction *trans ATTR_UNUSED,
		     struct istream *data_input)
{
	struct lmtp_proxy *proxy = client->proxy;
	struct lmtp_proxy_connection *const *conns;
	uoff_t size;

	i_assert(data_input->seekable);
	i_assert(proxy->data_input == NULL);

	proxy->pending_data_cmd = cmd;
	proxy->data_input = data_input;
	i_stream_ref(proxy->data_input);
	if (i_stream_get_size(proxy->data_input, TRUE, &size) < 0) {
		i_error("i_stream_get_size(data_input) failed: %s",
			i_stream_get_error(proxy->data_input));
		size = (uoff_t)-1;
	}

	/* create the data_input streams first */
	array_foreach(&proxy->connections, conns) {
		struct lmtp_proxy_connection *conn = *conns;

		if (conn->finished) {
			/* this connection had already failed */
			continue;
		}

		if (size == (uoff_t)-1)
			conn->data_input = i_stream_create_limit(data_input, (uoff_t)-1);
		else
			conn->data_input = i_stream_create_sized(data_input, size);
	}
	/* now that all the streams are created, start reading them
	   (reading them earlier could have caused the data_input parent's
	   offset to change) */
	array_foreach(&proxy->connections, conns) {
		struct lmtp_proxy_connection *conn = *conns;

		if (conn->finished) {
			/* this connection had already failed */
			continue;
		}

		smtp_client_transaction_set_timeout(conn->lmtp_trans,
			proxy->max_timeout_msecs);
		smtp_client_transaction_send(conn->lmtp_trans,
			conn->data_input,
			lmtp_proxy_data_dummy_cb, conn);
	}
}
