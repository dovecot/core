/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lmtp-common.h"
#include "istream.h"
#include "istream-sized.h"
#include "ostream.h"
#include "iostream-ssl.h"
#include "str.h"
#include "str-sanitize.h"
#include "strescape.h"
#include "time-util.h"
#include "smtp-common.h"
#include "smtp-params.h"
#include "smtp-address.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"
#include "smtp-client-transaction.h"
#include "smtp-dovecot.h"
#include "auth-proxy.h"
#include "auth-master.h"
#include "master-service-ssl-settings.h"
#include "mail-storage-service.h"
#include "lda-settings.h"
#include "lmtp-recipient.h"
#include "lmtp-proxy.h"

#define LMTP_MAX_REPLY_SIZE 4096
#define LMTP_PROXY_DEFAULT_TIMEOUT_MSECS (1000*125)

struct lmtp_proxy_redirect {
	struct ip_addr ip;
	in_port_t port;
};

struct lmtp_proxy_rcpt_settings {
	struct auth_proxy_settings set;
	enum smtp_protocol protocol;
	struct smtp_params_rcpt params;
};

struct lmtp_proxy_recipient {
	struct lmtp_recipient *rcpt;
	struct lmtp_proxy_connection *conn;
	ARRAY(struct lmtp_proxy_redirect) redirect_path;

	struct smtp_address *address;

	const unsigned char *forward_fields;
	size_t forward_fields_size;

	unsigned int proxy_ttl;

	bool rcpt_to_failed:1;
	bool data_reply_received:1;
	bool nologin:1;
	bool proxy_redirect_reauth:1;
};

struct lmtp_proxy_connection {
	struct lmtp_proxy *proxy;
	struct lmtp_proxy_rcpt_settings set;
	char *host;

	struct smtp_client_connection *lmtp_conn;
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

	struct istream *data_input;

	unsigned int max_timeout_msecs;
	unsigned int initial_ttl;
	unsigned int proxy_session_seq;

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
	const char *extra_capabilities[] = {
		LMTP_RCPT_FORWARD_CAPABILITY,
		NULL };
	struct smtp_client_settings lmtp_set;
	struct lmtp_proxy *proxy;

	proxy = i_new(struct lmtp_proxy, 1);
	proxy->client = client;
	proxy->trans = trans;
	i_array_init(&proxy->rcpt_to, 32);
	i_array_init(&proxy->connections, 32);

	i_zero(&lmtp_set);
	lmtp_set.my_hostname = client->my_domain;
	lmtp_set.extra_capabilities = extra_capabilities;
	lmtp_set.dns_client_socket_path = dns_client_socket_path;
	lmtp_set.max_reply_size = LMTP_MAX_REPLY_SIZE;
	lmtp_set.rawlog_dir = client->lmtp_set->lmtp_proxy_rawlog_dir;

	smtp_server_connection_get_proxy_data(client->conn,
					      &lmtp_set.proxy_data);
	lmtp_set.proxy_data.source_ip = client->remote_ip;
	lmtp_set.proxy_data.source_port = client->remote_port;
	/* This initial session_id is used only locally by lib-smtp. Each LMTP
	   proxy connection gets a more specific updated session_id. */
	lmtp_set.proxy_data.session = trans->id;
	if (lmtp_set.proxy_data.ttl_plus_1 == 0)
		lmtp_set.proxy_data.ttl_plus_1 = LMTP_PROXY_DEFAULT_TTL + 1;
	else
		lmtp_set.proxy_data.ttl_plus_1--;
	lmtp_set.event_parent = client->event;

	if (lmtp_set.proxy_data.ttl_plus_1 <= 1)
		proxy->initial_ttl = 1;
	else
		proxy->initial_ttl = lmtp_set.proxy_data.ttl_plus_1 - 1;

	proxy->lmtp_client = smtp_client_init(&lmtp_set);

	return proxy;
}

static void lmtp_proxy_connection_deinit(struct lmtp_proxy_connection *conn)
{
	if (conn->lmtp_trans != NULL)
		smtp_client_transaction_destroy(&conn->lmtp_trans);
	if (conn->lmtp_conn != NULL)
		smtp_client_connection_close(&conn->lmtp_conn);
	timeout_remove(&conn->to);
	i_stream_unref(&conn->data_input);
	i_free(conn->host);
	i_free(conn);
}

void lmtp_proxy_deinit(struct lmtp_proxy **_proxy)
{
	struct lmtp_proxy *proxy = *_proxy;
	struct lmtp_proxy_connection *conn;

	*_proxy = NULL;

	array_foreach_elem(&proxy->connections, conn)
		lmtp_proxy_connection_deinit(conn);

	smtp_client_deinit(&proxy->lmtp_client);
	i_stream_unref(&proxy->data_input);
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

static void lmtp_proxy_connection_finish(struct lmtp_proxy_connection *conn)
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

	*ssl_mode_r = SMTP_CLIENT_SSL_MODE_NONE;

	if ((conn->set.set.ssl_flags & AUTH_PROXY_SSL_FLAG_YES) == 0) {
		i_zero(ssl_set_r);
		return;
	}

	master_ssl_set = master_service_ssl_settings_get(master_service);
	master_service_ssl_client_settings_to_iostream_set(
		master_ssl_set, pool_datastack_create(), ssl_set_r);
	if ((conn->set.set.ssl_flags & AUTH_PROXY_SSL_FLAG_ANY_CERT) != 0)
		ssl_set_r->allow_invalid_cert = TRUE;

	if ((conn->set.set.ssl_flags & AUTH_PROXY_SSL_FLAG_STARTTLS) == 0)
		*ssl_mode_r = SMTP_CLIENT_SSL_MODE_IMMEDIATE;
	else
		*ssl_mode_r = SMTP_CLIENT_SSL_MODE_STARTTLS;
}

static bool
lmtp_proxy_connection_has_rcpt_forward(struct lmtp_proxy_connection *conn)
{
	const struct smtp_capability_extra *cap_extra =
		smtp_client_connection_get_extra_capability(
			conn->lmtp_conn, LMTP_RCPT_FORWARD_CAPABILITY);

	return (cap_extra != NULL);
}

static struct lmtp_proxy_connection *
lmtp_proxy_get_connection(struct lmtp_proxy *proxy,
			  const struct lmtp_proxy_rcpt_settings *set)
{
	static const char *rcpt_param_extensions[] =
		{ LMTP_RCPT_FORWARD_PARAMETER, NULL };
	static const struct smtp_client_capability_extra cap_rcpt_forward = {
		.name = LMTP_RCPT_FORWARD_CAPABILITY,
		.rcpt_param_extensions = rcpt_param_extensions,
	};
	struct smtp_client_settings lmtp_set;
	struct smtp_server_transaction *trans = proxy->trans;
	struct client *client = proxy->client;
	struct lmtp_proxy_connection *conn;
	enum smtp_client_connection_ssl_mode ssl_mode;
	struct ssl_iostream_settings ssl_set;

	i_assert(set->set.timeout_msecs > 0);

	array_foreach_elem(&proxy->connections, conn) {
		if (conn->set.protocol == set->protocol &&
		    conn->set.set.port == set->set.port &&
		    strcmp(conn->set.set.host, set->set.host) == 0 &&
		    (set->set.host_ip.family == 0 ||
		     net_ip_compare(&conn->set.set.host_ip, &set->set.host_ip)) &&
		    net_ip_compare(&conn->set.set.source_ip, &set->set.source_ip) &&
		    conn->set.set.ssl_flags == set->set.ssl_flags)
			return conn;
	}

	conn = i_new(struct lmtp_proxy_connection, 1);
	conn->proxy = proxy;
	conn->set.protocol = set->protocol;
	conn->set.set.host_ip = set->set.host_ip;
	conn->host = i_strdup(set->set.host);
	conn->set.set.host = conn->host;
	conn->set.set.source_ip = set->set.source_ip;
	conn->set.set.port = set->set.port;
	conn->set.set.ssl_flags = set->set.ssl_flags;
	conn->set.set.timeout_msecs = set->set.timeout_msecs;
	array_push_back(&proxy->connections, &conn);

	lmtp_proxy_connection_init_ssl(conn, &ssl_set, &ssl_mode);

	i_zero(&lmtp_set);
	lmtp_set.my_ip = conn->set.set.source_ip;
	lmtp_set.ssl = &ssl_set;
	lmtp_set.peer_trusted = !conn->set.set.remote_not_trusted;
	lmtp_set.forced_capabilities = SMTP_CAPABILITY__ORCPT;
	lmtp_set.mail_send_broken_path = TRUE;
	lmtp_set.verbose_user_errors = client->lmtp_set->lmtp_verbose_replies;

	if (conn->set.set.host_ip.family != 0) {
		conn->lmtp_conn = smtp_client_connection_create_ip(
			proxy->lmtp_client, set->protocol,
			&conn->set.set.host_ip, conn->set.set.port,
			conn->set.set.host, ssl_mode, &lmtp_set);
	} else {
		conn->lmtp_conn = smtp_client_connection_create(
			proxy->lmtp_client, set->protocol,
			conn->set.set.host, conn->set.set.port,
			ssl_mode, &lmtp_set);
	}
	struct smtp_proxy_data proxy_data = {
		.session = t_strdup_printf("%s:P%u", proxy->trans->id,
					   ++proxy->proxy_session_seq),
	};
	smtp_client_connection_update_proxy_data(conn->lmtp_conn, &proxy_data);
	smtp_client_connection_accept_extra_capability(conn->lmtp_conn,
						       &cap_rcpt_forward);
	smtp_client_connection_connect(conn->lmtp_conn, NULL, NULL);

	conn->lmtp_trans = smtp_client_transaction_create(
		conn->lmtp_conn, trans->mail_from, &trans->params, 0,
		lmtp_proxy_connection_finish, conn);

	smtp_client_transaction_start(conn->lmtp_trans,
				      lmtp_proxy_mail_cb, conn);

	if (proxy->max_timeout_msecs < set->set.timeout_msecs)
		proxy->max_timeout_msecs = set->set.timeout_msecs;
	return conn;
}

static void
lmtp_proxy_handle_connection_error(struct lmtp_proxy_recipient *lprcpt,
				   const struct smtp_reply *reply)
{
	struct lmtp_recipient *lrcpt = lprcpt->rcpt;
	struct client *client = lrcpt->client;
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	const char *detail = "";

	if (client->lmtp_set->lmtp_verbose_replies) {
		smtp_server_command_fail(rcpt->cmd->cmd, 451, "4.4.0",
					 "Proxy failed: %s (session=%s)",
					 smtp_reply_log(reply),
					 lrcpt->session_id);
		return;
	}

	switch (reply->status) {
	case SMTP_CLIENT_COMMAND_ERROR_ABORTED:
		break;
	case SMTP_CLIENT_COMMAND_ERROR_HOST_LOOKUP_FAILED:
		detail = "DNS lookup, ";
		break;
	case SMTP_CLIENT_COMMAND_ERROR_CONNECT_FAILED:
	case SMTP_CLIENT_COMMAND_ERROR_AUTH_FAILED:
		detail = "connect, ";
		break;
	case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_LOST:
	case SMTP_CLIENT_COMMAND_ERROR_CONNECTION_CLOSED:
		detail = "connection lost, ";
		break;
	case SMTP_CLIENT_COMMAND_ERROR_BAD_REPLY:
		detail = "bad reply, ";
		break;
	case SMTP_CLIENT_COMMAND_ERROR_TIMED_OUT:
		detail = "timed out, ";
		break;
	default:
		break;
	}

	smtp_server_command_fail(rcpt->cmd->cmd, 451, "4.4.0",
				 "Proxy failed (%ssession=%s)",
				 detail, lrcpt->session_id);
}

static bool
lmtp_proxy_handle_reply(struct lmtp_proxy_recipient *lprcpt,
			const struct smtp_reply *reply,
			struct smtp_reply *reply_r)
{
	*reply_r = *reply;

	if (!smtp_reply_is_remote(reply) ||
	    reply->status == SMTP_CLIENT_COMMAND_ERROR_CONNECTION_CLOSED) {
		lmtp_proxy_handle_connection_error(lprcpt, reply);
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

static void
lmtp_proxy_rcpt_login_cb(const struct smtp_reply *proxy_reply, void *context);

static void
lmtp_proxy_rcpt_destroy(struct smtp_server_recipient *rcpt ATTR_UNUSED,
			struct lmtp_proxy_recipient *lprcpt)
{
	array_free(&lprcpt->redirect_path);
}

static int
lmtp_proxy_rcpt_parse_fields(struct lmtp_proxy_recipient *lprcpt,
			     struct lmtp_proxy_rcpt_settings *set,
			     const char *const *args, const char **address)
{
	struct smtp_server_recipient *rcpt = lprcpt->rcpt->rcpt;
	const char *p, *key, *value, *error;
	in_port_t orig_port = set->set.port;
	int ret;

	set->set.proxy = FALSE;
	set->set.port = 0;

	for (; *args != NULL; args++) {
		p = strchr(*args, '=');
		if (p == NULL) {
			key = *args;
			value = "";
		} else {
			key = t_strdup_until(*args, p);
			value = p + 1;
		}

		ret = auth_proxy_settings_parse(&set->set, NULL,
						key, value, &error);
		if (ret < 0) {
			e_error(rcpt->event, "proxy: Invalid %s value '%s': %s",
				key, value, error);
			return -1;
		}
		if (ret > 0)
			continue;

		if (strcmp(key, "nologin") == 0)
			lprcpt->nologin = TRUE;
		else if (strcmp(key, "protocol") == 0) {
			if (strcmp(value, "lmtp") == 0) {
				set->protocol = SMTP_PROTOCOL_LMTP;
				if (set->set.port == 0)
					set->set.port = 24;
			} else if (strcmp(value, "smtp") == 0) {
				set->protocol = SMTP_PROTOCOL_SMTP;
				if (set->set.port == 0)
					set->set.port = 25;
			} else {
				e_error(rcpt->event,
					"proxy: Unknown protocol %s", value);
				return -1;
			}
		} else if (strcmp(key, "user") == 0) {
			/* Changing the username */
			*address = value;
		} else {
			/* Just ignore it */
		}
	}
	if (set->set.username != NULL) {
		/* "destuser" always overrides "user" */
		*address = set->set.username;
	}
	if (set->set.port == 0)
		set->set.port = orig_port;
	if (!set->set.proxy)
		return 0;

	if (set->set.host == NULL) {
		e_error(rcpt->event, "proxy: host not given");
		return -1;
	}
	if (set->set.redirect_reauth)
		lprcpt->proxy_redirect_reauth = TRUE;
	return 1;
}

static void
lmtp_proxy_rcpt_get_redirect_path(struct lmtp_proxy_recipient *lprcpt,
				  string_t *str)
{
	struct lmtp_proxy_connection *conn = lprcpt->conn;
	const struct lmtp_proxy_redirect *redirect;

	i_assert(conn->set.set.host_ip.family != 0);

	str_printfa(str, "%s",
		    net_ipport2str(&conn->set.set.host_ip, conn->set.set.port));
	if (!array_is_created(&lprcpt->redirect_path))
		return;
	array_foreach(&lprcpt->redirect_path, redirect) {
		str_printfa(str, ",%s",
			    net_ipport2str(&redirect->ip, redirect->port));
	}
}

static bool
lmtp_proxy_rcpt_have_connected(struct lmtp_proxy_recipient *lprcpt,
			       const struct ip_addr *ip, in_port_t port)
{
	struct lmtp_proxy_connection *conn = lprcpt->conn;
	const struct ip_addr *conn_ip = &conn->set.set.host_ip;
	in_port_t conn_port = conn->set.set.port;
	const struct lmtp_proxy_redirect *redirect;

	i_assert(ip->family != 0);

	if (net_ip_compare(conn_ip, ip) && conn_port == port)
		return TRUE;
	if (!array_is_created(&lprcpt->redirect_path))
		return FALSE;

	array_foreach(&lprcpt->redirect_path, redirect) {
		if (net_ip_compare(&redirect->ip, ip) && redirect->port == port)
			return TRUE;
	}
	return FALSE;
}

static bool
lmtp_proxy_is_ourself(const struct client *client,
		      const struct lmtp_proxy_rcpt_settings *set)
{
	struct ip_addr ip;

	if (set->set.port != client->local_port)
		return FALSE;

	if (set->set.host_ip.family != 0)
		ip = set->set.host_ip;
	else {
		if (net_addr2ip(set->set.host, &ip) < 0)
			return FALSE;
	}
	if (!net_ip_compare(&ip, &client->local_ip))
		return FALSE;
	return TRUE;
}

static int
lmtp_proxy_rcpt_get_connection(struct lmtp_proxy_recipient *lprcpt,
			       const struct lmtp_proxy_rcpt_settings *set,
			       struct lmtp_proxy_connection **conn_r)
{
	struct lmtp_recipient *lrcpt = lprcpt->rcpt;
	struct client *client = lrcpt->client;
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	struct smtp_server_transaction *trans;
	struct lmtp_proxy_connection *conn;
	struct smtp_proxy_data proxy_data;

	smtp_server_connection_get_proxy_data(rcpt->conn, &proxy_data);
	if (proxy_data.ttl_plus_1 == 1 ||
	    (lprcpt->conn != NULL && lprcpt->proxy_ttl == 0)) {
		e_error(rcpt->event,
			"Proxying to <%s> appears to be looping (TTL=0)",
			smtp_address_encode(rcpt->path));
		smtp_server_recipient_reply(rcpt, 554, "5.4.6",
					    "Proxying appears to be looping "
					    "(TTL=0)");
		return -1;
	}

	if (client->proxy == NULL) {
		trans = smtp_server_connection_get_transaction(rcpt->conn);
		i_assert(trans != NULL); /* MAIL command is synchronous */

		client->proxy = lmtp_proxy_init(client, trans);
	}
	if (lprcpt->conn == NULL)
		lprcpt->proxy_ttl = client->proxy->initial_ttl;

	conn = lmtp_proxy_get_connection(client->proxy, set);
	i_assert(conn != lprcpt->conn);

	*conn_r = lprcpt->conn = conn;
	return 0;
}

static int
lmtp_proxy_rcpt_parse_redirect(const struct smtp_reply *proxy_reply,
			       const char **destuser_r,
			       const char **host_r, struct ip_addr *ip_r,
			       in_port_t *port_r, const char **error_r)
{
	i_assert(proxy_reply->text_lines != NULL);

	return smtp_proxy_redirect_parse(*proxy_reply->text_lines, destuser_r,
					 host_r, ip_r, port_r, error_r);
}

static void
lmtp_proxy_rcpt_redirect_finish(struct lmtp_proxy_recipient *lprcpt,
				struct lmtp_proxy_rcpt_settings *set)
{
	struct lmtp_recipient *lrcpt = lprcpt->rcpt;
	struct client *client = lrcpt->client;
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	const struct ip_addr *ip = &set->set.host_ip;
	in_port_t port = set->set.port;
	struct lmtp_proxy_redirect *redirect;
	struct lmtp_proxy_connection *conn;

	if (lmtp_proxy_rcpt_have_connected(lprcpt, ip, port)) {
		e_error(rcpt->event,
			"Proxying loops - already connected to %s:%u",
			net_ip2addr(ip), port);
		smtp_server_recipient_reply(rcpt, 554, "5.4.6",
					    "Proxying loops to itself");
		return;
	}
	if (lmtp_proxy_is_ourself(client, set)) {
		e_error(rcpt->event, "Proxying to <%s> loops to itself",
			smtp_address_encode(lprcpt->address));
		smtp_server_recipient_reply(rcpt, 554, "5.4.6",
					    "Proxying loops to itself");
		return;
	}

	i_assert(lprcpt->proxy_ttl > 0);
	lprcpt->proxy_ttl--;

	/* Add current ip/port to redirect path */
	if (!array_is_created(&lprcpt->redirect_path))
		i_array_init(&lprcpt->redirect_path, 2);
	redirect = array_append_space(&lprcpt->redirect_path);
	redirect->ip = *ip;
	redirect->port = port;

	/* Connect to new host */
	e_debug(rcpt->event, "Redirecting to %s", net_ipport2str(ip, port));

	if (lmtp_proxy_rcpt_get_connection(lprcpt, set, &conn) < 0)
		return;

	smtp_client_connection_connect(conn->lmtp_conn,
				       lmtp_proxy_rcpt_login_cb, lprcpt);
}

static void
lmtp_proxy_rcpt_init_auth_user_info(struct lmtp_recipient *lrcpt,
				    struct auth_user_info *info_r)
{
	struct client *client = lrcpt->client;

	i_zero(info_r);
	info_r->service = master_service_get_name(master_service);
	info_r->local_ip = client->local_ip;
	info_r->real_local_ip = client->real_local_ip;
	info_r->remote_ip = client->remote_ip;
	info_r->real_remote_ip = client->real_remote_ip;
	info_r->local_port = client->local_port;
	info_r->real_local_port = client->real_local_port;
	info_r->remote_port = client->remote_port;
	info_r->real_remote_port = client->real_remote_port;
	info_r->forward_fields = lrcpt->forward_fields;
}

static void
lmtp_proxy_rcpt_redirect_relookup(struct lmtp_proxy_recipient *lprcpt,
				  struct lmtp_proxy_rcpt_settings *set,
				  const char *destuser)
{
	struct lmtp_recipient *lrcpt = lprcpt->rcpt;
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	const struct ip_addr *ip = &set->set.host_ip;
	in_port_t port = set->set.port;
	struct auth_master_connection *auth_conn;
	struct auth_user_info info;
	const char *const *fields, *errstr, *username;
	pool_t auth_pool;
	int ret;

	lmtp_proxy_rcpt_init_auth_user_info(lrcpt, &info);

	string_t *hosts_attempted = t_str_new(64);
	str_append(hosts_attempted, "proxy_redirect_host_attempts=");
	lmtp_proxy_rcpt_get_redirect_path(lprcpt, hosts_attempted);
	const char *const extra_fields[] = {
		t_strdup_printf("proxy_redirect_host_next=%s:%u",
				net_ip2addr(ip), port),
		str_c(hosts_attempted),
		t_strdup_printf("destuser=%s", str_tabescape(destuser)),
		t_strdup_printf("proxy_timeout=%u", lprcpt->conn->set.set.timeout_msecs),
	};
	t_array_init(&info.extra_fields, N_ELEMENTS(extra_fields));
	array_append(&info.extra_fields, extra_fields,
		     N_ELEMENTS(extra_fields));

	// FIXME: make this async
	auth_pool = pool_alloconly_create("auth lookup", 1024);
	auth_conn = mail_storage_service_get_auth_conn(storage_service);
	ret = auth_master_pass_lookup(auth_conn, lrcpt->username, &info,
				      auth_pool, &fields);
	if (ret <= 0) {
		if (ret == 0 || fields[0] == NULL)
			errstr = "Redirect lookup unexpectedly failed";
		else {
			errstr = t_strdup_printf(
				"Redirect lookup unexpectedly failed: %s",
				fields[0]);
		}
		pool_unref(&auth_pool);
		smtp_server_recipient_reply(rcpt, 451, "4.3.0", "%s", errstr);
		return;
	}

	if (lmtp_proxy_rcpt_parse_fields(lprcpt, set, fields, &username) <= 0) {
		smtp_server_recipient_reply(
			rcpt, 451, "4.3.0",
			"Redirect lookup yielded invalid result");
		return;
	}

	lmtp_proxy_rcpt_redirect_finish(lprcpt, set);
}

static void
lmtp_proxy_rcpt_redirect(struct lmtp_proxy_recipient *lprcpt,
			 const struct smtp_reply *proxy_reply)
{
	struct lmtp_recipient *lrcpt = lprcpt->rcpt;
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	struct lmtp_proxy_connection *conn = lprcpt->conn;
	struct lmtp_proxy_rcpt_settings set;
	const char *host, *destuser = lrcpt->username, *error;
	struct ip_addr ip;
	in_port_t port;

	if (lmtp_proxy_rcpt_parse_redirect(proxy_reply, &destuser,
					   &host, &ip, &port, &error) < 0) {
		e_error(rcpt->event,
			"Backend server returned invalid redirect '%s': %s",
			str_sanitize(smtp_reply_log(proxy_reply), 160), error);
		smtp_server_recipient_reply(rcpt, 451, "4.3.0",
					    "Temporary internal proxy error");
		return;
	}

	set = conn->set;
	set.set.host = host;
	set.set.host_ip = ip;
	set.set.port = port;

	if (lprcpt->proxy_redirect_reauth)
		lmtp_proxy_rcpt_redirect_relookup(lprcpt, &set, destuser);
	else
		lmtp_proxy_rcpt_redirect_finish(lprcpt, &set);
}

static void
lmtp_proxy_rcpt_approved(struct smtp_server_recipient *rcpt ATTR_UNUSED,
			 struct lmtp_proxy_recipient *lprcpt)
{
	struct client *client = lprcpt->rcpt->client;

	/* Add to proxy recipients */
	array_push_back(&client->proxy->rcpt_to, &lprcpt);
}

static void
lmtp_proxy_rcpt_cb(const struct smtp_reply *proxy_reply,
		   struct lmtp_proxy_recipient *lprcpt)
{
	struct smtp_server_recipient *rcpt = lprcpt->rcpt->rcpt;
	struct smtp_reply reply;

	if (!lmtp_proxy_handle_reply(lprcpt, proxy_reply, &reply))
		return;

	if (smtp_reply_is_proxy_redirect(proxy_reply)) {
		lmtp_proxy_rcpt_redirect(lprcpt, proxy_reply);
		return;
	}

	if (smtp_reply_is_success(proxy_reply)) {
		/* If backend accepts it, we accept it too */

		/* The default 2.0.0 code won't do */
		if (!smtp_reply_has_enhanced_code(proxy_reply))
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 1, 0);
	}

	/* Forward reply */
	smtp_server_recipient_reply_forward(rcpt, &reply);
}

static void
lmtp_proxy_rcpt_login_cb(const struct smtp_reply *proxy_reply, void *context)
{
	struct lmtp_proxy_recipient *lprcpt = context;
	struct lmtp_recipient *lrcpt = lprcpt->rcpt;
	struct lmtp_proxy_connection *conn = lprcpt->conn;
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	struct smtp_reply reply;
	struct smtp_client_transaction_rcpt *relay_rcpt;
	struct smtp_params_rcpt *rcpt_params = &rcpt->params;
	bool add_orcpt_param = FALSE, add_xrcptforward_param = FALSE;
	pool_t param_pool;

	if (conn->set.set.host_ip.family == 0) {
		smtp_client_connection_get_remote_ip(conn->lmtp_conn,
						     &conn->set.set.host_ip);
	}

	if (!lmtp_proxy_handle_reply(lprcpt, proxy_reply, &reply))
		return;
	if (!smtp_reply_is_success(proxy_reply)) {
		smtp_server_recipient_reply_forward(rcpt, &reply);
		return;
	}

	/* Add an ORCPT parameter when passdb changed the username (and
	   therefore the RCPT address changed) and there is no ORCPT parameter
	   yet. */
	if (!smtp_params_rcpt_has_orcpt(rcpt_params) &&
	    !smtp_address_equals(lprcpt->address, rcpt->path))
		add_orcpt_param = TRUE;

	/* Add forward fields parameter when passdb returned forward_* fields */
	if (lprcpt->forward_fields != NULL &&
	    lmtp_proxy_connection_has_rcpt_forward(conn))
		add_xrcptforward_param = TRUE;

	/* Copy params when changes are pending */
	param_pool = NULL;
	if (add_orcpt_param || add_xrcptforward_param) {
		param_pool = pool_datastack_create();
		rcpt_params = p_new(param_pool, struct smtp_params_rcpt, 1);
		smtp_params_rcpt_copy(param_pool, rcpt_params, &rcpt->params);
	}

	/* Add ORCPT */
	if (add_orcpt_param) {
		smtp_params_rcpt_set_orcpt(rcpt_params, param_pool,
					   rcpt->path);
	}
	/* Add forward fields parameter */
	if (add_xrcptforward_param) {
		smtp_params_rcpt_encode_extra(
			rcpt_params, param_pool, LMTP_RCPT_FORWARD_PARAMETER,
			lprcpt->forward_fields, lprcpt->forward_fields_size);
	}

	relay_rcpt = smtp_client_transaction_add_pool_rcpt(
		conn->lmtp_trans, rcpt->pool, lprcpt->address, rcpt_params,
		lmtp_proxy_rcpt_cb, lprcpt);
	smtp_client_transaction_rcpt_set_data_callback(
		relay_rcpt, lmtp_proxy_data_cb, lprcpt);
}

static int
lmtp_proxy_rcpt_handle_not_proxied(struct lmtp_proxy_recipient *lprcpt,
				   struct lmtp_proxy_rcpt_settings *set,
				   const char *destuser)
{
	struct smtp_server_recipient *rcpt = lprcpt->rcpt->rcpt;

	if (!lprcpt->nologin) {
		/* Ignore optional referral */
		return 0;
	}

	if (set->set.host == NULL) {
		smtp_server_recipient_reply(rcpt, 550, "5.3.5",
					    "Login disabled");
		return -1;
	}

	const struct smtp_proxy_redirect predir = {
		.username = destuser,
		.host = set->set.host,
		.host_ip = set->set.host_ip,
		.port = set->set.port,
	};
	smtp_server_recipient_reply_redirect(rcpt, 0, &predir);
	return -1;
}

int lmtp_proxy_rcpt(struct client *client,
		    struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		    struct lmtp_recipient *lrcpt)
{
	struct auth_master_connection *auth_conn;
	struct lmtp_proxy_rcpt_settings set;
	struct lmtp_proxy_connection *conn;
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	struct lmtp_proxy_recipient *lprcpt;
	struct smtp_address *address = rcpt->path;
	struct auth_user_info info;
	struct mail_storage_service_input input;
	const char *const *fields, *errstr, *username, *orig_username;
	struct smtp_address *user;
	string_t *fwfields;
	pool_t auth_pool;
	int ret;

	lprcpt = p_new(rcpt->pool, struct lmtp_proxy_recipient, 1);
	lprcpt->rcpt = lrcpt;

	lrcpt->type = LMTP_RECIPIENT_TYPE_PROXY;
	lrcpt->backend_context = lprcpt;

	i_zero(&input);
	input.module = input.service = "lmtp";
	mail_storage_service_init_settings(storage_service, &input);

	lmtp_proxy_rcpt_init_auth_user_info(lrcpt, &info);

	// FIXME: make this async
	username = orig_username = lrcpt->username;
	auth_pool = pool_alloconly_create("auth lookup", 1024);
	auth_conn = mail_storage_service_get_auth_conn(storage_service);
	ret = auth_master_pass_lookup(auth_conn, username, &info,
				      auth_pool, &fields);
	if (ret <= 0) {
		errstr = (ret < 0 && fields[0] != NULL ?
			  t_strdup(fields[0]) :
			  "Temporary user lookup failure");
		pool_unref(&auth_pool);
		if (ret < 0) {
			smtp_server_recipient_reply(rcpt, 451, "4.3.0", "%s",
						    errstr);
			return -1;
		} else {
			/* User not found from passdb: revert to local delivery.
			 */
			return 0;
		}
	}

	i_zero(&set);
	set.set.port = (client->local_port != 0 ?
			client->local_port : LMTP_PROXY_DEFAULT_PORT);
	set.set.timeout_msecs = LMTP_PROXY_DEFAULT_TIMEOUT_MSECS;
	set.protocol = SMTP_PROTOCOL_LMTP;

	ret = lmtp_proxy_rcpt_parse_fields(lprcpt, &set, fields, &username);
	if (ret < 0) {
		smtp_server_recipient_reply(
			rcpt, 550, "5.3.5",
			"Internal user lookup failure");
		pool_unref(&auth_pool);
		return -1;
	}
	if (ret == 0) {
		/* Not proxying this user */
		ret = lmtp_proxy_rcpt_handle_not_proxied(lprcpt, &set, username);
		pool_unref(&auth_pool);
		return ret;
	}
	if (strcmp(username, orig_username) != 0) {
		/* The existing "user" event field is overridden with the new
		   user name, while old username is available as "orig_user" */
		event_add_str(rcpt->event, "user", username);
		event_add_str(rcpt->event, "original_user", orig_username);

		if (smtp_address_parse_username(pool_datastack_create(),
						username, &user, &errstr) < 0) {
			e_error(rcpt->event, "%s: "
				"Username `%s' returned by passdb lookup is not a valid SMTP address",
				orig_username, username);
			smtp_server_recipient_reply(
				rcpt, 550, "5.3.5",
				"Internal user lookup failure");
			pool_unref(&auth_pool);
			return -1;
		}
		/* Username changed. change the address as well */
		if (*lrcpt->detail == '\0') {
			address = user;
		} else {
			address = smtp_address_add_detail_temp(
				user, lrcpt->detail, lrcpt->delim);
		}
	} else if (lmtp_proxy_is_ourself(client, &set)) {
		e_error(rcpt->event, "Proxying to <%s> loops to itself",
			username);
		smtp_server_recipient_reply(rcpt, 554, "5.4.6",
					    "Proxying loops to itself");
		pool_unref(&auth_pool);
		return -1;
	}

	if (lmtp_proxy_rcpt_get_connection(lprcpt, &set, &conn) < 0) {
		pool_unref(&auth_pool);
		return -1;
	}

	lprcpt->address = smtp_address_clone(rcpt->pool, address);

	smtp_server_recipient_add_hook(
		rcpt, SMTP_SERVER_RECIPIENT_HOOK_DESTROY,
		lmtp_proxy_rcpt_destroy, lprcpt);
	smtp_server_recipient_add_hook(
		rcpt, SMTP_SERVER_RECIPIENT_HOOK_APPROVED,
		lmtp_proxy_rcpt_approved, lprcpt);

	/* Copy forward fields returned from passdb */
	fwfields = NULL;
	for (const char *const *ptr = fields; *ptr != NULL; ptr++) {
		if (!str_begins_icase_with(*ptr, "forward_"))
			continue;

		if (fwfields == NULL)
			fwfields = t_str_new(128);
		else
			str_append_c(fwfields, '\t');

		str_append_tabescaped(fwfields, (*ptr) + 8);
	}
	if (fwfields != NULL) {
		lprcpt->forward_fields = p_memdup(
			rcpt->pool, str_data(fwfields), str_len(fwfields));
		lprcpt->forward_fields_size = str_len(fwfields);
	}

	pool_unref(&auth_pool);

	smtp_client_connection_connect(conn->lmtp_conn,
				       lmtp_proxy_rcpt_login_cb, lprcpt);
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
	struct lmtp_recipient *lrcpt = lprcpt->rcpt;
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	struct lmtp_proxy *proxy = conn->proxy;
	struct smtp_server_transaction *trans = proxy->trans;
	struct smtp_address *address = lprcpt->address;
	const struct smtp_client_transaction_times *times =
		smtp_client_transaction_get_times(conn->lmtp_trans);
	unsigned int rcpt_index = rcpt->index;
	struct smtp_reply reply;
	string_t *msg;

	/* Compose log message */
	msg = t_str_new(128);
	str_printfa(msg, "<%s>: ", lrcpt->session_id);
	if (smtp_reply_is_success(proxy_reply))
		str_append(msg, "Sent message to");
	else
		str_append(msg, "Failed to send message to");
	str_printfa(msg, " <%s> at %s:%u: %s (%u/%u at %u ms)",
		    smtp_address_encode(address),
		    conn->set.set.host, conn->set.set.port,
		    smtp_reply_log(proxy_reply),
		    rcpt_index + 1, array_count(&trans->rcpt_to),
		    timeval_diff_msecs(&ioloop_timeval, &times->started));

	/* Handle reply */
	if (smtp_reply_is_success(proxy_reply)) {
		/* If backend accepts it, we accept it too */
		e_info(rcpt->event, "%s", str_c(msg));

		/* Substitute our own success message */
		smtp_reply_printf(&reply, 250, "%s Saved", lrcpt->session_id);
		/* Do let the enhanced code through */
		if (!smtp_reply_has_enhanced_code(proxy_reply))
			reply.enhanced_code = SMTP_REPLY_ENH_CODE(2, 0, 0);
		else
			reply.enhanced_code = proxy_reply->enhanced_code;

	} else {
		if (smtp_reply_is_remote(proxy_reply)) {
			/* The problem isn't with the proxy, it's with the
			   remote side. so the remote side will log an error,
			   while for us this is just an info event */
			e_info(rcpt->event, "%s", str_c(msg));
		} else {
			e_error(rcpt->event, "%s", str_c(msg));
		}

		if (!lmtp_proxy_handle_reply(lprcpt, proxy_reply, &reply))
			return;
	}

	/* Forward reply */
	smtp_server_recipient_reply_forward(rcpt, &reply);
}

static void
lmtp_proxy_data_dummy_cb(const struct smtp_reply *proxy_reply ATTR_UNUSED,
			 struct lmtp_proxy_connection *conn ATTR_UNUSED)
{
	/* nothing */
}

void lmtp_proxy_data(struct client *client,
		     struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		     struct smtp_server_transaction *trans ATTR_UNUSED,
		     struct istream *data_input)
{
	struct lmtp_proxy *proxy = client->proxy;
	struct lmtp_proxy_connection *conn;
	uoff_t size;

	i_assert(data_input->seekable);
	i_assert(proxy->data_input == NULL);

	client_update_data_state(client, "proxying");

	proxy->data_input = data_input;
	i_stream_ref(proxy->data_input);
	if (i_stream_get_size(proxy->data_input, TRUE, &size) < 0) {
		e_error(client->event,
			"i_stream_get_size(data_input) failed: %s",
			i_stream_get_error(proxy->data_input));
		size = UOFF_T_MAX;
	}

	/* Create the data_input streams first */
	array_foreach_elem(&proxy->connections, conn) {
		if (conn->finished) {
			/* This connection had already failed */
			continue;
		}

		if (size == UOFF_T_MAX) {
			conn->data_input =
				i_stream_create_limit(data_input, UOFF_T_MAX);
		} else {
			conn->data_input =
				i_stream_create_sized(data_input, size);
		}
	}
	/* Now that all the streams are created, start reading them
	   (reading them earlier could have caused the data_input parent's
	   offset to change) */
	array_foreach_elem(&proxy->connections, conn) {
		if (conn->finished) {
			/* This connection had already failed */
			continue;
		}

		smtp_client_transaction_set_timeout(conn->lmtp_trans,
						    proxy->max_timeout_msecs);
		smtp_client_transaction_send(conn->lmtp_trans, conn->data_input,
					     lmtp_proxy_data_dummy_cb, conn);
	}
}
