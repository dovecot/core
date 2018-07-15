/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "submission-common.h"
#include "array.h"
#include "ioloop.h"
#include "base64.h"
#include "str.h"
#include "llist.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-ssl.h"
#include "hostpid.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "raw-storage.h"
#include "imap-urlauth.h"
#include "smtp-client.h"
#include "smtp-client-connection.h"

#include "submission-commands.h"
#include "submission-settings.h"

#include <unistd.h>

/* max. length of input command line */
#define MAX_INBUF_SIZE 4096

/* Stop reading input when output buffer has this many bytes. Once the buffer
   size has dropped to half of it, start reading input again. */
#define OUTBUF_THROTTLE_SIZE 4096

/* Disconnect client when it sends too many bad commands in a row */
#define CLIENT_MAX_BAD_COMMANDS 20

/* Disconnect client after idling this many milliseconds */
#define CLIENT_IDLE_TIMEOUT_MSECS (10*60*1000)

struct client *submission_clients;
unsigned int submission_client_count;

static const struct smtp_server_callbacks smtp_callbacks;

/* try to proxy pipelined commands in a similarly pipelined fashion */
static void client_input_pre(void *context)
{
	struct client *client = context;

	if (client->proxy_conn != NULL)
		smtp_client_connection_cork(client->proxy_conn);
}
static void client_input_post(void *context)
{
	struct client *client = context;

	if (client->proxy_conn != NULL)
		smtp_client_connection_uncork(client->proxy_conn);
}

static const char *client_remote_id(struct client *client)
{
	const char *addr = NULL;

	if (client->user->conn.remote_ip != NULL)
		addr = net_ip2addr(client->user->conn.remote_ip);
	if (addr == NULL)
		addr = "local";
	return addr;
}

static void client_proxy_ready_cb(const struct smtp_reply *reply,
				  void *context)
{
	struct client *client = context;
	enum smtp_capability caps;

	/* check proxy status */
	if ((reply->status / 100) != 2) {
		i_error("Failed to establish relay connection: %s",
			smtp_reply_log(reply));
		client_destroy(client,
			"4.4.0", "Failed to establish relay connection");
		return;
	}

	/* propagate capabilities */
	caps = smtp_client_connection_get_capabilities(client->proxy_conn);
	caps |= SMTP_CAPABILITY_AUTH | SMTP_CAPABILITY_PIPELINING |
		SMTP_CAPABILITY_SIZE | SMTP_CAPABILITY_ENHANCEDSTATUSCODES |
		SMTP_CAPABILITY_CHUNKING | SMTP_CAPABILITY_BURL |
		SMTP_CAPABILITY_VRFY;
	caps &= SUBMISSION_SUPPORTED_SMTP_CAPABILITIES;
	smtp_server_connection_set_capabilities(client->conn, caps);

	/* now that we know our capabilities, commence server protocol dialog */
	smtp_server_connection_resume(client->conn);
}

static void client_proxy_create(struct client *client,
				const struct submission_settings *set)
{
	struct mail_user *user = client->user;
	struct ssl_iostream_settings ssl_set;
	struct smtp_client_settings smtp_set;
	enum smtp_client_connection_ssl_mode ssl_mode;

	i_zero(&ssl_set);
	mail_user_init_ssl_client_settings(user, &ssl_set);
	if (set->submission_relay_ssl_verify)
		ssl_set.verbose_invalid_cert = TRUE;
	else
		ssl_set.allow_invalid_cert = TRUE;

	/* make proxy connection */
	i_zero(&smtp_set);
	smtp_set.my_hostname = set->hostname;
	smtp_set.ssl = &ssl_set;
	smtp_set.debug = user->mail_debug;
	smtp_set.rawlog_dir =
		mail_user_home_expand(user,
				      set->submission_relay_rawlog_dir);

	if (set->submission_relay_trusted) {
		smtp_set.peer_trusted = TRUE;

		if (user->conn.remote_ip != NULL) {
			smtp_set.proxy_data.source_ip =
				*user->conn.remote_ip;
			smtp_set.proxy_data.source_port =
				user->conn.remote_port;
		}
		smtp_set.proxy_data.login = user->username;
	}

	smtp_set.username = set->submission_relay_user;
	smtp_set.master_user = set->submission_relay_master_user;
	smtp_set.password = set->submission_relay_password;
	smtp_set.connect_timeout_msecs =
		set->submission_relay_connect_timeout;
	smtp_set.command_timeout_msecs =
		set->submission_relay_command_timeout;

	if (strcmp(set->submission_relay_ssl, "smtps") == 0)
		ssl_mode = SMTP_CLIENT_SSL_MODE_IMMEDIATE;
	else if (strcmp(set->submission_relay_ssl, "starttls") == 0)
		ssl_mode = SMTP_CLIENT_SSL_MODE_STARTTLS;
	else
		ssl_mode = SMTP_CLIENT_SSL_MODE_NONE;

	client->proxy_conn = smtp_client_connection_create(smtp_client,
		SMTP_PROTOCOL_SMTP, set->submission_relay_host,
		set->submission_relay_port, ssl_mode, &smtp_set);
	smtp_client_connection_connect(client->proxy_conn,
		client_proxy_ready_cb, client);
}

static void client_init_urlauth(struct client *client)
{
	static const char *access_apps[] = { "submit+", NULL };
	struct imap_urlauth_config config;

	i_zero(&config);
	config.url_host = client->set->imap_urlauth_host;
	config.url_port = client->set->imap_urlauth_port;
	config.socket_path = t_strconcat(client->user->set->base_dir,
					 "/"IMAP_URLAUTH_SOCKET_NAME, NULL);
	config.session_id = client->session_id;
	config.access_anonymous = client->user->anonymous;
	config.access_user = client->user->username;
	config.access_service = "submission";
	config.access_applications = access_apps;

	client->urlauth_ctx = imap_urlauth_init(client->user, &config);
}

struct client *client_create(int fd_in, int fd_out,
			     const char *session_id, struct mail_user *user,
			     struct mail_storage_service_user *service_user,
			     const struct submission_settings *set,
			     const char *helo,
			     const unsigned char *pdata, unsigned int pdata_len)
{
	enum submission_client_workarounds workarounds =
		set->parsed_workarounds;
	const struct mail_storage_settings *mail_set;
	struct smtp_server_settings smtp_set;
	const char *ident;
	struct client *client;

	/* always use nonblocking I/O */
	net_set_nonblock(fd_in, TRUE);
	net_set_nonblock(fd_out, TRUE);

	client = i_new(struct client, 1);
	client->user = user;
	client->service_user = service_user;
	client->set = set;
	client->session_id = i_strdup(session_id);

	i_zero(&smtp_set);
	smtp_set.hostname = set->hostname;
	smtp_set.login_greeting = set->login_greeting;
	smtp_set.max_recipients = set->submission_max_recipients;
	smtp_set.max_client_idle_time_msecs = CLIENT_IDLE_TIMEOUT_MSECS;
	smtp_set.max_message_size = set->submission_max_mail_size;
	smtp_set.rawlog_dir = set->rawlog_dir;
	smtp_set.debug = user->mail_debug;

	if ((workarounds & WORKAROUND_WHITESPACE_BEFORE_PATH) != 0) {
		smtp_set.workarounds |=
			SMTP_SERVER_WORKAROUND_WHITESPACE_BEFORE_PATH;
	}
	if ((workarounds & WORKAROUND_MAILBOX_FOR_PATH) != 0) {
		smtp_set.workarounds |=
			SMTP_SERVER_WORKAROUND_MAILBOX_FOR_PATH;
	}

	client->conn = smtp_server_connection_create(smtp_server,
		fd_in, fd_out, user->conn.remote_ip, user->conn.remote_port,
		FALSE, &smtp_set, &smtp_callbacks, client);

	client_proxy_create(client, set);

	smtp_server_connection_login(client->conn,
		client->user->username, helo,
		pdata, pdata_len, user->conn.ssl_secured);
	smtp_server_connection_start_pending(client->conn);

	mail_set = mail_user_set_get_storage_set(user);
	if (*set->imap_urlauth_host != '\0' &&
	    *mail_set->mail_attribute_dict != '\0') {
		/* Enable BURL capability only when urlauth dict is
		   configured correctly */
		client_init_urlauth(client);
	}

	submission_client_count++;
	DLLIST_PREPEND(&submission_clients, client);

	ident = mail_user_get_anvil_userip_ident(client->user);
	if (ident != NULL) {
		master_service_anvil_send(master_service, t_strconcat(
			"CONNECT\t", my_pid, "\tsubmission/",
			ident, "\n", NULL));
		client->anvil_sent = TRUE;
	}

	if (hook_client_created != NULL)
		hook_client_created(&client);

	submission_refresh_proctitle();
	return client;
}

static void client_state_reset(struct client *client)
{
	i_stream_unref(&client->state.data_input);

	i_zero(&client->state);
}

void client_destroy(struct client *client, const char *prefix,
		    const char *reason)
{
	if (client->destroyed)
		return;
	client->destroyed = TRUE;

	client_disconnect(client, prefix, reason);

	submission_client_count--;
	DLLIST_REMOVE(&submission_clients, client);

	if (client->proxy_conn != NULL)
		smtp_client_connection_close(&client->proxy_conn);

	if (client->anvil_sent) {
		master_service_anvil_send(master_service, t_strconcat(
			"DISCONNECT\t", my_pid, "\tsubmission/",
			mail_user_get_anvil_userip_ident(client->user),
			"\n", NULL));
	}

	if (client->urlauth_ctx != NULL)
		imap_urlauth_deinit(&client->urlauth_ctx);

	mail_user_unref(&client->user);
	mail_storage_service_user_unref(&client->service_user);

	client_state_reset(client);

	i_free(client->session_id);
	i_free(client);

	master_service_client_connection_destroyed(master_service);
	submission_refresh_proctitle();
}

static void
client_connection_trans_free(void *context,
			     struct smtp_server_transaction *trans ATTR_UNUSED)
{
	struct client *client = context;

	client_state_reset(client);
}

static void
client_connection_state_changed(void *context ATTR_UNUSED,
				enum smtp_server_state newstate ATTR_UNUSED)
{
	if (submission_client_count == 1)
		submission_refresh_proctitle();
}

static void client_connection_disconnect(void *context, const char *reason)
{
	struct client *client = context;
	struct smtp_server_connection *conn = client->conn;
	const struct smtp_server_stats *stats;

	if (conn != NULL) {
		stats = smtp_server_connection_get_stats(conn);
		client->stats = *stats;
		client->last_state = smtp_server_connection_get_state(conn);
	}
	client_disconnect(client, NULL, reason);
}

static void client_connection_destroy(void *context)
{
	struct client *client = context;

	client_destroy(client, NULL, NULL);
}

const char *client_state_get_name(struct client *client)
{
	enum smtp_server_state state;

	if (client->conn == NULL)
		state = client->last_state;
	else
		state = smtp_server_connection_get_state(client->conn);
	return smtp_server_state_names[state];
}

static const char *client_stats(struct client *client)
{
	const char *trans_id = (client->conn == NULL ? "" :
		smtp_server_connection_get_transaction_id(client->conn));
	const struct var_expand_table logout_tab[] = {
		{ 'i', dec2str(client->stats.input), "input" },
		{ 'o', dec2str(client->stats.output), "output" },
		{ '\0', dec2str(client->stats.command_count), "command_count" },
		{ '\0', dec2str(client->stats.reply_count), "reply_count" },
		{ '\0', client->session_id, "session" },
		{ '\0', trans_id, "transaction_id" },
		{ '\0', NULL, NULL }
	};
	const struct var_expand_table *user_tab =
		mail_user_var_expand_table(client->user);
	const struct var_expand_table *tab =
		t_var_expand_merge_tables(logout_tab, user_tab);
	string_t *str;
	const char *error;

	str = t_str_new(128);
	if (var_expand_with_funcs(str, client->set->submission_logout_format,
				  tab, mail_user_var_expand_func_table,
				  client->user, &error) < 0) {
		i_error("Failed to expand submission_logout_format=%s: %s",
			client->set->submission_logout_format, error);
	}
	return str_c(str);
}

void client_disconnect(struct client *client, const char *enh_code,
		       const char *reason)
{
	struct smtp_server_connection *conn;

	if (client->disconnected)
		return;
	client->disconnected = TRUE;

	timeout_remove(&client->to_quit);
	if (client->proxy_conn != NULL)
		smtp_client_connection_close(&client->proxy_conn);

	if (client->conn != NULL) {
		const struct smtp_server_stats *stats =
			smtp_server_connection_get_stats(client->conn);
		client->stats = *stats;
	}

	if (reason == NULL)
		reason = "Connection closed";
	i_info("Disconnect from %s: %s %s (state=%s)",
	       client_remote_id(client),
	       reason, client_stats(client),
	       client_state_get_name(client));

	conn = client->conn;
	client->conn = NULL;
	if (conn != NULL) {
		client->last_state = smtp_server_connection_get_state(conn);
		smtp_server_connection_terminate(&conn,
			(enh_code == NULL ? "4.0.0" : enh_code), reason);
	}
}

uoff_t client_get_max_mail_size(struct client *client)
{
	uoff_t max_size;

	/* Account for the backend server's SIZE limit and calculate our own
	   relative to it. */
	max_size = smtp_client_connection_get_size_capability(client->proxy_conn);
	if (max_size == 0 || max_size <= SUBMISSION_MAX_ADDITIONAL_MAIL_SIZE) {
		max_size = client->set->submission_max_mail_size;
	} else {
		max_size = max_size - SUBMISSION_MAX_ADDITIONAL_MAIL_SIZE;
		if (client->set->submission_max_mail_size > 0 &&
			max_size > client->set->submission_max_mail_size)
			max_size = client->set->submission_max_mail_size;
	}

	return max_size;
}

void clients_destroy_all(void)
{
	while (submission_clients != NULL) {
		client_destroy(submission_clients,
			"4.3.2", "Shutting down");
	}
}

static const struct smtp_server_callbacks smtp_callbacks = {
	.conn_cmd_helo = cmd_helo,

	.conn_cmd_mail = cmd_mail,
	.conn_cmd_rcpt = cmd_rcpt,
	.conn_cmd_rset = cmd_rset,

	.conn_cmd_data_begin = cmd_data_begin,
	.conn_cmd_data_continue = cmd_data_continue,

	.conn_cmd_vrfy = cmd_vrfy,

	.conn_cmd_noop = cmd_noop,
	.conn_cmd_quit = cmd_quit,

	.conn_cmd_input_pre = client_input_pre,
	.conn_cmd_input_post = client_input_post,

	.conn_trans_free = client_connection_trans_free,

	.conn_state_changed = client_connection_state_changed,

	.conn_disconnect = client_connection_disconnect,
	.conn_destroy = client_connection_destroy,
};
