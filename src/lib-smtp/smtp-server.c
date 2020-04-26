/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "str.h"
#include "hash.h"
#include "hostpid.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "connection.h"
#include "dns-lookup.h"
#include "iostream-rawlog.h"
#include "iostream-ssl.h"

#include "smtp-server-private.h"

static struct event_category event_category_smtp_server = {
	.name = "smtp-server"
};

/*
 * Server
 */

struct smtp_server *smtp_server_init(const struct smtp_server_settings *set)
{
	struct smtp_server *server;
	pool_t pool;

	pool = pool_alloconly_create("smtp server", 1024);
	server = p_new(pool, struct smtp_server, 1);
	server->pool = pool;
	server->set.protocol = set->protocol;
	server->set.rawlog_dir = p_strdup_empty(pool, set->rawlog_dir);

	if (set->ssl != NULL) {
		server->set.ssl =
			ssl_iostream_settings_dup(server->pool, set->ssl);
	}

	if (set->hostname != NULL && *set->hostname != '\0')
		server->set.hostname = p_strdup(pool, set->hostname);
	else
		server->set.hostname = p_strdup(pool, my_hostdomain());
	if (set->login_greeting != NULL && *set->login_greeting != '\0')
		server->set.login_greeting = p_strdup(pool, set->login_greeting);
	else
		server->set.login_greeting = PACKAGE_NAME" ready.";
	if (set->capabilities == 0) {
		server->set.capabilities = SMTP_SERVER_DEFAULT_CAPABILITIES;
	} else  {
		server->set.capabilities = set->capabilities;
	}
	server->set.workarounds = set->workarounds;
	server->set.max_client_idle_time_msecs = set->max_client_idle_time_msecs;
	server->set.max_pipelined_commands = (set->max_pipelined_commands > 0 ?
		set->max_pipelined_commands : 1);
	server->set.max_bad_commands = (set->max_bad_commands > 0 ?
		set->max_bad_commands : SMTP_SERVER_DEFAULT_MAX_BAD_COMMANDS);
	server->set.max_recipients = set->max_recipients;
	server->set.command_limits = set->command_limits;
	server->set.max_message_size = set->max_message_size;

	if (set->mail_param_extensions != NULL) {
		server->set.mail_param_extensions =
			p_strarray_dup(pool, set->mail_param_extensions);
	}
	if (set->rcpt_param_extensions != NULL) {
		server->set.rcpt_param_extensions =
			p_strarray_dup(pool, set->rcpt_param_extensions);
	}
	if (set->xclient_extensions != NULL) {
		server->set.xclient_extensions =
			p_strarray_dup(pool, set->xclient_extensions);
	}

	server->set.socket_send_buffer_size = set->socket_send_buffer_size;
	server->set.socket_recv_buffer_size = set->socket_recv_buffer_size;

	server->set.tls_required = set->tls_required;
	server->set.auth_optional = set->auth_optional;
	server->set.rcpt_domain_optional = set->rcpt_domain_optional;
	server->set.mail_path_allow_broken = set->mail_path_allow_broken;
	server->set.debug = set->debug;

	/* There is no event log prefix added here, since the server itself does
	   not log anything. */
	server->event = event_create(set->event_parent);
	smtp_server_event_init(server, server->event);
	event_set_forced_debug(server->event, set->debug);

	server->conn_list = smtp_server_connection_list_init();
	smtp_server_commands_init(server);
	return server;
}

void smtp_server_event_init(struct smtp_server *server, struct event *event)
{
	event_add_category(event, &event_category_smtp_server);
	event_add_str(event, "protocol",
		      smtp_protocol_name(server->set.protocol));
}

void smtp_server_deinit(struct smtp_server **_server)
{
	struct smtp_server *server = *_server;

	connection_list_deinit(&server->conn_list);

	if (server->ssl_ctx != NULL)
		ssl_iostream_context_unref(&server->ssl_ctx);
	event_unref(&server->event);
	pool_unref(&server->pool);
	*_server = NULL;
}

void smtp_server_switch_ioloop(struct smtp_server *server)
{
	struct connection *_conn = server->conn_list->connections;

	/* move connections */
	/* FIXME: we wouldn't necessarily need to switch all of them
	   immediately, only those that have commands now. but also connections
	   that get new commands before ioloop is switched again.. */
	for (; _conn != NULL; _conn = _conn->next) {
		struct smtp_server_connection *conn =
			(struct smtp_server_connection *)_conn;

		smtp_server_connection_switch_ioloop(conn);
	}
}

int smtp_server_init_ssl_ctx(struct smtp_server *server, const char **error_r)
{
	const char *error;

	if (server->ssl_ctx != NULL || server->set.ssl == NULL)
		return 0;

	if (ssl_iostream_server_context_cache_get(server->set.ssl,
		&server->ssl_ctx, &error) < 0) {
		*error_r = t_strdup_printf("Couldn't initialize SSL context: %s",
					   error);
		return -1;
	}
	return 0;
}
