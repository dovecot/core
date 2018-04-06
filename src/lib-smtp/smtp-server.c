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

	if (set->xclient_extensions != NULL) {
		server->set.xclient_extensions =
			p_strarray_dup(pool, set->xclient_extensions);
	}

	server->set.socket_send_buffer_size = set->socket_send_buffer_size;
	server->set.socket_recv_buffer_size = set->socket_recv_buffer_size;

	server->set.tls_required = set->tls_required;
	server->set.auth_optional = set->auth_optional;
	server->set.rcpt_domain_optional = set->rcpt_domain_optional;
	server->set.param_extensions = set->param_extensions;
	server->set.debug = set->debug;

	server->conn_list = smtp_server_connection_list_init();
	smtp_server_commands_init(server);
	return server;
}

void smtp_server_deinit(struct smtp_server **_server)
{
	struct smtp_server *server = *_server;

	connection_list_deinit(&server->conn_list);

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
