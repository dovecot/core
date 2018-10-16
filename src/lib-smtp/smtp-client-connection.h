#ifndef SMTP_CLIENT_CONNECTION_H
#define SMTP_CLIENT_CONNECTION_H

#include "net.h"
#include "smtp-common.h"

#include "smtp-client-command.h"

enum smtp_capability;

struct smtp_reply;
struct smtp_client;
struct smtp_client_settings;
struct smtp_client_command;

enum smtp_client_connection_ssl_mode {
	SMTP_CLIENT_SSL_MODE_NONE = 0,
	SMTP_CLIENT_SSL_MODE_IMMEDIATE,
	SMTP_CLIENT_SSL_MODE_STARTTLS
};

enum smtp_client_connection_state {
	/* No connection */
	SMTP_CLIENT_CONNECTION_STATE_DISCONNECTED = 0,
	/* Trying to connect */
	SMTP_CLIENT_CONNECTION_STATE_CONNECTING,
	/* Connected, performing handshake */
	SMTP_CLIENT_CONNECTION_STATE_HANDSHAKING,
	/* Handshake ready, trying to authenticate */
	SMTP_CLIENT_CONNECTION_STATE_AUTHENTICATING,
	/* Authenticated, ready to accept commands */
	SMTP_CLIENT_CONNECTION_STATE_READY,
	/* Involved in active transaction */
	SMTP_CLIENT_CONNECTION_STATE_TRANSACTION
};
extern const char *const smtp_client_connection_state_names[];

struct smtp_client_connection *
smtp_client_connection_create(struct smtp_client *client,
	enum smtp_protocol protocol, const char *host, in_port_t port,
	enum smtp_client_connection_ssl_mode ssl_mode,
	const struct smtp_client_settings *set)
	ATTR_NULL(6);
struct smtp_client_connection *
smtp_client_connection_create_ip(struct smtp_client *client,
	enum smtp_protocol protocol, const struct ip_addr *ip, in_port_t port,
	const char *hostname, enum smtp_client_connection_ssl_mode ssl_mode,
	const struct smtp_client_settings *set)
	ATTR_NULL(5,7);
struct smtp_client_connection *
smtp_client_connection_create_unix(struct smtp_client *client,
				   enum smtp_protocol protocol,
				   const char *path,
				   const struct smtp_client_settings *set)
	ATTR_NULL(4);

void smtp_client_connection_ref(struct smtp_client_connection *conn);
void smtp_client_connection_unref(struct smtp_client_connection **_conn);
void smtp_client_connection_close(struct smtp_client_connection **_conn);

void smtp_client_connection_cork(struct smtp_client_connection *conn);
void smtp_client_connection_uncork(struct smtp_client_connection *conn);

void smtp_client_connection_connect(struct smtp_client_connection *conn,
	smtp_client_command_callback_t login_callback, void *login_context);
void smtp_client_connection_disconnect(struct smtp_client_connection *conn);
bool smtp_client_connection_send_xclient(struct smtp_client_connection *conn,
					 struct smtp_proxy_data *xclient);

void smtp_client_connection_switch_ioloop(struct smtp_client_connection *conn);

enum smtp_capability
smtp_client_connection_get_capabilities(struct smtp_client_connection *conn);
uoff_t smtp_client_connection_get_size_capability(
	struct smtp_client_connection *conn);
void smtp_client_connection_accept_extra_capability(
	struct smtp_client_connection *conn, const char *cap_name);
const struct smtp_capability_extra *
smtp_client_connection_get_extra_capability(struct smtp_client_connection *conn,
					    const char *name);

enum smtp_client_connection_state
smtp_client_connection_get_state(struct smtp_client_connection *conn);

#endif
