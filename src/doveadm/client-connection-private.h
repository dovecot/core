#ifndef CLIENT_CONNECTION_PRIVATE_H
#define CLIENT_CONNECTION_PRIVATE_H

#include "client-connection.h"

bool doveadm_client_is_allowed_command(const struct doveadm_settings *set,
	const char *cmd_name);

int client_connection_init(struct client_connection *conn,
	enum client_connection_type type, int fd);
void client_connection_deinit(struct client_connection *conn ATTR_UNUSED);

void client_connection_set_proctitle(struct client_connection *conn,
				     const char *text);

void client_connection_destroy_http(struct client_connection *conn);

void doveadm_http_server_init(void);
void doveadm_http_server_deinit(void);

#endif
