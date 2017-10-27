#ifndef CLIENT_CONNECTION_PRIVATE_H
#define CLIENT_CONNECTION_PRIVATE_H

#include "client-connection.h"

bool doveadm_client_is_allowed_command(const struct doveadm_settings *set,
	const char *cmd_name);

int client_connection_init(struct client_connection *conn,
	enum doveadm_client_connection_type type, pool_t pool, int fd);
void client_connection_destroy(struct client_connection **_conn);

void client_connection_set_proctitle(struct client_connection *conn,
				     const char *text);

void doveadm_http_server_init(void);
void doveadm_http_server_deinit(void);

void doveadm_server_init(void);
void doveadm_server_deinit(void);

#endif
