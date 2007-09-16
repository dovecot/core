#ifndef AUTH_CLIENT_H
#define AUTH_CLIENT_H

struct auth_connection *auth_connection_init(const char *auth_socket);
void auth_connection_deinit(struct auth_connection *conn);

/* Returns -1 = error, 0 = user not found, 1 = ok */
int auth_client_put_user_env(struct auth_connection *conn,
			     const char *user);

#endif
