#ifndef AUTH_CLIENT_H
#define AUTH_CLIENT_H

struct auth_master_connection;

/* Returns -1 = error, 0 = user not found, 1 = ok */
int auth_client_put_user_env(struct auth_master_connection *conn,
			     const char *user);

#endif
