#ifndef LOGIN_CONNECTION_H
#define LOGIN_CONNECTION_H

struct director;

enum login_connection_type {
	LOGIN_CONNECTION_TYPE_AUTH,
	LOGIN_CONNECTION_TYPE_USERDB,
	LOGIN_CONNECTION_TYPE_AUTHREPLY
};

struct login_connection *
login_connection_init(struct director *dir, int fd,
		      struct auth_connection *auth,
		      enum login_connection_type type);
void login_connection_deinit(struct login_connection **conn);

void login_connections_deinit(void);

#endif
