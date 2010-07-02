#ifndef LOGIN_CONNECTION_H
#define LOGIN_CONNECTION_H

struct director;

struct login_connection *
login_connection_init(struct director *dir, int fd,
		      struct auth_connection *auth, bool userdb);
void login_connection_deinit(struct login_connection **conn);

void login_connections_deinit(void);

#endif
