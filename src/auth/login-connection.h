#ifndef __LOGIN_CONNECTION_H
#define __LOGIN_CONNECTION_H

struct login_connection *login_connection_create(int fd);
void login_connection_destroy(struct login_connection *conn);

void login_connections_init(void);
void login_connections_deinit(void);

#endif
