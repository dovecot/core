#ifndef __LOGIN_CONNECTION_H
#define __LOGIN_CONNECTION_H

typedef struct _LoginConnection LoginConnection;

LoginConnection *login_connection_create(int fd);
void login_connection_destroy(LoginConnection *conn);

void login_connections_init(void);
void login_connections_deinit(void);

#endif
