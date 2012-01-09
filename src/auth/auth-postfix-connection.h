#ifndef AUTH_POSTFIX_CONNECTION_H
#define AUTH_POSTFIX_CONNECTION_H

struct auth_postfix_connection *
auth_postfix_connection_create(struct auth *auth, int fd);

void auth_postfix_connections_destroy_all(void);

#endif

