#ifndef ANVIL_CONNECTION_H
#define ANVIL_CONNECTION_H

struct anvil_connection *
anvil_connection_create(int fd, bool master, bool fifo);
void anvil_connection_destroy(struct anvil_connection *conn);

void anvil_connections_destroy_all(void);

#endif
