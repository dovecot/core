#ifndef ANVIL_CONNECTION_H
#define ANVIL_CONNECTION_H

void anvil_connection_create(int fd, bool master, bool fifo);

void anvil_connections_init(void);
void anvil_connections_deinit(void);

#endif
