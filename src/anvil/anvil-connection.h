#ifndef ANVIL_CONNECTION_H
#define ANVIL_CONNECTION_H

void anvil_connection_create(int fd, bool master, bool fifo);

/* Find an existing anvil connection from the specified process. */
struct anvil_connection *anvil_connection_find(const char *service, pid_t pid);

void anvil_connections_init(void);
void anvil_connections_deinit(void);

#endif
