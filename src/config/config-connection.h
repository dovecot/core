#ifndef CONFIG_CONNECTION_H
#define CONFIG_CONNECTION_H

struct config_connection *config_connection_create(int fd);
void config_connection_destroy(struct config_connection *conn);

void config_connections_destroy_all(void);

#endif
