#ifndef CONFIG_CONNECTION_H
#define CONFIG_CONNECTION_H

enum config_dump_flags;

struct config_connection *config_connection_create(int fd);
void config_connection_destroy(struct config_connection *conn);

void config_connection_dump_request(int fd, const char *service,
				    enum config_dump_flags flags);

void config_connections_destroy_all(void);

#endif
