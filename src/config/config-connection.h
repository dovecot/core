#ifndef __CONFIG_CONNECTION_H
#define __CONFIG_CONNECTION_H

struct config_connection *config_connection_create(int fd);
void config_connection_destroy(struct config_connection *conn);

void config_connection_dump_request(int fd, const char *service);
void config_connection_putenv(void);

#endif
