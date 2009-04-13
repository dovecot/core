#ifndef __CONFIG_CONNECTION_H
#define __CONFIG_CONNECTION_H

enum config_dump_flags {
	CONFIG_DUMP_FLAG_HUMAN		= 0x01,
	CONFIG_DUMP_FLAG_DEFAULTS	= 0x02
};

struct config_connection *config_connection_create(int fd);
void config_connection_destroy(struct config_connection *conn);

void config_connection_dump_request(int fd, const char *service,
				    enum config_dump_flags flags);
void config_connection_putenv(void);

#endif
