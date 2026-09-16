#ifndef CLIENT_WRITER_H
#define CLIENT_WRITER_H

struct stats_metrics;

void client_writer_create(int fd);

void client_writer_update_connections(void);

/* Tell the writer clients to switch to the stats process that replaces us. */
void client_writers_send_reconnect(void);

void client_writers_init(void);
void client_writers_deinit(void);

#endif
