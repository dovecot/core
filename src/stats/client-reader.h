#ifndef CLIENT_READER_H
#define CLIENT_READER_H

struct stats_metrics;

void client_reader_create(int fd, struct stats_metrics *metrics);

void client_readers_init(void);
void client_readers_deinit(void);

#endif
