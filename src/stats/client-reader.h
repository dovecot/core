#ifndef CLIENT_READER_H
#define CLIENT_READER_H

struct stats_metrics;

void client_reader_create(int fd);

void client_readers_init(void);
void client_readers_deinit(void);

#endif
