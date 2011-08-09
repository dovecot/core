#ifndef INDEXER_CLIENT_H
#define INDEXER_CLIENT_H

struct indexer_queue;

struct indexer_client *
indexer_client_create(int fd, struct indexer_queue *queue);
void indexer_client_status_callback(int percentage, void *context);

unsigned int indexer_clients_get_count(void);
void indexer_clients_destroy_all(void);

#endif
