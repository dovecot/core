#ifndef INDEXER_CLIENT_H
#define INDEXER_CLIENT_H

struct indexer_status;
struct indexer_queue;

void indexer_client_create(struct master_service_connection *conn,
			   struct indexer_queue *queue);
void indexer_client_status_callback(const struct indexer_status *status,
				    void *context);

unsigned int indexer_clients_get_count(void);
void indexer_clients_destroy_all(void);

#endif
