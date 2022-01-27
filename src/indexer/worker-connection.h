#ifndef WORKER_CONNECTION_H
#define WORKER_CONNECTION_H

#include "indexer.h"

struct indexer_request;
struct connection;

typedef void worker_available_callback_t(void);

/* Try to create a new worker connection. Returns 1 if successful, 0 if
   indexer-worker service's process_limit was already reached, -1 on connect
   error. */
int worker_connection_try_create(const char *socket_path,
				 indexer_status_callback_t *callback,
				 worker_available_callback_t *avail_callback);

/* Send a new indexing request for username+mailbox. The status callback is
   called as necessary. Requests can be queued, but only for the same
   username. */
void worker_connection_request(struct connection *conn,
			       struct indexer_request *request);

unsigned int worker_connections_get_count(void);
struct connection *worker_connections_find_user(const char *username);

void worker_connections_init(void);
void worker_connections_deinit(void);

#endif
