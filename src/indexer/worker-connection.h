#ifndef WORKER_CONNECTION_H
#define WORKER_CONNECTION_H

#include "indexer.h"

struct indexer_request;
struct worker_connection;

typedef void worker_available_callback_t(void);

/* Try to create a new worker connection and send a new indexing request for
   the given username+mailbox. The status callback is called as necessary.
   Returns 1 if successful, 0 if indexer-worker service's process_limit was
   already reached, -1 on connect error. */
int worker_connection_try_create(const char *socket_path,
				 struct indexer_request *request,
				 indexer_status_callback_t *callback,
				 worker_available_callback_t *avail_callback);

unsigned int worker_connections_get_count(void);
struct worker_connection *worker_connections_find_user(const char *username);

void worker_connections_init(void);
void worker_connections_deinit(void);

#endif
