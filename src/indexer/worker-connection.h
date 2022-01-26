#ifndef WORKER_CONNECTION_H
#define WORKER_CONNECTION_H

#include "indexer.h"

struct indexer_request;
struct connection_list;

typedef void worker_available_callback_t(void);

struct connection *
worker_connection_create(const char *socket_path,
			 indexer_status_callback_t *callback,
			 worker_available_callback_t *avail_callback,
			 struct connection_list *list);
void worker_connection_destroy(struct connection *conn);

struct connection_list *worker_connection_list_create(void);

/* Returns TRUE if worker is connected to (not necessarily handshaked yet) */
bool worker_connection_is_connected(struct connection *conn);

/* Returns the last process_limit returned by a worker connection handshake.
   If no handshakes have been received yet, returns 0. */
unsigned int worker_connections_get_process_limit(void);

/* Send a new indexing request for username+mailbox. The status callback is
   called as necessary. Requests can be queued, but only for the same
   username. */
void worker_connection_request(struct connection *conn,
			       struct indexer_request *request);
/* Returns username of the currently pending requests,
   or NULL if there are none. */
const char *worker_connection_get_username(struct connection *conn);

#endif
