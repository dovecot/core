#ifndef WORKER_POOL_H
#define WORKER_POOL_H

#include "indexer.h"
#include "worker-connection.h"

struct connection;

struct worker_pool *
worker_pool_init(const char *socket_path, indexer_status_callback_t *callback,
		 worker_available_callback_t *avail_callback);
void worker_pool_deinit(struct worker_pool **pool);

bool worker_pool_have_connections(struct worker_pool *pool);

bool worker_pool_get_connection(struct worker_pool *pool,
				struct connection **conn_r);

struct connection *
worker_pool_find_username_connection(struct worker_pool *pool,
				     const char *username);

#endif
