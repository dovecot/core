#ifndef WORKER_POOL_H
#define WORKER_POOL_H

#include "indexer.h"

struct worker_connection;

struct worker_pool *
worker_pool_init(const char *socket_path, indexer_status_callback_t *callback);
void worker_pool_deinit(struct worker_pool **pool);

bool worker_pool_have_busy_connections(struct worker_pool *pool);

bool worker_pool_get_connection(struct worker_pool *pool,
				struct worker_connection **conn_r);
void worker_pool_release_connection(struct worker_pool *pool,
				    struct worker_connection *conn);

struct worker_connection *
worker_pool_find_username_connection(struct worker_pool *pool,
				     const char *username);

#endif
