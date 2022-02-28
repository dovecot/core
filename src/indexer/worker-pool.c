/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "llist.h"
#include "connection.h"
#include "master-service.h"
#include "worker-connection.h"
#include "worker-pool.h"

struct worker_pool {
	char *socket_path;
	indexer_status_callback_t *callback;
	worker_available_callback_t *avail_callback;

	struct connection_list *connection_list;
};

struct worker_pool *
worker_pool_init(const char *socket_path, indexer_status_callback_t *callback,
		 worker_available_callback_t *avail_callback)
{
	struct worker_pool *pool;

	pool = i_new(struct worker_pool, 1);
	pool->socket_path = i_strdup(socket_path);
	pool->callback = callback;
	pool->avail_callback = avail_callback;
	pool->connection_list = worker_connection_list_create();
	return pool;
}

void worker_pool_deinit(struct worker_pool **_pool)
{
	struct worker_pool *pool = *_pool;

	*_pool = NULL;

	if (pool->connection_list != NULL)
		connection_list_deinit(&pool->connection_list);

	i_free(pool->connection_list);
	i_free(pool->socket_path);
	i_free(pool);
}

bool worker_pool_have_connections(struct worker_pool *pool)
{
	return worker_connections_get_count(pool->connection_list) > 0;
}

bool worker_pool_get_connection(struct worker_pool *pool,
				struct connection **conn_r)
{
	return worker_connection_try_create(pool->socket_path, pool->callback,
					    pool->avail_callback,
					    pool->connection_list, conn_r) > 0;
}

struct connection *
worker_pool_find_username_connection(struct worker_pool *pool,
				     const char *username)
{
	return worker_connections_find_user(pool->connection_list, username);
}
