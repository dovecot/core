/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "llist.h"
#include "connection.h"
#include "master-service.h"
#include "worker-connection.h"
#include "worker-pool.h"

#define MAX_WORKER_IDLE_SECS (60*5)

struct worker_pool {
	char *socket_path;
	indexer_status_callback_t *callback;

	struct connection_list *connection_list;
};

struct worker_pool *
worker_pool_init(const char *socket_path, indexer_status_callback_t *callback)
{
	struct worker_pool *pool;

	pool = i_new(struct worker_pool, 1);
	pool->socket_path = i_strdup(socket_path);
	pool->callback = callback;
	pool->connection_list = worker_connection_list_create();
	return pool;
}

void worker_pool_deinit(struct worker_pool **_pool)
{
	struct worker_pool *pool = *_pool;

	*_pool = NULL;

	connection_list_deinit(&pool->connection_list);

	i_free(pool->connection_list);
	i_free(pool->socket_path);
	i_free(pool);
}

bool worker_pool_have_busy_connections(struct worker_pool *pool)
{
	return pool->connection_list->connections_count > 0;
}

static int worker_pool_add_connection(struct worker_pool *pool,
				      struct connection **conn_r)
{
	struct connection *conn;

	conn = worker_connection_create(pool->socket_path, pool->callback,
					pool->connection_list);
	if (connection_client_connect(conn) < 0) {
		worker_connection_unref(&conn);
		return -1;
	}

	*conn_r = conn;
	return 0;
}

static unsigned int worker_pool_find_max_connections(struct worker_pool *pool)
{
	struct connection *list;
	unsigned int limit;

	if (pool->connection_list->connections == NULL)
		return 1;

	for (list = pool->connection_list->connections; list != NULL; list = list->next) {
		if (worker_connection_get_process_limit(list, &limit))
			return limit;
	}
	/* we have at least one connection that has already been created,
	   but without having handshaked yet. wait until it's finished. */
	return 0;
}

bool worker_pool_get_connection(struct worker_pool *pool,
				struct connection **conn_r)
{
	unsigned int max_connections;

	max_connections = worker_pool_find_max_connections(pool);
	if (pool->connection_list->connections_count >= max_connections)
		return FALSE;
	if (worker_pool_add_connection(pool, conn_r) < 0)
		return FALSE;

	return TRUE;
}

void worker_pool_release_connection(struct worker_pool *pool ATTR_UNUSED,
				    struct connection *conn)
{
	worker_connection_unref(&conn);
}

struct connection *
worker_pool_find_username_connection(struct worker_pool *pool,
				     const char *username)
{
	struct connection *list;
	const char *worker_user;

	for (list = pool->connection_list->connections; list != NULL; list = list->next) {
		worker_user = worker_connection_get_username(list);
		if (worker_user != NULL && strcmp(worker_user, username) == 0)
			return list;
	}
	return NULL;
}
