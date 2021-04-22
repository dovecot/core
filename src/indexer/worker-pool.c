/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "llist.h"
#include "master-service.h"
#include "worker-connection.h"
#include "worker-pool.h"

#define MAX_WORKER_IDLE_SECS (60*5)

struct worker_connection_list {
	struct worker_connection_list *prev, *next;

	struct worker_connection *conn;
	time_t last_use;
};

struct worker_pool {
	char *socket_path;
	indexer_status_callback_t *callback;

	unsigned int connection_count;
	struct worker_connection_list *busy_list;
};

static void
worker_connection_list_free(struct worker_pool *pool,
			    struct worker_connection_list *list);

struct worker_pool *
worker_pool_init(const char *socket_path, indexer_status_callback_t *callback)
{
	struct worker_pool *pool;

	pool = i_new(struct worker_pool, 1);
	pool->socket_path = i_strdup(socket_path);
	pool->callback = callback;
	return pool;
}

void worker_pool_deinit(struct worker_pool **_pool)
{
	struct worker_pool *pool = *_pool;

	*_pool = NULL;

	while (pool->busy_list != NULL) {
		struct worker_connection_list *list = pool->busy_list;

		DLLIST_REMOVE(&pool->busy_list, list);
		worker_connection_list_free(pool, list);
	}

	i_free(pool->socket_path);
	i_free(pool);
}

bool worker_pool_have_busy_connections(struct worker_pool *pool)
{
	return pool->busy_list != NULL;
}

static int worker_pool_add_connection(struct worker_pool *pool,
				      struct worker_connection **conn_r)
{
	struct worker_connection *conn;

	pool->connection_count++;
	conn = worker_connection_create(pool->socket_path, pool->callback);
	if (worker_connection_connect(conn) < 0) {
		worker_connection_destroy(&conn);
		return -1;
	}

	*conn_r = conn;
	return 0;
}

static void
worker_connection_list_free(struct worker_pool *pool,
			    struct worker_connection_list *list)
{
	i_assert(pool->connection_count > 0);
	pool->connection_count--;

	worker_connection_destroy(&list->conn);
	i_free(list);
}

static unsigned int worker_pool_find_max_connections(struct worker_pool *pool)
{
	struct worker_connection_list *list;
	unsigned int limit;

	if (pool->busy_list == NULL)
		return 1;

	for (list = pool->busy_list; list != NULL; list = list->next) {
		if (worker_connection_get_process_limit(list->conn, &limit))
			return limit;
	}
	/* we have at least one connection that has already been created,
	   but without having handshaked yet. wait until it's finished. */
	return 0;
}

bool worker_pool_get_connection(struct worker_pool *pool,
				struct worker_connection **conn_r)
{
	struct worker_connection_list *list;
	unsigned int max_connections;

	max_connections = worker_pool_find_max_connections(pool);
	if (pool->connection_count >= max_connections)
		return FALSE;
	if (worker_pool_add_connection(pool, conn_r) < 0)
		return FALSE;
	list = i_new(struct worker_connection_list, 1);
	list->conn = *conn_r;
	list->last_use = ioloop_time;
	DLLIST_PREPEND(&pool->busy_list, list);

	return TRUE;
}

void worker_pool_release_connection(struct worker_pool *pool,
				    struct worker_connection *conn)
{
	struct worker_connection_list *list;

	pool->connection_count--;
	for (list = pool->busy_list; list != NULL; list = list->next) {
		if (list->conn == conn)
			break;
	}
	i_assert(list != NULL);

	DLLIST_REMOVE(&pool->busy_list, list);

	worker_connection_destroy(&conn);
}

struct worker_connection *
worker_pool_find_username_connection(struct worker_pool *pool,
				     const char *username)
{
	struct worker_connection_list *list;
	const char *worker_user;

	for (list = pool->busy_list; list != NULL; list = list->next) {
		worker_user = worker_connection_get_username(list->conn);
		if (worker_user != NULL && strcmp(worker_user, username) == 0)
			return list->conn;
	}
	return NULL;
}
