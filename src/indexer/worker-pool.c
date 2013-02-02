/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

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
	struct worker_connection_list *busy_list, *idle_list;
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
		master_service_client_connection_destroyed(master_service);
		worker_connection_list_free(pool, list);
	}

	while (pool->idle_list != NULL) {
		struct worker_connection_list *list = pool->idle_list;

		DLLIST_REMOVE(&pool->idle_list, list);
		worker_connection_list_free(pool, list);
	}

	i_free(pool->socket_path);
	i_free(pool);
}

bool worker_pool_have_busy_connections(struct worker_pool *pool)
{
	return pool->busy_list != NULL;
}

static int worker_pool_add_connection(struct worker_pool *pool)
{
	struct worker_connection *conn;
	struct worker_connection_list *list;

	conn = worker_connection_create(pool->socket_path, pool->callback);
	if (worker_connection_connect(conn) < 0) {
		worker_connection_destroy(&conn);
		return -1;
	}

	i_assert(pool->idle_list == NULL);

	list = i_new(struct worker_connection_list, 1);
	list->conn = conn;
	list->last_use = ioloop_time;
	pool->idle_list = list;
	pool->connection_count++;
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

	i_assert(pool->idle_list == NULL);

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

	while (pool->idle_list != NULL &&
	       !worker_connection_is_connected(pool->idle_list->conn)) {
		list = pool->idle_list;
		DLLIST_REMOVE(&pool->idle_list, list);
		worker_connection_list_free(pool, list);
	}

	if (pool->idle_list == NULL) {
		max_connections = worker_pool_find_max_connections(pool);
		if (pool->connection_count >= max_connections)
			return FALSE;
		if (worker_pool_add_connection(pool) < 0)
			return FALSE;
		i_assert(pool->idle_list != NULL);
	}
	list = pool->idle_list;
	DLLIST_REMOVE(&pool->idle_list, list);
	DLLIST_PREPEND(&pool->busy_list, list);
	/* treat worker connection as another client. this is required (once,
	   at least) so that master doesn't think we are busy doing nothing and
	   ignoring an idle-kill. */
	master_service_client_connection_created(master_service);

	*conn_r = list->conn;
	return TRUE;
}

static void worker_pool_kill_idle_connections(struct worker_pool *pool)
{
	struct worker_connection_list *list, *next;
	time_t kill_timestamp;

	kill_timestamp = ioloop_time - MAX_WORKER_IDLE_SECS;
	for (list = pool->idle_list; list != NULL; list = next) {
		next = list->next;
		if (list->last_use < kill_timestamp) {
			DLLIST_REMOVE(&pool->idle_list, list);
			worker_connection_list_free(pool, list);
		}
	}
}

void worker_pool_release_connection(struct worker_pool *pool,
				    struct worker_connection *conn)
{
	struct worker_connection_list *list;

	if (worker_connection_is_busy(conn)) {
		/* not finished with all queued requests yet */
		return;
	}

	for (list = pool->busy_list; list != NULL; list = list->next) {
		if (list->conn == conn)
			break;
	}
	i_assert(list != NULL);

	DLLIST_REMOVE(&pool->busy_list, list);
	master_service_client_connection_destroyed(master_service);

	if (!worker_connection_is_connected(conn))
		worker_connection_list_free(pool, list);
	else {
		DLLIST_PREPEND(&pool->idle_list, list);
		list->last_use = ioloop_time;

		worker_pool_kill_idle_connections(pool);
	}
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
