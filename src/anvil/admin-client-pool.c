/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "admin-client-pool.h"

struct admin_client_cmd_context {
	struct admin_client_ref *client;
	admin_client_callback_t *callback;
	void *context;
};

struct admin_client_ref {
	int refcount;
	pid_t pid;
	struct admin_client *client;
	struct admin_client_pool *pool;
};

struct admin_client_pool {
	char *base_dir;
	unsigned int max_connections;
	unsigned int idle_connection_count;
	ARRAY(struct admin_client_ref *) clients;
};

struct admin_client_pool *
admin_client_pool_init(const char *base_dir, unsigned int max_connections)
{
	struct admin_client_pool *pool;

	pool = i_new(struct admin_client_pool, 1);
	pool->base_dir = i_strdup(base_dir);
	pool->max_connections = max_connections;
	i_array_init(&pool->clients, 8);
	return pool;

}

void admin_client_pool_deinit(struct admin_client_pool **_pool)
{
	struct admin_client_pool *pool = *_pool;
	struct admin_client_ref *client;

	array_foreach_elem(&pool->clients, client) {
		i_assert(client->refcount == 0);
		admin_client_unref(&client->client);
	}
	array_free(&pool->clients);
	i_free(pool->base_dir);
	i_free(pool);
}

static void admin_client_pool_cleanup(struct admin_client_pool *pool)
{
	struct admin_client_ref *const *clients;
	unsigned int i, count;

	/* see if we need to destroy the connection to keep it under the max
	   connections limit. */
	clients = array_get(&pool->clients, &count);
	for (i = count; i > 0; i--) {
		if (array_count(&pool->clients) <= pool->max_connections)
			break;
		if (pool->idle_connection_count == 0)
			break;
		if (clients[i-1]->refcount == 0) {
			admin_client_unref(&clients[i-1]->client);
			array_delete(&pool->clients, i-1, 1);
		}
	}
}

static struct admin_client_ref *
admin_client_pool_get(struct admin_client_pool *pool,
		      const char *service, pid_t pid)
{
	struct admin_client_ref *client;

	array_foreach_elem(&pool->clients, client) {
		if (client->pid == pid) {
			if (client->refcount++ == 0) {
				i_assert(pool->idle_connection_count > 0);
				pool->idle_connection_count--;
			}
			return client;
		}
	}

	client = i_new(struct admin_client_ref, 1);
	client->refcount = 1;
	client->pid = pid;
	client->client = admin_client_init(pool->base_dir, service, pid);
	client->pool = pool;
	array_push_back(&pool->clients, &client);
	admin_client_pool_cleanup(pool);
	return client;
}

static void
admin_client_pool_cmd_callback(const char *reply, const char *error,
			       struct admin_client_cmd_context *cmd_ctx)
{
	struct admin_client_ref *client = cmd_ctx->client;

	i_assert(client->refcount > 0);

	cmd_ctx->callback(reply, error, cmd_ctx->context);
	i_free(cmd_ctx);

	if (--client->refcount > 0)
		return;
	client->pool->idle_connection_count++;
	admin_client_pool_cleanup(client->pool);
}

void admin_client_pool_send_cmd(struct admin_client_pool *pool,
				const char *service, pid_t pid, const char *cmd,
				admin_client_callback_t *callback,
				void *context)
{
	struct admin_client_cmd_context *cmd_ctx;

	cmd_ctx = i_new(struct admin_client_cmd_context, 1);
	cmd_ctx->client = admin_client_pool_get(pool, service, pid);
	cmd_ctx->callback = callback;
	cmd_ctx->context = context;
	admin_client_send_cmd(cmd_ctx->client->client, cmd,
			      admin_client_pool_cmd_callback, cmd_ctx);
}
