/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "ldap-private.h"
#include "ldap-connection-pool.h"

struct ldap_connection_pool {
	struct ldap_connection_list *conn_list;
	unsigned int conn_count;

	unsigned int max_connections;
};

static void ldap_connection_list_remove(struct ldap_connection_pool *pool,
					struct ldap_connection_list *list)
{
	DLLIST_REMOVE(&pool->conn_list, list);
	pool->conn_count--;

	ldap_connection_deinit(&list->conn);
	i_free(list);
}

static void
ldap_connection_pool_shrink_to(struct ldap_connection_pool *pool,
			       unsigned int max_count)
{
	struct ldap_connection_list *list, *next;

	list = pool->conn_list;
	for (; list != NULL && pool->conn_count > max_count; list = next) {
		next = list->next;
		if (list->refcount == 0)
			ldap_connection_list_remove(pool, list);
	}
}

struct ldap_connection_pool *
ldap_connection_pool_init(unsigned int max_connections)
{
	struct ldap_connection_pool *pool;

	pool = i_new(struct ldap_connection_pool, 1);
	pool->max_connections = max_connections;
	return pool;
}

void ldap_connection_pool_deinit(struct ldap_connection_pool **_pool)
{
	struct ldap_connection_pool *pool = *_pool;

	*_pool = NULL;

	ldap_connection_pool_shrink_to(pool, 0);
	i_assert(pool->conn_list == NULL);
	i_free(pool);
}

int ldap_connection_pool_get(struct ldap_connection_pool *pool,
			     struct ldap_client *client,
			     const struct ldap_client_settings *set,
			     struct ldap_connection_list **list_r,
			     const char **error_r)
{
	struct ldap_connection_list *list;
	struct ldap_connection *conn;

	for (list = pool->conn_list; list != NULL; list = list->next) {
		if (ldap_connection_have_settings(list->conn, set)) {
			list->refcount++;
			*list_r = list;
			return 0;
		}
	}
	if (ldap_connection_init(client, set, &conn, error_r) < 0)
		return -1;

	list = i_new(struct ldap_connection_list, 1);
	list->conn = conn;
	list->refcount++;

	DLLIST_PREPEND(&pool->conn_list, list);
	pool->conn_count++;

	ldap_connection_pool_shrink_to(pool, pool->max_connections);
	*list_r = list;
	return 0;
}

void ldap_connection_pool_unref(struct ldap_connection_pool *pool,
				struct ldap_connection_list **_list)
{
	struct ldap_connection_list *list = *_list;

	*_list = NULL;

	i_assert(list->refcount > 0);

	if (--list->refcount == 0)
		ldap_connection_pool_shrink_to(pool, pool->max_connections);
}

bool ldap_connection_pool_have_references(struct ldap_connection_pool *pool)
{
	struct ldap_connection_list *list;

	for (list = pool->conn_list; list != NULL; list = list->next) {
		if (list->refcount > 0)
			return TRUE;
	}
	return FALSE;
}
