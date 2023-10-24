/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"

#include "sasl-server-private.h"

struct event_category event_category_sasl_server = {
	.name = "sasl-server"
};

/*
 * Instance
 */

struct sasl_server_instance *
sasl_server_instance_create(struct sasl_server *server,
			    const struct sasl_server_settings *set)
{
	struct sasl_server_instance *sinst;
	pool_t pool;

	pool = pool_alloconly_create(
		MEMPOOL_GROWING"sasl_server_instance", 2048);
	sinst = p_new(pool, struct sasl_server_instance, 1);
	sinst->pool = pool;
	sinst->refcount = 1;
	sinst->server = server;

	sinst->set = *set;
	if (set->realms != NULL)
		sinst->set.realms = p_strarray_dup(pool, set->realms);

	if (set->event_parent == NULL)
		sinst->event = event_create(server->event);
	else {
		sinst->event = event_create(set->event_parent);
		event_add_category(sinst->event, &event_category_sasl_server);
		event_set_append_log_prefix(sinst->event, "sasl: ");
	}

	DLLIST_PREPEND(&server->instances, sinst);

	return sinst;
}

void sasl_server_instance_ref(struct sasl_server_instance *sinst)
{
	i_assert(sinst->refcount > 0);
	sinst->refcount++;
}

void sasl_server_instance_unref(struct sasl_server_instance **_sinst)
{
	struct sasl_server_instance *sinst = *_sinst;

	if (sinst == NULL)
		return;
	*_sinst = NULL;

	i_assert(sinst->refcount > 0);
	if (--sinst->refcount > 0)
		return;

	struct sasl_server *server = sinst->server;

	i_assert(sinst->requests == 0);

	sasl_server_instance_mech_registry_free(sinst);

	DLLIST_REMOVE(&server->instances, sinst);

	event_unref(&sinst->event);
	pool_unref(&sinst->pool);
}

/*
 * Server
 */

struct sasl_server *
sasl_server_init(struct event *event_parent,
		 const struct sasl_server_request_funcs *funcs)
{
	struct sasl_server *server;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"sasl_server", 2048);
	server = p_new(pool, struct sasl_server, 1);
	server->pool = pool;

	server->funcs = funcs;

	server->event = event_create(event_parent);
	event_add_category(server->event, &event_category_sasl_server);
	event_set_append_log_prefix(server->event, "sasl: ");

	return server;
}

void sasl_server_deinit(struct sasl_server **_server)
{
	struct sasl_server *server = *_server;

	if (server == NULL)
		return;
	*_server = NULL;

	i_assert(server->instances == NULL);
	i_assert(server->requests == 0);

	event_unref(&server->event);
	pool_unref(&server->pool);
}
