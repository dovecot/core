/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"

#include "sasl-server-private.h"

static struct event_category event_category_sasl_server = {
	.name = "sasl-server"
};

/*
 * Server
 */

struct sasl_server *sasl_server_init(struct event *event_parent)
{
	struct sasl_server *server;
	pool_t pool;

	pool = pool_alloconly_create(MEMPOOL_GROWING"sasl_server", 2048);
	server = p_new(pool, struct sasl_server, 1);
	server->pool = pool;

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

	i_assert(server->requests == 0);

	event_unref(&server->event);
	pool_unref(&server->pool);
}
