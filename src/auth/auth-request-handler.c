/* Copyright (C) 2005 Timo Sirainen */

#include "common.h"
#include "auth-request-handler.h"
#include "auth-request-balancer.h"

struct auth_request_handler_api *auth_request_handler_api;

struct auth_request_handler *
auth_request_handler_create(struct auth *auth, int prepend_connect_uid,
			    auth_request_callback_t *callback, void *context,
			    auth_request_callback_t *master_callback,
			    void *master_context)
{
	return auth_request_handler_api->
		create(auth, prepend_connect_uid, callback, context,
		       master_callback, master_context);
}

void auth_request_handler_set(struct auth_request_handler *handler,
			      unsigned int connect_uid,
			      unsigned int client_pid)
{
	auth_request_handler_api->set(handler, connect_uid, client_pid);
}

void auth_request_handler_unref(struct auth_request_handler *handler)
{
	auth_request_handler_api->unref(handler);
}

void auth_request_handler_check_timeouts(struct auth_request_handler *handler)
{
        auth_request_handler_api->check_timeouts(handler);
}

int auth_request_handler_auth_begin(struct auth_request_handler *handler,
				    const char *args)
{
        return auth_request_handler_api->auth_begin(handler, args);
}

int auth_request_handler_auth_continue(struct auth_request_handler *handler,
				       const char *args)
{
	return auth_request_handler_api->auth_continue(handler, args);
}

void auth_request_handler_master_request(struct auth_request_handler *handler,
					 unsigned int id,
					 unsigned int client_id)
{
        auth_request_handler_api->master_request(handler, id, client_id);
}

void auth_request_handlers_flush_failures(void)
{
        auth_request_handler_api->flush_failures();
}

void auth_request_handlers_init(int balancer)
{
	/* use balancer if we have it */
	auth_request_handler_api = balancer ?
		&auth_request_handler_balancer : &auth_request_handler_default;

        auth_request_handler_api->init();
}

void auth_request_handlers_deinit(void)
{
        auth_request_handler_api->deinit();
}
