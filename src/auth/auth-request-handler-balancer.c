/* Copyright (C) 2005 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "hash.h"
#include "str.h"
#include "str-sanitize.h"
#include "mech.h"
#include "auth-client-interface.h"
#include "auth-request-handler.h"
#include "auth-request-balancer.h"

#include <stdlib.h>

struct auth_balancer_request {
	unsigned int client_id;
	unsigned int master_id;
	unsigned int balancer_pid;
	time_t created;
};

struct auth_request_handler {
	int refcount;
	pool_t pool;
	struct hash_table *client_requests;

        struct auth *auth;
	unsigned int connect_uid, client_pid;

	auth_request_callback_t *callback;
	void *context;

	auth_request_callback_t *master_callback;
	void *master_context;
};

static struct auth_request_handler *
_create(struct auth *auth, int prepend_connect_uid,
	auth_request_callback_t *callback, void *context,
	auth_request_callback_t *master_callback, void *master_context)
{
	struct auth_request_handler *handler;
	pool_t pool;

	i_assert(!prepend_connect_uid);

	pool = pool_alloconly_create("auth request handler", 4096);

	handler = p_new(pool, struct auth_request_handler, 1);
	handler->refcount = 1;
	handler->pool = pool;
	handler->client_requests =
		hash_create(default_pool, pool, 0, NULL, NULL);
	handler->auth = auth;
	handler->callback = callback;
	handler->context = context;
	handler->master_callback = master_callback;
	handler->master_context = master_context;

	return handler;
}

static void _set(struct auth_request_handler *handler,
		 unsigned int connect_uid, unsigned int client_pid)
{
	i_assert(handler->connect_uid == 0);

	handler->connect_uid = connect_uid;
	handler->client_pid = client_pid;

	auth_request_balancer_add_handler(handler, connect_uid);
}

static void _unref(struct auth_request_handler *handler)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	i_assert(handler->refcount > 0);
	if (--handler->refcount > 0)
		return;

	auth_request_balancer_remove_handler(handler->connect_uid);

	iter = hash_iterate_init(handler->client_requests);
	while (hash_iterate(iter, &key, &value))
		i_free(value);
	hash_iterate_deinit(iter);

	/* notify parent that we're done with all requests */
	handler->callback(NULL, handler->context);

	hash_destroy(handler->client_requests);
	pool_unref(handler->pool);
}

static void auth_request_handler_remove(struct auth_request_handler *handler,
					struct auth_balancer_request *request)
{
	hash_remove(handler->client_requests, POINTER_CAST(request->client_id));
	i_free(request);
}

static void _check_timeouts(struct auth_request_handler *handler)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_iterate_init(handler->client_requests);
	while (hash_iterate(iter, &key, &value)) {
		struct auth_balancer_request *request = value;

		if (request->created + AUTH_REQUEST_TIMEOUT < ioloop_time)
			auth_request_handler_remove(handler, request);
	}
	hash_iterate_deinit(iter);
}

static int _auth_begin(struct auth_request_handler *handler, const char *args)
{
	struct auth_balancer_request *request;
	struct mech_module *mech;
	const char *mech_name;
	string_t *str;
	unsigned int id;

	/* <id> <mechanism> [...] */
	id = (unsigned int)strtoul(t_strcut(args, '\t'), NULL, 10);
	mech_name = strchr(args, '\t');
	if (mech_name == NULL) {
		i_error("BUG: Authentication client %u "
			"sent broken AUTH request", handler->client_pid);
		return FALSE;
	}
	args = strchr(++mech_name, '\t');
	mech_name = t_strcut(mech_name, '\t');

	mech = mech_module_find(mech_name);
	if (mech == NULL) {
		/* unsupported mechanism */
		i_error("BUG: Authentication client %u requested unsupported "
			"authentication mechanism %s", handler->client_pid,
			str_sanitize(mech_name, MAX_MECH_NAME_LEN));
		return FALSE;
	}

	request = i_new(struct auth_balancer_request, 1);
	request->created = ioloop_time;
	request->client_id = id;

	str = t_str_new(256);
	str_printfa(str, "%u\t%u\tAUTH\t%u\t%s%s",
		    handler->connect_uid, handler->client_pid,
		    id, mech->mech_name, args == NULL ? "" : args);
	request->balancer_pid = auth_request_balancer_send(str_c(str));

	hash_insert(handler->client_requests, POINTER_CAST(id), request);
	return TRUE;
}

static int
_auth_continue(struct auth_request_handler *handler, const char *args)
{
	struct auth_balancer_request *request;
	const char *data;
	string_t *str;
	unsigned int id;

	data = strchr(args, '\t');
	if (data++ == NULL) {
		i_error("BUG: Authentication client sent broken CONT request");
		return FALSE;
	}

	id = (unsigned int)strtoul(args, NULL, 10);

	request = hash_lookup(handler->client_requests, POINTER_CAST(id));
	if (request == NULL) {
		data = t_strdup_printf("FAIL\t%u\treason=Timeouted", id);
		handler->callback(data, handler->context);
		return TRUE;
	}

	str = t_str_new(128);
	str_printfa(str, "%u\t%u\tCONT\t%u\t%s",
		    handler->connect_uid, handler->client_pid, id, data);
	auth_request_balancer_send_to(request->balancer_pid, str_c(str));
	return TRUE;
}

static void _master_request(struct auth_request_handler *handler,
			    unsigned int id, unsigned int client_id)
{
	struct auth_balancer_request *request;
	const char *reply;
	string_t *str;

	request = hash_lookup(handler->client_requests,
			      POINTER_CAST(client_id));
	if (request == NULL || request->balancer_pid == 0) {
		i_error("Master request %u.%u not found from balancer",
			handler->client_pid, client_id);
		reply = t_strdup_printf("NOTFOUND\t%u", id);
		handler->master_callback(reply, handler->master_context);
		return;
	}

	request->master_id = id;

	str = t_str_new(128);
	str_printfa(str, "%u\t%u\tREQUEST\t%u",
		    handler->connect_uid, handler->client_pid, client_id);
	auth_request_balancer_send_to(request->balancer_pid, str_c(str));
}

static void _flush_failures(void)
{
}

static void _init(void)
{
        auth_request_balancer_child_init();
}

static void _deinit(void)
{
        auth_request_balancer_child_deinit();
}

struct auth_request_handler_api auth_request_handler_balancer = {
	_create,
	_unref,
	_set,
	_check_timeouts,
	_auth_begin,
	_auth_continue,
	_master_request,
	_flush_failures,
	_init,
	_deinit
};

void auth_request_handler_balancer_reply(struct auth_request_handler *handler,
					 const char *line)
{
	struct auth_balancer_request *request;
	const char *cmd, *id_str, *args;
	unsigned int id;

	/* <cmd> <id> [...] */
	args = strchr(line, '\t');
	if (args == NULL) {
		i_error("Balancer worker sent invalid reply: %s", line);
		return;
	}

	cmd = t_strdup_until(line, args);
	id_str = args + 1;
	args = strchr(id_str, '\t');
	if (args == NULL)
		args = "";
	else
		id_str = t_strdup_until(id_str, args);

	id = (unsigned int)strtoul(id_str, NULL, 10);
	request = hash_lookup(handler->client_requests, POINTER_CAST(id));
	if (request == NULL) {
		i_error("Balancer worker sent unknown request %u", id);
		return;
	}

	if (request->master_id == 0) {
		handler->callback(line, handler->context);
		if (strcmp(cmd, "CONT") != 0 &&
		    (strcmp(cmd, "OK") != 0 ||
		     strstr(line, "\tnologin") != NULL ||
		     handler->master_callback == NULL)) {
			/* this request doesn't have to wait for master
			   process to pick it up. delete it */
			auth_request_handler_remove(handler, request);
		}
	} else {
		/* replace client id with master id */
		line = t_strdup_printf("%s\t%u%s", cmd,
				       request->master_id, args);
		handler->master_callback(line, handler->master_context);
		auth_request_handler_remove(handler, request);
	}
}
