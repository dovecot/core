/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "ostream.h"
#include "auth-client.h"
#include "auth-server-connection.h"
#include "auth-server-request.h"

struct auth_request {
        enum auth_mech mech;
        struct auth_server_connection *conn;

	unsigned int id;

	auth_request_callback_t *callback;
	void *context;

	unsigned int init_sent:1;
};

void auth_server_request_handle_reply(struct auth_server_connection *conn,
				      struct auth_client_request_reply *reply,
				      const unsigned char *data)
{
	struct auth_request *request;

	request = hash_lookup(conn->requests, POINTER_CAST(reply->id));
	if (request == NULL) {
		i_error("BUG: Auth server sent us reply with unknown ID %u",
			reply->id);
		return;
	}

	request->callback(request, reply, data, request->context);

	if (reply->result != AUTH_CLIENT_RESULT_CONTINUE) {
		hash_remove(conn->requests, POINTER_CAST(request->id));
		i_free(request);
	}
}

static void request_hash_remove(void *key __attr_unused__, void *value,
				void *context __attr_unused__)
{
	struct auth_request *request = value;

	request->callback(request, NULL, NULL, request->context);
	request->conn = NULL;
}

void auth_server_requests_remove_all(struct auth_server_connection *conn)
{
	hash_foreach(conn->requests, request_hash_remove, NULL);
}

struct auth_request *
auth_client_request_new(struct auth_client *client,
			enum auth_mech mech, enum auth_protocol protocol,
			auth_request_callback_t *callback, void *context,
			const char **error_r)
{
	struct auth_server_connection *conn;
	struct auth_request *request;
	struct auth_client_request_new auth_request;

	conn = auth_server_connection_find_mech(client, mech, error_r);
	if (conn == NULL)
		return NULL;

	request = i_new(struct auth_request, 1);
	request->mech = mech;
	request->conn = conn;
	request->id = ++client->request_id_counter;
	if (request->id == 0) {
		/* wrapped - ID 0 not allowed */
		request->id = ++client->request_id_counter;
	}
	request->callback = callback;
	request->context = context;

	hash_insert(conn->requests, POINTER_CAST(request->id), request);

	/* send request to auth */
	auth_request.type = AUTH_CLIENT_REQUEST_NEW;
	auth_request.id = request->id;
	auth_request.protocol = protocol;
	auth_request.mech = request->mech;
	if (o_stream_send(request->conn->output, &auth_request,
			  sizeof(auth_request)) < 0) {
		errno = request->conn->output->stream_errno;
		i_warning("Error sending request to auth server: %m");
		auth_server_connection_destroy(request->conn, TRUE);
	}
	return request;
}

void auth_client_request_continue(struct auth_request *request,
				  const unsigned char *data, size_t data_size)
{
	struct auth_client_request_continue auth_request;

	/* send continued request to auth */
	auth_request.type = AUTH_CLIENT_REQUEST_CONTINUE;
	auth_request.id = request->id;
	auth_request.data_size = data_size;

	if (o_stream_send(request->conn->output, &auth_request,
			  sizeof(auth_request)) < 0 ||
	    o_stream_send(request->conn->output, data, data_size) < 0) {
		errno = request->conn->output->stream_errno;
		i_warning("Error sending continue request to auth server: %m");
		auth_server_connection_destroy(request->conn, TRUE);
	}
}

void auth_client_request_abort(struct auth_request *request)
{
	void *id = POINTER_CAST(request->id);

	if (hash_lookup(request->conn->requests, id) != NULL)
		hash_remove(request->conn->requests, id);
	i_free(request);
}

unsigned int auth_client_request_get_id(struct auth_request *request)
{
	return request->id;
}

unsigned int auth_client_request_get_server_pid(struct auth_request *request)
{
	return request->conn->pid;
}
