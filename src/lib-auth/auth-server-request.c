/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "hash.h"
#include "ostream.h"
#include "auth-client.h"
#include "auth-server-connection.h"
#include "auth-server-request.h"

struct auth_request {
        struct auth_server_connection *conn;

	enum auth_mech mech;
        enum auth_protocol protocol;

	unsigned int id;

	auth_request_callback_t *callback;
	void *context;

        struct auth_server_connection *next_conn;
	unsigned char *plaintext_data; /* for resending to other servers */
        size_t plaintext_data_size;

	unsigned int init_sent:1;
	unsigned int retrying:1;
};

static int auth_server_send_new_request(struct auth_server_connection *conn,
					struct auth_request *request)
{
	struct auth_client_request_new auth_request;

	auth_request.type = AUTH_CLIENT_REQUEST_NEW;
	auth_request.id = request->id;
	auth_request.protocol = request->protocol;
	auth_request.mech = request->mech;

	if (o_stream_send(conn->output, &auth_request,
			  sizeof(auth_request)) < 0) {
		errno = conn->output->stream_errno;
		i_warning("Error sending request to auth server: %m");
		auth_server_connection_destroy(conn, TRUE);
		return FALSE;
	}

	return TRUE;
}

static void auth_server_send_continue(struct auth_server_connection *conn,
				      struct auth_request *request,
				      const unsigned char *data, size_t size)
{
	struct auth_client_request_continue auth_request;

	/* send continued request to auth */
	auth_request.type = AUTH_CLIENT_REQUEST_CONTINUE;
	auth_request.id = request->id;
	auth_request.data_size = size;

	if (o_stream_send(conn->output, &auth_request,
			  sizeof(auth_request)) < 0 ||
	    o_stream_send(conn->output, data, size) < 0) {
		errno = conn->output->stream_errno;
		i_warning("Error sending continue request to auth server: %m");
		auth_server_connection_destroy(conn, TRUE);
	}
}

static struct auth_server_connection *
get_next_plain_server(struct auth_server_connection *conn)
{
	conn = conn->next;
	while (conn != NULL) {
		if ((conn->available_auth_mechs & AUTH_MECH_PLAIN) != 0)
			return conn;
		conn = conn->next;
	}
	return NULL;
}

void auth_server_request_handle_reply(struct auth_server_connection *conn,
				      struct auth_client_request_reply *reply,
				      const unsigned char *data)
{
	struct auth_request *request;
        struct auth_server_connection *next;

	request = hash_lookup(conn->requests, POINTER_CAST(reply->id));
	if (request == NULL) {
		/* We've already destroyed the request */
		return;
	}

	switch (reply->result) {
	case AUTH_CLIENT_RESULT_SUCCESS:
		hash_remove(request->conn->requests, POINTER_CAST(request->id));
		if (request->next_conn != NULL) {
			hash_remove(request->next_conn->requests,
				    POINTER_CAST(request->id));
		}
		request->conn = conn;
		request->next_conn = NULL;
		break;
	case AUTH_CLIENT_RESULT_FAILURE:
		hash_remove(conn->requests, POINTER_CAST(request->id));
		if (!request->retrying)
			break;

		next = request->next_conn == NULL ? NULL :
			get_next_plain_server(request->next_conn);

		if (conn == request->conn)
			request->conn = request->next_conn;
		request->next_conn = NULL;

		if (next == NULL) {
			if (request->conn != NULL) {
				/* the other one hasn't replied yet */
				return;
			}
			request->conn = conn;
			break;
		}

		hash_insert(next->requests, POINTER_CAST(request->id), request);
		request->next_conn = next;

		auth_server_send_new_request(next, request);
		return;
	case AUTH_CLIENT_RESULT_CONTINUE:
		if (!request->retrying)
			break;

		auth_server_send_continue(conn, request,
					  request->plaintext_data,
					  request->plaintext_data_size);
		return;
	}

	request->callback(request, reply, data, request->context);

	if (reply->result != AUTH_CLIENT_RESULT_CONTINUE) {
		i_free(request->plaintext_data);
		i_free(request);
	}
}

static void request_hash_remove(struct auth_server_connection *conn,
                                struct auth_request *request)
{
	if (request->conn == conn) {
		if (request->next_conn == NULL) {
			request->callback(request, NULL, NULL,
					  request->context);
			request->conn = NULL;
		} else {
			request->conn = request->next_conn;
			request->next_conn = NULL;
		}
	} else {
		request->next_conn = NULL;
	}
}

void auth_server_requests_remove_all(struct auth_server_connection *conn)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_iterate_init(conn->requests);
	while (hash_iterate(iter, &key, &value))
		request_hash_remove(conn, value);
	hash_iterate_deinit(iter);
}

struct auth_request *
auth_client_request_new(struct auth_client *client,
			enum auth_mech mech, enum auth_protocol protocol,
			auth_request_callback_t *callback, void *context,
			const char **error_r)
{
	struct auth_server_connection *conn;
	struct auth_request *request;

	conn = auth_server_connection_find_mech(client, mech, error_r);
	if (conn == NULL)
		return NULL;

	request = i_new(struct auth_request, 1);
	request->conn = conn;
	request->mech = mech;
	request->protocol = protocol;
	request->id = ++client->request_id_counter;
	if (request->id == 0) {
		/* wrapped - ID 0 not allowed */
		request->id = ++client->request_id_counter;
	}
	request->callback = callback;
	request->context = context;

	hash_insert(conn->requests, POINTER_CAST(request->id), request);

	if (!auth_server_send_new_request(conn, request))
		request = NULL;
	return request;
}

void auth_client_request_continue(struct auth_request *request,
				  const unsigned char *data, size_t data_size)
{
	auth_server_send_continue(request->conn, request, data, data_size);

	if (request->mech == AUTH_MECH_PLAIN &&
	    request->plaintext_data == NULL) {
		request->next_conn = get_next_plain_server(request->conn);
		if (request->next_conn != NULL) {
			/* plaintext authentication - save the data so we can
			   try it for the next */
			request->plaintext_data = i_malloc(data_size);
			memcpy(request->plaintext_data, data, data_size);
			request->plaintext_data_size = data_size;

			hash_insert(request->next_conn->requests,
				    POINTER_CAST(request->id), request);
			auth_server_send_new_request(request->next_conn,
						     request);
			request->retrying = TRUE;
		}
	}
}

void auth_client_request_abort(struct auth_request *request)
{
	void *id = POINTER_CAST(request->id);

	hash_remove(request->conn->requests, id);
	if (request->next_conn != NULL)
		hash_remove(request->next_conn->requests, id);

	request->callback(request, NULL, NULL, request->context);

	i_free(request->plaintext_data);
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
