/* Copyright (C) 2003 Timo Sirainen */

#include "lib.h"
#include "buffer.h"
#include "hash.h"
#include "ostream.h"
#include "auth-client.h"
#include "auth-server-connection.h"
#include "auth-server-request.h"

struct auth_request {
        struct auth_server_connection *conn;

	unsigned int id;

	char *mech, *protocol;
	enum auth_client_request_new_flags flags;
	struct ip_addr local_ip, remote_ip;

	unsigned char *initial_resp_data;
	size_t initial_resp_size;

	auth_request_callback_t *callback;
	void *context;

        struct auth_server_connection *next_conn;
	unsigned char *plaintext_data; /* for resending to other servers */
        size_t plaintext_data_size;

	unsigned int init_sent:1;
	unsigned int retrying:1;
};

static int auth_server_send_new_request(struct auth_server_connection *conn,
					struct auth_request *request);

static struct auth_server_connection *
get_next_plain_server(struct auth_server_connection *conn)
{
	conn = conn->next;
	while (conn != NULL) {
		if (conn->has_plain_mech)
			return conn;
		conn = conn->next;
	}
	return NULL;
}

static void
auth_server_request_check_retry(struct auth_request *request,
				const unsigned char *data, size_t data_size)
{
	if (strcmp(request->mech, "PLAIN") == 0 &&
	    request->plaintext_data == NULL && request->conn != NULL) {
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

static int auth_server_send_new_request(struct auth_server_connection *conn,
					struct auth_request *request)
{
	struct auth_client_request_new auth_request;
	buffer_t *buf;
	size_t size;
	int ret;

	memset(&auth_request, 0, sizeof(auth_request));
	auth_request.type = AUTH_CLIENT_REQUEST_NEW;
	auth_request.id = request->id;
	auth_request.flags = request->flags;

	if (request->local_ip.family == request->remote_ip.family)
		auth_request.ip_family = request->local_ip.family;

	t_push();
	buf = buffer_create_dynamic(pool_datastack_create(), 256, (size_t)-1);
	buffer_set_used_size(buf, sizeof(auth_request));

	if (auth_request.ip_family != 0) {
		size = IPADDR_IS_V4(&request->local_ip) ? 4 :
			sizeof(request->local_ip.ip);
		buffer_append(buf, &request->local_ip.ip, size);
		buffer_append(buf, &request->remote_ip.ip, size);
	}

	auth_request.mech_idx =
		buffer_get_used_size(buf) - sizeof(auth_request);
	buffer_append(buf, request->mech, strlen(request->mech)+1);

	auth_request.protocol_idx =
		buffer_get_used_size(buf) - sizeof(auth_request);
	buffer_append(buf, request->protocol, strlen(request->protocol)+1);

	auth_request.initial_resp_idx =
		buffer_get_used_size(buf) - sizeof(auth_request);
	buffer_append(buf, request->initial_resp_data,
		      request->initial_resp_size);

	auth_request.data_size =
		buffer_get_used_size(buf) - sizeof(auth_request);

	memcpy(buffer_get_space_unsafe(buf, 0, sizeof(auth_request)),
	       &auth_request, sizeof(auth_request));

	ret = o_stream_send(conn->output, buffer_get_data(buf, NULL),
			    buffer_get_used_size(buf));
	t_pop();

	if (ret < 0) {
		errno = conn->output->stream_errno;
		i_warning("Error sending request to auth server: %m");
		auth_server_connection_destroy(conn, TRUE);
		return FALSE;
	}

	auth_server_request_check_retry(request, request->initial_resp_data,
					request->initial_resp_size);
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
auth_client_request_new(struct auth_client *client, struct auth_connect_id *id,
			const struct auth_request_info *request_info,
			auth_request_callback_t *callback, void *context,
			const char **error_r)
{
	struct auth_server_connection *conn;
	struct auth_request *request;

	if (id == NULL) {
		conn = auth_server_connection_find_mech(client,
							request_info->mech,
							error_r);
	} else {
		*error_r = NULL;
		conn = client->connections;
		for (; conn != NULL; conn = conn->next) {
			if (conn->connect_uid == id->connect_uid &&
			    conn->server_pid == id->server_pid)
				break;
		}
	}

	if (conn == NULL)
		return NULL;

	request = i_new(struct auth_request, 1);
	request->conn = conn;
	request->mech = i_strdup(request_info->mech);
	request->protocol = i_strdup(request_info->protocol);
	request->flags = request_info->flags;
	request->local_ip = request_info->local_ip;
	request->remote_ip = request_info->remote_ip;
	request->id = ++client->request_id_counter;

	if (request_info->initial_resp_size != 0) {
		request->initial_resp_size = request_info->initial_resp_size;
		request->initial_resp_data =
			i_malloc(request_info->initial_resp_size);
		memcpy(request->initial_resp_data,
		       request_info->initial_resp_data,
		       request_info->initial_resp_size);
	}
	
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

	auth_server_request_check_retry(request, data, data_size);
}

void auth_client_request_abort(struct auth_request *request)
{
	void *id = POINTER_CAST(request->id);

	hash_remove(request->conn->requests, id);
	if (request->next_conn != NULL)
		hash_remove(request->next_conn->requests, id);

	request->callback(request, NULL, NULL, request->context);

	i_free(request->initial_resp_data);
	i_free(request->plaintext_data);
	i_free(request->mech);
	i_free(request->protocol);
	i_free(request);
}

unsigned int auth_client_request_get_id(struct auth_request *request)
{
	return request->id;
}

unsigned int auth_client_request_get_server_pid(struct auth_request *request)
{
	return request->conn->server_pid;
}
