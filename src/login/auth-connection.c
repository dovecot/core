/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "hash.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "auth-connection.h"

#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAX_INBUF_SIZE (AUTH_MAX_REQUEST_DATA_SIZE)
#define MAX_OUTBUF_SIZE \
	(sizeof(AuthContinuedRequestData) + AUTH_MAX_REQUEST_DATA_SIZE)

struct _AuthConnection {
	AuthConnection *next;

	char *path;
	int fd;
	IO io;
	IStream *input;
	OStream *output;

	int auth_process;
	AuthMethod available_auth_methods;
        AuthReplyData in_reply;

        HashTable *requests;

	unsigned int init_received:1;
	unsigned int in_reply_received:1;
};

AuthMethod available_auth_methods;

static int auth_reconnect;
static int request_id_counter;
static AuthConnection *auth_connections;
static Timeout to;

static void auth_input(void *context, int fd, IO io);
static void auth_connect_missing(void);

static AuthConnection *auth_connection_find(const char *path)
{
	AuthConnection *conn;

	for (conn = auth_connections; conn != NULL; conn = conn->next) {
		if (strcmp(conn->path, path) == 0)
			return conn;
	}

	return NULL;
}

static AuthConnection *auth_connection_new(const char *path)
{
        AuthConnection *conn;
	int fd;

	fd = net_connect_unix(path);
	if (fd == -1) {
		i_error("Can't connect to imap-auth at %s: %m", path);
                auth_reconnect = TRUE;
		return NULL;
	}

	conn = i_new(AuthConnection, 1);
	conn->path = i_strdup(path);
	conn->fd = fd;
	conn->io = io_add(fd, IO_READ, auth_input, conn);
	conn->input = i_stream_create_file(fd, default_pool, MAX_INBUF_SIZE,
					   FALSE);
	conn->output = o_stream_create_file(fd, default_pool, MAX_OUTBUF_SIZE,
					    IO_PRIORITY_DEFAULT, FALSE);
	conn->requests = hash_create(default_pool, 100, NULL, NULL);

	conn->next = auth_connections;
	auth_connections = conn;
	return conn;
}

static void request_destroy(AuthRequest *request)
{
	hash_remove(request->conn->requests, POINTER_CAST(request->id));
	i_free(request);
}

static void request_abort(AuthRequest *request)
{
	request->callback(request, request->conn->auth_process,
			  AUTH_RESULT_INTERNAL_FAILURE,
			  (const unsigned char *) "Authentication process died",
			  0, request->context);
	request_destroy(request);
}

static void request_hash_destroy(void *key __attr_unused__, void *value,
				 void *context __attr_unused__)
{
	request_abort(value);
}

static void auth_connection_destroy(AuthConnection *conn)
{
	AuthConnection **pos;

	for (pos = &auth_connections; *pos != NULL; pos = &(*pos)->next) {
		if (*pos == conn) {
			*pos = conn->next;
			break;
		}
	}

	hash_foreach(conn->requests, request_hash_destroy, NULL);
	hash_destroy(conn->requests);

	(void)close(conn->fd);
	io_remove(conn->io);
	i_stream_unref(conn->input);
	o_stream_unref(conn->output);
	i_free(conn->path);
	i_free(conn);
}

static AuthConnection *auth_connection_get(AuthMethod method, size_t size,
					   const char **error)
{
	AuthConnection *conn;
	int found;

	found = FALSE;
	for (conn = auth_connections; conn != NULL; conn = conn->next) {
		if ((conn->available_auth_methods & method)) {
			if (o_stream_have_space(conn->output, size) > 0)
				return conn;

			found = TRUE;
		}
	}

	if (!found) {
		if ((available_auth_methods & method) == 0)
			*error = "Unsupported authentication method";
		else {
			*error = "Authentication server isn't connected, "
				"try again later..";
			auth_reconnect = TRUE;
		}
	} else {
		*error = "Authentication servers are busy, wait..";
		i_warning("Authentication servers are busy");
	}

	return NULL;
}

static void update_available_auth_methods(void)
{
	AuthConnection *conn;

        available_auth_methods = 0;
	for (conn = auth_connections; conn != NULL; conn = conn->next)
                available_auth_methods |= conn->available_auth_methods;
}

static void auth_handle_init(AuthConnection *conn, AuthInitData *init_data)
{
	conn->auth_process = init_data->auth_process;
	conn->available_auth_methods = init_data->auth_methods;
	conn->init_received = TRUE;

	update_available_auth_methods();
}

static void auth_handle_reply(AuthConnection *conn, AuthReplyData *reply_data,
			      const unsigned char *data)
{
	AuthRequest *request;

	request = hash_lookup(conn->requests, POINTER_CAST(reply_data->id));
	if (request == NULL) {
		i_error("BUG: imap-auth sent us reply with unknown ID %u",
			reply_data->id);
		return;
	}

	/* save the returned cookie */
	memcpy(request->cookie, reply_data->cookie, AUTH_COOKIE_SIZE);

	t_push();
	request->callback(request, request->conn->auth_process,
			  reply_data->result, data, reply_data->data_size,
			  request->context);
	t_pop();

	if (reply_data->result != AUTH_RESULT_CONTINUE)
		request_destroy(request);
}

static void auth_input(void *context, int fd __attr_unused__,
		       IO io __attr_unused__)
{
	AuthConnection *conn = context;
        AuthInitData init_data;
	const unsigned char *data;
	size_t size;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
                auth_reconnect = TRUE;
		auth_connection_destroy(conn);
		return;
	case -2:
		/* buffer full - can't happen unless imap-auth is buggy */
		i_error("BUG: imap-auth sent us more than %d bytes of data",
			MAX_INBUF_SIZE);
		auth_connection_destroy(conn);
		return;
	}

	data = i_stream_get_data(conn->input, &size);

	if (!conn->init_received) {
		if (size == sizeof(AuthInitData)) {
			memcpy(&init_data, data, sizeof(AuthInitData));
			i_stream_skip(conn->input, sizeof(AuthInitData));

			auth_handle_init(conn, &init_data);
		} else if (size > sizeof(AuthInitData)) {
			i_error("BUG: imap-auth sent us too much "
				"initialization data (%"PRIuSIZE_T " vs %"
				PRIuSIZE_T")", size, sizeof(AuthInitData));
			auth_connection_destroy(conn);
		}

		return;
	}

	if (!conn->in_reply_received) {
		data = i_stream_get_data(conn->input, &size);
		if (size < sizeof(AuthReplyData))
			return;

		memcpy(&conn->in_reply, data, sizeof(AuthReplyData));
		data += sizeof(AuthReplyData);
		size -= sizeof(AuthReplyData);
		i_stream_skip(conn->input, sizeof(AuthReplyData));
		conn->in_reply_received = TRUE;
	}

	if (size < conn->in_reply.data_size)
		return;

	/* we've got a full reply */
	conn->in_reply_received = FALSE;
	auth_handle_reply(conn, &conn->in_reply, data);
	i_stream_skip(conn->input, conn->in_reply.data_size);
}

int auth_init_request(AuthMethod method, AuthCallback callback,
		      void *context, const char **error)
{
	AuthConnection *conn;
	AuthRequest *request;
	AuthInitRequestData request_data;

	if (auth_reconnect)
		auth_connect_missing();

	conn = auth_connection_get(method, sizeof(AuthInitRequestData), error);
	if (conn == NULL)
		return FALSE;

	/* create internal request structure */
	request = i_new(AuthRequest, 1);
	request->method = method;
	request->conn = conn;
	request->id = ++request_id_counter;
	request->callback = callback;
	request->context = context;

	hash_insert(conn->requests, POINTER_CAST(request->id), request);

	/* send request to auth */
	request_data.type = AUTH_REQUEST_INIT;
	request_data.method = request->method;
	request_data.id = request->id;
	if (o_stream_send(request->conn->output, &request_data,
			  sizeof(request_data)) < 0)
		auth_connection_destroy(request->conn);
	return TRUE;
}

void auth_continue_request(AuthRequest *request, const unsigned char *data,
			   size_t data_size)
{
	AuthContinuedRequestData request_data;

	/* send continued request to auth */
	memcpy(request_data.cookie, request->cookie, AUTH_COOKIE_SIZE);
	request_data.type = AUTH_REQUEST_CONTINUE;
	request_data.id = request->id;
	request_data.data_size = data_size;

	if (o_stream_send(request->conn->output, &request_data,
			  sizeof(request_data)) < 0)
		auth_connection_destroy(request->conn);
	else if (o_stream_send(request->conn->output, data, data_size) < 0)
		auth_connection_destroy(request->conn);
}

static void auth_connect_missing(void)
{
	DIR *dirp;
	struct dirent *dp;
	struct stat st;

	auth_reconnect = TRUE;

	/* we're chrooted into */
	dirp = opendir(".");
	if (dirp == NULL) {
		i_error("opendir(\".\") failed when trying to get list of "
			"authentication servers: %m");
		return;
	}

	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;

		if (auth_connection_find(dp->d_name) != NULL) {
			/* already connected */
			continue;
		}

		if (stat(dp->d_name, &st) == 0 && S_ISSOCK(st.st_mode)) {
			if (auth_connection_new(dp->d_name) != NULL)
				auth_reconnect = FALSE;
		}
	}

	(void)closedir(dirp);
}

static void auth_connect_missing_timeout(void *context __attr_unused__,
					 Timeout timeout __attr_unused__)
{
	if (auth_reconnect)
                auth_connect_missing();
}

void auth_connection_init(void)
{
	auth_connections = NULL;
	request_id_counter = 0;
        auth_reconnect = FALSE;

	auth_connect_missing();
	to = timeout_add(1000, auth_connect_missing_timeout, NULL);
}

void auth_connection_deinit(void)
{
	AuthConnection *next;

	while (auth_connections != NULL) {
		next = auth_connections->next;
		auth_connection_destroy(auth_connections);
		auth_connections = next;
	}

	timeout_remove(to);
}
