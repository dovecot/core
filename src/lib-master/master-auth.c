/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "fdpass.h"
#include "buffer.h"
#include "hash.h"
#include "master-service-private.h"
#include "master-auth.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#define SOCKET_CONNECT_RETRY_MSECS 500
#define MASTER_AUTH_REQUEST_TIMEOUT_MSECS (MASTER_LOGIN_TIMEOUT_SECS/2*1000)

struct master_auth_connection {
	struct master_auth *auth;
	unsigned int tag;

	int fd;
	struct io *io;
	struct timeout *to;

	char buf[sizeof(struct master_auth_reply)];
	unsigned int buf_pos;

	master_auth_callback_t *callback;
	void *context;
};

struct master_auth {
	struct master_service *service;
	pool_t pool;

	const char *path;

	unsigned int tag_counter;
	struct hash_table *connections;
};

struct master_auth *
master_auth_init(struct master_service *service, const char *path)
{
	struct master_auth *auth;
	pool_t pool;

	pool = pool_alloconly_create("master auth", 1024);
	auth = p_new(pool, struct master_auth, 1);
	auth->pool = pool;
	auth->service = service;
	auth->path = p_strdup(pool, path);
	auth->connections = hash_table_create(default_pool, pool,
					      0, NULL, NULL);
	return auth;
}

static void
master_auth_connection_deinit(struct master_auth_connection **_conn)
{
	struct master_auth_connection *conn = *_conn;

	*_conn = NULL;

	if (conn->tag != 0) {
		hash_table_remove(conn->auth->connections,
				  POINTER_CAST(conn->tag));
	}

	if (conn->callback != NULL)
		conn->callback(NULL, conn->context);

	if (conn->to != NULL)
		timeout_remove(&conn->to);
	if (conn->io != NULL)
		io_remove(&conn->io);
	if (conn->fd != -1) {
		if (close(conn->fd) < 0)
			i_fatal("close(%s) failed: %m", conn->auth->path);
		conn->fd = -1;
	}
	i_free(conn);
}

void master_auth_deinit(struct master_auth **_auth)
{
	struct master_auth *auth = *_auth;
	struct hash_iterate_context *iter;
	void *key, *value;

	*_auth = NULL;

	iter = hash_table_iterate_init(auth->connections);
	while (hash_table_iterate(iter, &key, &value)) {
		struct master_auth_connection *conn = value;

		conn->tag = 0;
		master_auth_connection_deinit(&conn);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&auth->connections);
	pool_unref(&auth->pool);
}

static void master_auth_connection_input(struct master_auth_connection *conn)
{
	const struct master_auth_reply *reply;
	int ret;

	ret = read(conn->fd, conn->buf + conn->buf_pos,
		   sizeof(conn->buf) - conn->buf_pos);
	if (ret <= 0) {
		if (ret < 0) {
			if (errno == EAGAIN)
				return;
			i_error("read(%s) failed: %m", conn->auth->path);
		} else {
			i_error("read(%s) failed: Remote closed connection "
				"(process_limit reached?)",
				conn->auth->path);
		}
		master_auth_connection_deinit(&conn);
		return;
	}

	conn->buf_pos += ret;
	if (conn->buf_pos < sizeof(conn->buf))
		return;

	/* reply is now read */
	reply = (const void *)conn->buf;
	conn->buf_pos = 0;

	if (conn->tag != reply->tag)
		i_error("master(%s): Received reply with unknown tag %u",
			conn->auth->path, reply->tag);
	else if (conn->callback == NULL) {
		/* request aborted */
	} else {
		conn->callback(reply, conn->context);
		conn->callback = NULL;
	}
	master_auth_connection_deinit(&conn);
}

static void master_auth_connection_timeout(struct master_auth_connection *conn)
{
	i_error("master(%s): Auth request timed out (received %u/%u bytes)",
		conn->auth->path, conn->buf_pos,
		(unsigned int)sizeof(conn->buf));
	master_auth_connection_deinit(&conn);
}

void master_auth_request(struct master_auth *auth, int fd,
			 const struct master_auth_request *request,
			 const unsigned char *data,
			 master_auth_callback_t *callback,
			 void *context, unsigned int *tag_r)
{
        struct master_auth_connection *conn;
	struct master_auth_request req;
	buffer_t *buf;
	struct stat st;
	ssize_t ret;

	i_assert(request->client_pid != 0);
	i_assert(request->auth_pid != 0);

	conn = i_new(struct master_auth_connection, 1);
	conn->auth = auth;
	conn->callback = callback;
	conn->context = context;

	req = *request;
	req.tag = ++auth->tag_counter;
	if (req.tag == 0)
		req.tag = ++auth->tag_counter;

	if (fstat(fd, &st) < 0)
		i_fatal("fstat(auth dest fd) failed: %m");
	req.ino = st.st_ino;

	buf = buffer_create_dynamic(pool_datastack_create(),
				    sizeof(req) + req.data_size);
	buffer_append(buf, &req, sizeof(req));
	buffer_append(buf, data, req.data_size);

	conn->fd = net_connect_unix_with_retries(auth->path,
						 SOCKET_CONNECT_RETRY_MSECS);
	if (conn->fd == -1) {
		i_error("net_connect_unix(%s) failed: %m", auth->path);
		master_auth_connection_deinit(&conn);
		return;
	}

	ret = fd_send(conn->fd, fd, buf->data, buf->used);
	if (ret < 0)
		i_error("fd_send(%s, %d) failed: %m", auth->path, fd);
	else if ((size_t)ret != buf->used) {
		i_error("fd_send(%s) sent only %d of %d bytes",
			auth->path, (int)ret, (int)buf->used);
		ret = -1;
	}
	if (ret < 0) {
		master_auth_connection_deinit(&conn);
		return;
	}

	conn->tag = req.tag;
	conn->to = timeout_add(MASTER_AUTH_REQUEST_TIMEOUT_MSECS,
			       master_auth_connection_timeout, conn);
	conn->io = io_add(conn->fd, IO_READ,
			  master_auth_connection_input, conn);
	hash_table_insert(auth->connections, POINTER_CAST(req.tag), conn);
	*tag_r = req.tag;
}

void master_auth_request_abort(struct master_auth *auth, unsigned int tag)
{
        struct master_auth_connection *conn;

	conn = hash_table_lookup(auth->connections, POINTER_CAST(tag));
	if (conn == NULL)
		i_panic("master_auth_request_abort(): tag %u not found", tag);

	conn->callback = NULL;
}
