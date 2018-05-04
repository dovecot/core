/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "fdpass.h"
#include "buffer.h"
#include "hash.h"
#include "time-util.h"
#include "master-service-private.h"
#include "master-auth.h"

#include <unistd.h>
#include <sys/stat.h>

#define SOCKET_CONNECT_RETRY_MSECS 500
#define SOCKET_CONNECT_RETRY_WARNING_INTERVAL_SECS 2
#define MASTER_AUTH_REQUEST_TIMEOUT_MSECS (MASTER_LOGIN_TIMEOUT_SECS/2*1000)

struct master_auth_connection {
	struct master_auth *auth;
	unsigned int tag;

	unsigned int client_pid, auth_id;
	struct ip_addr remote_ip;
	struct timeval create_time;

	char *path;
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

	const char *default_path;
	time_t last_connect_warning;

	unsigned int tag_counter;
	HASH_TABLE(void *, struct master_auth_connection *) connections;
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
	auth->default_path = p_strdup(pool, path);
	hash_table_create_direct(&auth->connections, pool, 0);
	return auth;
}

static void
master_auth_connection_deinit(struct master_auth_connection **_conn)
{
	struct master_auth_connection *conn = *_conn;

	*_conn = NULL;

	if (conn->tag != 0)
		hash_table_remove(conn->auth->connections,
				  POINTER_CAST(conn->tag));

	if (conn->callback != NULL)
		conn->callback(NULL, conn->context);

	timeout_remove(&conn->to);
	io_remove(&conn->io);
	if (conn->fd != -1) {
		if (close(conn->fd) < 0)
			i_fatal("close(%s) failed: %m", conn->path);
		conn->fd = -1;
	}
	i_free(conn->path);
	i_free(conn);
}

static void ATTR_FORMAT(2, 3)
conn_error(struct master_auth_connection *conn, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	i_error("master(%s): %s (client-pid=%u, client-id=%u, rip=%s, created %u msecs ago, received %u/%zu bytes)",
		conn->path, t_strdup_vprintf(fmt, args),
		conn->client_pid, conn->auth_id, net_ip2addr(&conn->remote_ip),
		timeval_diff_msecs(&ioloop_timeval, &conn->create_time),
		conn->buf_pos, sizeof(conn->buf_pos));
	va_end(args);
}

void master_auth_deinit(struct master_auth **_auth)
{
	struct master_auth *auth = *_auth;
	struct hash_iterate_context *iter;
	void *key;
	struct master_auth_connection *conn;

	*_auth = NULL;

	iter = hash_table_iterate_init(auth->connections);
	while (hash_table_iterate(iter, auth->connections, &key, &conn)) {
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
		if (ret == 0 || errno == ECONNRESET) {
			conn_error(conn, "read() failed: Remote closed connection "
				"(destination service { process_limit } reached?)");
		} else {
			if (errno == EAGAIN)
				return;
			conn_error(conn, "read() failed: %m");
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
		conn_error(conn, "Received reply with unknown tag %u", reply->tag);
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
	conn_error(conn, "Auth request timed out");
	master_auth_connection_deinit(&conn);
}

void master_auth_request_full(struct master_auth *auth,
			      const struct master_auth_request_params *params,
			      master_auth_callback_t *callback, void *context,
			      unsigned int *tag_r)
{
        struct master_auth_connection *conn;
	struct master_auth_request req;
	buffer_t *buf;
	struct stat st;
	ssize_t ret;

	i_assert(params->request.client_pid != 0);
	i_assert(params->request.auth_pid != 0);

	conn = i_new(struct master_auth_connection, 1);
	conn->auth = auth;
	conn->create_time = ioloop_timeval;
	conn->callback = callback;
	conn->context = context;
	conn->path = params->socket_path != NULL ?
		i_strdup(params->socket_path) : i_strdup(auth->default_path);

	req = params->request;
	req.tag = ++auth->tag_counter;
	if (req.tag == 0)
		req.tag = ++auth->tag_counter;

	conn->client_pid = req.client_pid;
	conn->auth_id = req.auth_id;
	conn->remote_ip = req.remote_ip;

	if (fstat(params->client_fd, &st) < 0)
		i_fatal("fstat(auth dest fd) failed: %m");
	req.ino = st.st_ino;

	buf = t_buffer_create(sizeof(req) + req.data_size);
	buffer_append(buf, &req, sizeof(req));
	buffer_append(buf, params->data, req.data_size);

	conn->fd = net_connect_unix(conn->path);
	if (conn->fd == -1 && errno == EAGAIN) {
		/* Couldn't connect to the socket immediately. This will add
		   a delay that causes hangs to the whole process, which won't
		   be obvious unless we log a warning. FIXME: The wait could
		   be asynchronous. */
		struct timeval start_time;

		io_loop_time_refresh();
		start_time = ioloop_timeval;
		conn->fd = net_connect_unix_with_retries(conn->path,
			SOCKET_CONNECT_RETRY_MSECS);
		io_loop_time_refresh();
		if (conn->fd != -1 &&
		    ioloop_time - auth->last_connect_warning >=
		    SOCKET_CONNECT_RETRY_WARNING_INTERVAL_SECS) {
			i_warning("net_connect_unix(%s) succeeded only after retrying - "
				  "took %lld us", conn->path,
				  timeval_diff_usecs(&ioloop_timeval, &start_time));
			auth->last_connect_warning = ioloop_time;
		}
	}
	if (conn->fd == -1) {
		conn_error(conn, "net_connect_unix(%s) failed: %m%s",
			conn->path, errno != EAGAIN ? "" :
			" - http://wiki2.dovecot.org/SocketUnavailable");
		master_auth_connection_deinit(&conn);
		return;
	}

	ret = fd_send(conn->fd, params->client_fd, buf->data, buf->used);
	if (ret < 0) {
		conn_error(conn, "fd_send(fd=%d) failed: %m",
			   params->client_fd);
	} else if ((size_t)ret != buf->used) {
		conn_error(conn, "fd_send() sent only %d of %d bytes",
			   (int)ret, (int)buf->used);
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
	i_assert(hash_table_lookup(auth->connections, POINTER_CAST(req.tag)) == NULL);
	hash_table_insert(auth->connections, POINTER_CAST(req.tag), conn);
	*tag_r = req.tag;
}

void master_auth_request(struct master_auth *auth, int fd,
			 const struct master_auth_request *request,
			 const unsigned char *data,
			 master_auth_callback_t *callback,
			 void *context, unsigned int *tag_r)
{
	struct master_auth_request_params params;

	i_zero(&params);
	params.client_fd = fd;
	params.request = *request;
	params.data = data;

	master_auth_request_full(auth, &params, callback, context, tag_r);
}

void master_auth_request_abort(struct master_auth *auth, unsigned int tag)
{
        struct master_auth_connection *conn;

	conn = hash_table_lookup(auth->connections, POINTER_CAST(tag));
	if (conn == NULL)
		i_panic("master_auth_request_abort(): tag %u not found", tag);

	conn->callback = NULL;
}
