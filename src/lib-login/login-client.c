/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "fdpass.h"
#include "buffer.h"
#include "hash.h"
#include "str.h"
#include "time-util.h"
#include "master-service-private.h"
#include "login-client.h"

#include <unistd.h>
#include <sys/stat.h>

#define SOCKET_CONNECT_RETRY_MSECS 500
#define SOCKET_CONNECT_RETRY_WARNING_INTERVAL_SECS 2
#define LOGIN_CLIENT_REQUEST_TIMEOUT_MSECS (MASTER_LOGIN_TIMEOUT_SECS/2*1000)

struct login_connection {
	struct login_client_list *list;
	unsigned int tag;

	unsigned int client_pid, auth_id;
	struct ip_addr remote_ip;
	struct timeval create_time;

	char *path;
	int fd;
	struct io *io;
	struct timeout *to;

	char buf[sizeof(struct login_reply)];
	unsigned int buf_pos;

	login_client_request_callback_t *callback;
	void *context;
	struct event *event;
};

struct login_client_list {
	struct master_service *service;
	pool_t pool;

	const char *default_path;
	time_t last_connect_warning;

	unsigned int tag_counter;
	HASH_TABLE(void *, struct login_connection *) connections;
};

struct login_client_list *
login_client_list_init(struct master_service *service, const char *path)
{
	struct login_client_list *list;
	pool_t pool;

	pool = pool_alloconly_create("login connection list", 1024);
	list = p_new(pool, struct login_client_list, 1);
	list->pool = pool;
	list->service = service;
	list->default_path = p_strdup(pool, path);
	hash_table_create_direct(&list->connections, pool, 0);
	return list;
}

static void
login_connection_deinit(struct login_connection **_conn)
{
	struct login_connection *conn = *_conn;

	*_conn = NULL;

	if (conn->tag != 0)
		hash_table_remove(conn->list->connections,
				  POINTER_CAST(conn->tag));

	if (conn->callback != NULL)
		conn->callback(NULL, conn->context);

	timeout_remove(&conn->to);
	io_remove(&conn->io);
	i_close_fd(&conn->fd);
	event_unref(&conn->event);
	i_free(conn->path);
	i_free(conn);
}

static const char *
login_connection_event_callback(struct login_connection *conn,
				enum log_type log_type ATTR_UNUSED,
				const char *message)
{
	string_t *str = t_str_new(128);
	str_printfa(str, "%s (client-pid=%u, client-id=%u, rip=%s, created %u msecs ago, received %u/%zu bytes)",
		message, conn->client_pid, conn->auth_id,
		net_ip2addr(&conn->remote_ip),
		timeval_diff_msecs(&ioloop_timeval, &conn->create_time),
		conn->buf_pos, sizeof(conn->buf_pos));
	return str_c(str);
}

void login_client_list_deinit(struct login_client_list **_list)
{
	struct login_client_list *list = *_list;
	struct hash_iterate_context *iter;
	void *key;
	struct login_connection *conn;

	*_list = NULL;

	iter = hash_table_iterate_init(list->connections);
	while (hash_table_iterate(iter, list->connections, &key, &conn)) {
		conn->tag = 0;
		login_connection_deinit(&conn);
	}
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&list->connections);
	pool_unref(&list->pool);
}

static void login_connection_input(struct login_connection *conn)
{
	const struct login_reply *reply;
	int ret;

	ret = read(conn->fd, conn->buf + conn->buf_pos,
		   sizeof(conn->buf) - conn->buf_pos);
	if (ret <= 0) {
		if (ret == 0 || errno == ECONNRESET) {
			e_error(conn->event, "read() failed: Remote closed connection "
				"(destination service { process_limit } reached?)");
		} else {
			if (errno == EAGAIN)
				return;
			e_error(conn->event, "read() failed: %m");
		}
		login_connection_deinit(&conn);
		return;
	}

	conn->buf_pos += ret;
	if (conn->buf_pos < sizeof(conn->buf))
		return;

	/* reply is now read */
	reply = (const void *)conn->buf;
	conn->buf_pos = 0;

	if (conn->tag != reply->tag)
		e_error(conn->event, "Received reply with unknown tag %u", reply->tag);
	else if (conn->callback == NULL) {
		/* request aborted */
	} else {
		conn->callback(reply, conn->context);
		conn->callback = NULL;
	}
	login_connection_deinit(&conn);
}

static void login_connection_timeout(struct login_connection *conn)
{
	e_error(conn->event, "Login request timed out");
	login_connection_deinit(&conn);
}

void login_client_request(struct login_client_list *list,
			  const struct login_client_request_params *params,
			  login_client_request_callback_t *callback,
			  void *context, unsigned int *tag_r)
{
        struct login_connection *conn;
	struct login_request req;
	buffer_t *buf;
	struct stat st;
	ssize_t ret;

	i_assert(params->request.client_pid != 0);
	i_assert(params->request.auth_pid != 0);

	conn = i_new(struct login_connection, 1);
	conn->list = list;
	conn->create_time = ioloop_timeval;
	conn->callback = callback;
	conn->context = context;
	conn->path = params->socket_path != NULL ?
		i_strdup(params->socket_path) : i_strdup(list->default_path);

	conn->event = event_create(NULL);
	event_set_append_log_prefix(conn->event, t_strdup_printf("master(%s): ", conn->path));
	event_set_log_message_callback(conn->event, login_connection_event_callback, conn);

	req = params->request;
	req.tag = ++list->tag_counter;
	if (req.tag == 0)
		req.tag = ++list->tag_counter;

	conn->client_pid = req.client_pid;
	conn->auth_id = req.auth_id;
	conn->remote_ip = req.remote_ip;

	if (fstat(params->client_fd, &st) < 0)
		i_fatal("fstat(login dest fd) failed: %m");
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
		    ioloop_time - list->last_connect_warning >=
		    SOCKET_CONNECT_RETRY_WARNING_INTERVAL_SECS) {
			e_warning(conn->event,
				  "net_connect_unix(%s) succeeded only after retrying - "
				  "took %lld us", conn->path,
				  timeval_diff_usecs(&ioloop_timeval, &start_time));
			list->last_connect_warning = ioloop_time;
		}
	}
	if (conn->fd == -1) {
		e_error(conn->event, "net_connect_unix(%s) failed: %m%s",
			conn->path, errno != EAGAIN ? "" :
			" - https://doc.dovecot.org/admin_manual/errors/socket_unavailable/");
		login_connection_deinit(&conn);
		return;
	}

	ret = fd_send(conn->fd, params->client_fd, buf->data, buf->used);
	if (ret < 0) {
		e_error(conn->event, "fd_send(fd=%d) failed: %m",
			   params->client_fd);
	} else if ((size_t)ret != buf->used) {
		e_error(conn->event, "fd_send() sent only %d of %d bytes",
			   (int)ret, (int)buf->used);
		ret = -1;
	}
	if (ret < 0) {
		login_connection_deinit(&conn);
		return;
	}

	conn->tag = req.tag;
	conn->to = timeout_add(LOGIN_CLIENT_REQUEST_TIMEOUT_MSECS,
			       login_connection_timeout, conn);
	conn->io = io_add(conn->fd, IO_READ,
			  login_connection_input, conn);
	i_assert(hash_table_lookup(list->connections, POINTER_CAST(req.tag)) == NULL);
	hash_table_insert(list->connections, POINTER_CAST(req.tag), conn);
	*tag_r = req.tag;
}

void login_client_request_abort(struct login_client_list *list,
				unsigned int tag)
{
        struct login_connection *conn;

	conn = hash_table_lookup(list->connections, POINTER_CAST(tag));
	if (conn == NULL)
		i_panic("login_client_request_abort(): tag %u not found", tag);

	conn->callback = NULL;
}
