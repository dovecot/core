/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "ostream.h"
#include "fdpass.h"
#include "llist.h"
#include "str.h"
#include "strescape.h"
#include "time-util.h"
#include "process-title.h"
#include "master-service-private.h"
#include "login-server.h"
#include "login-server-auth.h"

#include <sys/stat.h>
#include <unistd.h>

#define login_server_conn_is_closed(conn) \
	((conn)->fd == -1)
#define login_server_conn_has_requests(conn) \
	((conn)->refcount > 1)

struct login_server_postlogin {
	struct login_server_request *request;

	int fd;
	struct timeval create_time;
	struct io *io;
	struct timeout *to;
	string_t *input;
	char *username;
	char *socket_path;
};

struct login_server {
	struct master_service *service;
	login_server_callback_t *callback;
	login_server_failure_callback_t *failure_callback;
	struct login_server_connection *conns;
	struct login_server_auth *auth;
	char *postlogin_socket_path;
	unsigned int postlogin_timeout_secs;

	bool update_proctitle:1;
	bool stopping:1;
};

static void login_server_conn_close(struct login_server_connection *conn);
static void login_server_conn_unref(struct login_server_connection **_conn);

static void login_server_stop_new_connections(void *context)
{
	struct login_server *server = context;

	login_server_stop(server);
}

static void login_server_proctitle_refresh(struct login_server *server)
{
	if (!server->update_proctitle)
		return;

	/* This function assumes that client_limit=1. With a higher limit
	   it just returns the first client's state, which isn't too bad
	   either. */
	if (server->conns == NULL)
		process_title_set("[idling]");
	else if (server->conns->requests == NULL)
		process_title_set("[waiting on client]");
	else if (server->conns->requests->postlogin_request == NULL)
		process_title_set("[auth lookup]");
	else
		process_title_set("[post-login script]");
}

struct login_server *
login_server_init(struct master_service *service,
		  const struct login_server_settings *set)
{
	struct login_server *server;

	i_assert(set->postlogin_socket_path == NULL ||
		 set->postlogin_timeout_secs > 0);

	server = i_new(struct login_server, 1);
	server->service = service;
	server->callback = set->callback;
	server->failure_callback = set->failure_callback;
	server->auth = login_server_auth_init(set->auth_socket_path,
					      set->request_auth_token);
	server->postlogin_socket_path = i_strdup(set->postlogin_socket_path);
	server->postlogin_timeout_secs = set->postlogin_timeout_secs;
	server->update_proctitle = set->update_proctitle;

	master_service_add_stop_new_connections_callback(service,
		login_server_stop_new_connections, server);
	return server;
}

void login_server_deinit(struct login_server **_server)
{
	struct login_server *server = *_server;
	struct login_server_connection *conn, *next;

	*_server = NULL;

	master_service_remove_stop_new_connections_callback(server->service,
		login_server_stop_new_connections, server);

	login_server_auth_deinit(&server->auth);
	for (conn = server->conns; conn != NULL; conn = next) {
		next = conn->next;
		if (!login_server_conn_is_closed(conn)) {
			login_server_conn_close(conn);
			login_server_conn_unref(&conn);
		} else {
			/* FIXME: auth request or post-login script is still
			   running - we don't currently support aborting them */
			i_assert(conn->requests != NULL);
		}
	}
	i_free(server->postlogin_socket_path);
	i_free(server);
}

static const char *
login_server_event_log_callback(struct login_server_connection *conn,
			        enum log_type log_type ATTR_UNUSED,
			        const char *message)
{
	string_t *str = t_str_new(128);
	str_printfa(str, "%s (connection created %d msecs ago", message,
		timeval_diff_msecs(&ioloop_timeval, &conn->create_time));
	if (conn->requests != NULL) {
		struct login_server_request *request = conn->requests;

		str_append(str, ", ");
		if (request->next != NULL)
			str_printfa(str, "%u requests, first ", conn->refcount-1);
		str_printfa(str, "request created %d msecs ago: ",
			    timeval_diff_msecs(&ioloop_timeval,
					       &request->create_time));
		str_printfa(str, "session=%s, rip=%s, auth_pid=%ld, "
			    "client-pid=%u, client-id=%u",
			    request->session_id,
			    net_ip2addr(&request->auth_req.remote_ip),
			    (long)request->auth_req.auth_pid,
			    request->auth_req.client_pid,
			    request->auth_req.auth_id);
		if (request->postlogin_request != NULL) {
			struct login_server_postlogin *pl =
				request->postlogin_request;
			str_printfa(str, ", post-login script %s started %d msecs ago",
				    pl->socket_path,
				    timeval_diff_msecs(&ioloop_timeval,
						       &pl->create_time));
		}
	}
	str_append(str, ")");
	return str_c(str);
}

static int
login_server_conn_read_request(struct login_server_connection *conn,
			       struct login_request *req_r,
			       unsigned char data[LOGIN_REQUEST_MAX_DATA_SIZE],
			       int *client_fd_r)
{
	struct stat st;
	ssize_t ret;

	*client_fd_r = -1;

	ret = fd_read(conn->fd, req_r, sizeof(*req_r), client_fd_r);
	if (ret != sizeof(*req_r)) {
		if (ret == 0) {
			/* disconnected */
			if (login_server_conn_has_requests(conn))
				e_error(conn->event,
					"Login client disconnected too early");
		} else if (ret > 0) {
			/* request wasn't fully read */
			e_error(conn->event, "fd_read() partial input (%d/%d)",
				   (int)ret, (int)sizeof(*req_r));
		} else {
			if (errno == EAGAIN)
				return 0;

			e_error(conn->event, "fd_read() failed: %m");
		}
		return -1;
	}

	if (req_r->data_size != 0) {
		if (req_r->data_size > LOGIN_REQUEST_MAX_DATA_SIZE) {
			e_error(conn->event, "Too large auth data_size sent");
			return -1;
		}
		/* @UNSAFE */
		ret = read(conn->fd, data, req_r->data_size);
		if (ret != (ssize_t)req_r->data_size) {
			if (ret == 0) {
				/* disconnected */
				if (login_server_conn_has_requests(conn)) {
					e_error(conn->event,
						"Login client disconnected too early "
						"(while reading data)");
				}
			} else if (ret > 0) {
				/* request wasn't fully read */
				e_error(conn->event, "Data read partially %d/%u",
					(int)ret, req_r->data_size);
			} else {
				e_error(conn->event, "read(data) failed: %m");
			}
			return -1;
		}
	}

	if (*client_fd_r == -1) {
		e_error(conn->event, "Auth request missing a file descriptor");
		return -1;
	}

	if (fstat(*client_fd_r, &st) < 0) {
		e_error(conn->event, "fstat(fd_read client) failed: %m");
		return -1;
	}
	if (st.st_ino != req_r->ino) {
		e_error(conn->event, "Auth request inode mismatch: %s != %s",
			   dec2str(st.st_ino), dec2str(req_r->ino));
		return -1;
	}
	return 1;
}

static void login_server_request_free(struct login_server_request **_request)
{
	struct login_server_request *request = *_request;

	*_request = NULL;
	if (request->fd != -1) {
		i_close_fd(&request->fd);
		/* this client failed (login callback wasn't called).
		   reset prefix to default. */
		i_set_failure_prefix("%s: ", request->conn->server->service->name);
	}

	/* FIXME: currently we create a separate connection for each request,
	   so close the connection after we're done with this request */
	if (!login_server_conn_is_closed(request->conn)) {
		i_assert(request->conn->refcount > 1);
		request->conn->refcount--;
	}
	DLLIST_REMOVE(&request->conn->requests, request);
	login_server_conn_unref(&request->conn);
	i_free(request->session_id);
	i_free(request);
}

static void login_server_auth_finish(struct login_server_request *request,
				     const char *const *auth_args)
{
	struct login_server *server = request->conn->server;
	struct master_service *service = server->service;
	bool close_sockets;

	close_sockets = service->master_status.available_count == 0 &&
		service->service_count_left == 1;

	request->conn->login_success = TRUE;
	server->callback(request, auth_args[0], auth_args+1);

	if (close_sockets) {
		/* we're dying as soon as this connection closes. */
		i_assert(login_server_auth_request_count(server->auth) == 0);
		login_server_auth_disconnect(server->auth);
	} else if (server->stopping) {
		/* try stopping again */
		login_server_stop(server);
	}

	request->fd = -1;
	login_server_request_free(&request);
}

static void login_server_postlogin_free(struct login_server_postlogin *pl)
{
	if (pl->request != NULL) {
		i_assert(pl->request->postlogin_request == pl);
		login_server_request_free(&pl->request);
	}
	timeout_remove(&pl->to);
	io_remove(&pl->io);
	i_close_fd(&pl->fd);
	str_free(&pl->input);
	i_free(pl->socket_path);
	i_free(pl->username);
	i_free(pl);
}

static void login_server_postlogin_input(struct login_server_postlogin *pl)
{
	struct login_server_connection *conn = pl->request->conn;
	char buf[1024];
	const char *const *auth_args;
	size_t len;
	ssize_t ret;
	int fd = -1;

	while ((ret = fd_read(pl->fd, buf, sizeof(buf), &fd)) > 0) {
		if (fd != -1) {
			/* post-login script replaced fd */
			i_close_fd(&pl->request->fd);
			pl->request->fd = fd;
		}
		str_append_data(pl->input, buf, ret);
	}

	len = str_len(pl->input);
	if (len > 0 && str_c(pl->input)[len-1] == '\n') {
		/* finished reading the input */
		str_truncate(pl->input, len-1);
	} else {
		if (ret < 0) {
			if (errno == EAGAIN)
				return;

			e_error(conn->event,
				"fd_read(%s) failed: %m", pl->socket_path);
		} else if (str_len(pl->input) > 0) {
			e_error(conn->event,  "fd_read(%s) failed: disconnected",
				pl->socket_path);
		} else {
			e_error(conn->event,
				"Post-login script denied access to user %s",
				pl->username);
		}
		login_server_postlogin_free(pl);
		return;
	}

	auth_args = t_strsplit_tabescaped(str_c(pl->input));
	pl->request->postlogin_request = NULL;
	login_server_auth_finish(pl->request, auth_args);

	pl->request = NULL;
	login_server_postlogin_free(pl);
}

static void login_server_postlogin_timeout(struct login_server_postlogin *pl)
{
	e_error(pl->request->conn->event,
		   "Timeout waiting for post-login script to finish, aborting");

	login_server_postlogin_free(pl);
}

static int login_server_postlogin(struct login_server_request *request,
				  const char *const *auth_args,
				  const char *socket_path)
{
	struct login_server *server = request->conn->server;
	struct login_server_postlogin *pl;
	string_t *str;
	unsigned int i;
	int fd;
	ssize_t ret;

	if (request->conn->server->update_proctitle)
		process_title_set("[post-login script]");

	fd = net_connect_unix_with_retries(socket_path, 1000);
	if (fd == -1) {
		e_error(request->conn->event, "net_connect_unix(%s) failed: %m%s",
			   socket_path, errno != EAGAIN ? "" :
			   " - https://doc.dovecot.org/admin_manual/errors/socket_unavailable/");
		return -1;
	}

	str = t_str_new(256);
	str_printfa(str, "VERSION\tscript-login\t1\t0\n"
		    "%s\t%s", net_ip2addr(&request->auth_req.local_ip),
		    net_ip2addr(&request->auth_req.remote_ip));
	for (i = 0; auth_args[i] != NULL; i++) {
		str_append_c(str, '\t');
		str_append_tabescaped(str, auth_args[i]);
	}
	str_append_c(str, '\n');
	ret = fd_send(fd, request->fd, str_data(str), str_len(str));
	if (ret != (ssize_t)str_len(str)) {
		if (ret < 0) {
			e_error(request->conn->event,
				"write(%s) failed: %m", socket_path);
		} else {
			e_error(request->conn->event,
				"write(%s) failed: partial write", socket_path);
		}
		i_close_fd(&fd);
		return -1;
	}
	net_set_nonblock(fd, TRUE);
	io_loop_time_refresh();

	pl = i_new(struct login_server_postlogin, 1);
	pl->request = request;
	pl->username = i_strdup(auth_args[0]);
	pl->socket_path = i_strdup(socket_path);
	pl->create_time = ioloop_timeval;
	pl->fd = fd;
	pl->io = io_add(fd, IO_READ, login_server_postlogin_input, pl);
	pl->to = timeout_add(server->postlogin_timeout_secs * 1000,
			     login_server_postlogin_timeout, pl);
	pl->input = str_new(default_pool, 512);

	i_assert(request->postlogin_request == NULL);
	request->postlogin_request = pl;

	login_server_proctitle_refresh(server);
	return 0;
}

static const char *
auth_args_find_postlogin_socket(const char *const *auth_args)
{
	const char *value;

	for (unsigned int i = 0; auth_args[i] != NULL; i++) {
		if (str_begins(auth_args[i], "postlogin=", &value))
			return value;
	}
	return NULL;
}

static void
login_server_auth_callback(const char *const *auth_args, const char *errormsg,
			   void *context)
{
	struct login_server_request *request = context;
	struct login_server_connection *conn = request->conn;
	struct login_reply reply;
	const char *postlogin_socket_path;

	i_assert(errormsg != NULL || auth_args != NULL);

	i_zero(&reply);
	reply.tag = request->auth_req.tag;
	reply.status = errormsg == NULL ? LOGIN_REPLY_STATUS_OK :
		LOGIN_REPLY_STATUS_INTERNAL_ERROR;
	reply.mail_pid = getpid();
	o_stream_nsend(conn->output, &reply, sizeof(reply));

	if (errormsg != NULL || auth_args[0] == NULL) {
		if (auth_args != NULL) {
			e_error(conn->event,
				"login client: Username missing from auth reply");
			errormsg = LOGIN_REQUEST_ERRMSG_INTERNAL_FAILURE;
		}
		conn->server->failure_callback(request, errormsg);
		login_server_request_free(&request);
		return;
	}
	i_set_failure_prefix("%s(%s): ", request->conn->server->service->name,
			     auth_args[0]);

	postlogin_socket_path = auth_args_find_postlogin_socket(auth_args);
	if (postlogin_socket_path == NULL)
		postlogin_socket_path = conn->server->postlogin_socket_path;

	if (postlogin_socket_path == NULL)
		login_server_auth_finish(request, auth_args);
	else {
		/* we've sent the reply. the connection is no longer needed,
		   so disconnect it (before login process disconnects us and
		   logs an error) */
		if (!login_server_conn_is_closed(conn)) {
			login_server_conn_close(conn);
			login_server_conn_unref(&conn);
		}

		/* execute post-login scripts before finishing auth */
		if (login_server_postlogin(request, auth_args,
					   postlogin_socket_path) < 0)
			login_server_request_free(&request);
	}
}

static void login_server_conn_input(struct login_server_connection *conn)
{
	struct login_request req;
	struct login_server_request *request;
	struct login_server *server = conn->server;
	unsigned char data[LOGIN_REQUEST_MAX_DATA_SIZE];
	size_t i, session_len = 0;
	int ret, client_fd;

	ret = login_server_conn_read_request(conn, &req, data, &client_fd);
	if (ret <= 0) {
		if (ret < 0) {
			login_server_conn_close(conn);
			login_server_conn_unref(&conn);
		}
		i_close_fd(&client_fd);
		return;
	}
	fd_close_on_exec(client_fd, TRUE);

	/* extract the session ID from the request data */
	for (i = 0; i < req.data_size; i++) {
		if (data[i] == '\0') {
			session_len = i++;
			break;
		}
	}
	io_loop_time_refresh();

	/* @UNSAFE: we have a request. do userdb lookup for it. */
	req.data_size -= i;
	request = i_malloc(MALLOC_ADD(sizeof(struct login_server_request),
				      req.data_size));
	request->create_time = ioloop_timeval;
	request->conn = conn;
	request->fd = client_fd;
	request->auth_req = req;
	request->session_id = i_strndup(data, session_len);
	memcpy(request->data, data+i, req.data_size);
	conn->refcount++;
	DLLIST_PREPEND(&conn->requests, request);
	login_server_proctitle_refresh(conn->server);

	login_server_auth_request(server->auth, &req,
				  login_server_auth_callback, request);
}

void login_server_add(struct login_server *server, int fd)
{
	struct login_server_connection *conn;

	conn = i_new(struct login_server_connection, 1);
	conn->refcount = 1;
	conn->server = server;
	conn->create_time = ioloop_timeval;
	conn->fd = fd;
	conn->io = io_add(conn->fd, IO_READ, login_server_conn_input, conn);
	conn->output = o_stream_create_fd(fd, SIZE_MAX);
	o_stream_set_no_error_handling(conn->output, TRUE);

	conn->event = event_create(server->service->event);
	event_set_log_message_callback(conn->event, login_server_event_log_callback, conn);

	DLLIST_PREPEND(&server->conns, conn);
	login_server_proctitle_refresh(server);

	/* NOTE: currently there's a separate connection for each request. */
}

static void login_server_conn_close(struct login_server_connection *conn)
{
	if (login_server_conn_is_closed(conn))
		return;

	io_remove(&conn->io);
	o_stream_close(conn->output);
	i_close_fd(&conn->fd);
}

static void login_server_conn_unref(struct login_server_connection **_conn)
{
	struct login_server_connection *conn = *_conn;

	i_assert(conn->refcount > 0);

	if (--conn->refcount > 0)
		return;

	*_conn = NULL;
	i_assert(conn->requests == NULL);
	login_server_conn_close(conn);
	o_stream_unref(&conn->output);

	DLLIST_REMOVE(&conn->server->conns, conn);
	login_server_proctitle_refresh(conn->server);

	if (!conn->login_success)
		master_service_client_connection_destroyed(conn->server->service);
	event_unref(&conn->event);
	i_free(conn);
}

void login_server_stop(struct login_server *server)
{
	server->stopping = TRUE;
	if (login_server_auth_request_count(server->auth) == 0)
		login_server_auth_disconnect(server->auth);
}
