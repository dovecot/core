/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "ostream.h"
#include "fdpass.h"
#include "fd-close-on-exec.h"
#include "llist.h"
#include "master-login.h"
#include "master-login-auth.h"

#include <sys/stat.h>
#include <unistd.h>

struct master_login_connection {
	struct master_login_connection *prev, *next;

	struct master_login *login;
	int fd;
	struct io *io;
	struct ostream *output;
};

struct master_login {
	master_login_callback_t *callback;
	struct master_login_connection *conns;
	struct master_login_auth *auth;
};

static void master_login_conn_deinit(struct master_login_connection **_conn);

struct master_login *
master_login_init(const char *auth_socket_path,
		  master_login_callback_t *callback)
{
	struct master_login *login;

	login = i_new(struct master_login, 1);
	login->callback = callback;
	login->auth = master_login_auth_init(auth_socket_path);
	return login;
}

void master_login_deinit(struct master_login **_login)
{
	struct master_login *login = *_login;

	*_login = NULL;

	master_login_auth_deinit(&login->auth);
	while (login->conns != NULL) {
		struct master_login_connection *conn = login->conns;

		master_login_conn_deinit(&conn);
	}
	i_free(login);
}

static int
master_login_conn_read_request(struct master_login_connection *conn,
			       struct master_auth_request *req_r,
			       unsigned char data[MASTER_AUTH_MAX_DATA_SIZE],
			       int *client_fd_r)
{
	struct stat st;
	ssize_t ret;

	*client_fd_r = -1;

	ret = fd_read(conn->fd, req_r, sizeof(*req_r), client_fd_r);
	if (ret != sizeof(*req_r)) {
		if (ret == 0) {
			/* disconnected */
		} else if (ret > 0) {
			/* request wasn't fully read */
			i_error("fd_read() partial input (%d/%d)",
				(int)ret, (int)sizeof(*req_r));
		} else {
			if (errno == EAGAIN)
				return 0;

			i_error("fd_read() failed: %m");
		}
		return -1;
	}

	if (req_r->data_size != 0) {
		if (req_r->data_size > MASTER_AUTH_MAX_DATA_SIZE) {
			i_error("Too large auth data_size sent");
			return -1;
		}
		/* @UNSAFE */
		ret = read(conn->fd, data, req_r->data_size);
		if (ret != (ssize_t)req_r->data_size) {
			if (ret == 0) {
				/* disconnected */
			} else if (ret > 0) {
				/* request wasn't fully read */
				i_error("Data read partially %d/%u",
					(int)ret, req_r->data_size);
			} else {
				i_error("read(data) failed: %m");
			}
			return -1;
		}
	}

	if (*client_fd_r == -1) {
		i_error("Auth request missing a file descriptor");
		return -1;
	}

	if (fstat(*client_fd_r, &st) < 0) {
		i_error("fstat(fd_recv client) failed: %m");
		return -1;
	}
	if (st.st_ino != req_r->ino) {
		i_error("Auth request inode mismatch: %s != %s",
			dec2str(st.st_ino), dec2str(req_r->ino));
		return -1;
	}
	return 1;
}

static void
master_login_auth_callback(const char *const *auth_args, void *context)
{
	struct master_login_client *client = context;
	struct master_auth_reply reply;

	memset(&reply, 0, sizeof(reply));
	reply.tag = client->auth_req.tag;
	reply.status = auth_args != NULL ? MASTER_AUTH_STATUS_OK :
		MASTER_AUTH_STATUS_INTERNAL_ERROR;
	reply.mail_pid = getpid();
	o_stream_send(client->conn->output, &reply, sizeof(reply));

	if (auth_args == NULL) {
		if (close(client->fd) < 0)
			i_error("close(fd_recv client) failed: %m");
		i_free(client);
		return;
	}

	client->conn->login->callback(client, auth_args[0], auth_args+1);
	i_free(client);
}

static void master_login_conn_input(struct master_login_connection *conn)
{
	struct master_auth_request req;
	struct master_login_client *client;
	unsigned char data[MASTER_AUTH_MAX_DATA_SIZE];
	int ret, client_fd;

	ret = master_login_conn_read_request(conn, &req, data, &client_fd);
	if (ret <= 0) {
		if (ret < 0)
			master_login_conn_deinit(&conn);
		if (client_fd != -1) {
			if (close(client_fd) < 0)
				i_error("close(fd_recv client) failed: %m");
		}
		return;
	}
	fd_close_on_exec(client_fd, TRUE);

	/* @UNSAFE: we have a request. do userdb lookup for it. */
	client = i_malloc(sizeof(struct master_login_client) + req.data_size);
	client->conn = conn;
	client->fd = client_fd;
	client->auth_req = req;
	memcpy(client->data, data, req.data_size);

	master_login_auth_request(conn->login->auth, &req,
				  master_login_auth_callback, client);
}

void master_login_add(struct master_login *login, int fd)
{
	struct master_login_connection *conn;

	conn = i_new(struct master_login_connection, 1);
	conn->login = login;
	conn->fd = fd;
	conn->io = io_add(conn->fd, IO_READ, master_login_conn_input, conn);
	conn->output = o_stream_create_fd(fd, (size_t)-1, FALSE);

	DLLIST_PREPEND(&login->conns, conn);
}

static void master_login_conn_deinit(struct master_login_connection **_conn)
{
	struct master_login_connection *conn = *_conn;

	*_conn = NULL;

	DLLIST_REMOVE(&conn->login->conns, conn);

	io_remove(&conn->io);
	o_stream_unref(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(master login) failed: %m");
	i_free(conn);
}
