/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "buffer.h"
#include "hash.h"
#include "ioloop.h"
#include "ostream.h"
#include "network.h"
#include "mech.h"
#include "userdb.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"

#define MAX_OUTBUF_SIZE (1024*50)

static struct auth_master_reply failure_reply =
{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

struct master_userdb_request {
	struct auth_master_connection *conn;
	unsigned int tag;
};

static int auth_master_connection_unref(struct auth_master_connection *conn);

static size_t reply_add(buffer_t *buf, const char *str)
{
	size_t index;

	if (str == NULL || *str == '\0')
		return (size_t)-1;

	index = buffer_get_used_size(buf) - sizeof(struct auth_master_reply);
	buffer_append(buf, str, strlen(str)+1);
	return index;
}

static struct auth_master_reply *
fill_reply(const struct user_data *user, size_t *reply_size)
{
	struct auth_master_reply reply, *reply_p;
	buffer_t *buf;
	char *p;

	buf = buffer_create_dynamic(pool_datastack_create(),
				    sizeof(reply) + 256, (size_t)-1);
	memset(&reply, 0, sizeof(reply));
	buffer_append(buf, &reply, sizeof(reply));

	reply.success = TRUE;

	reply.uid = user->uid;
	reply.gid = user->gid;

	reply.system_user_idx = reply_add(buf, user->system_user);
	reply.virtual_user_idx = reply_add(buf, user->virtual_user);
	reply.mail_idx = reply_add(buf, user->mail);

	p = user->home != NULL ? strstr(user->home, "/./") : NULL;
	if (p == NULL) {
		reply.home_idx = reply_add(buf, user->home);
		reply.chroot_idx = reply_add(buf, NULL);
	} else {
		/* wu-ftpd like <chroot>/./<home> */
		reply.chroot_idx =
			reply_add(buf, t_strdup_until(user->home, p));
		reply.home_idx = reply_add(buf, p + 3);
	}

	*reply_size = buffer_get_used_size(buf);
	reply.data_size = *reply_size - sizeof(reply);

	reply_p = buffer_get_space_unsafe(buf, 0, sizeof(reply));
	*reply_p = reply;

	return reply_p;
}

static void master_send_reply(struct auth_master_connection *conn,
			      struct auth_master_reply *reply,
			      size_t reply_size, unsigned int tag)
{
	ssize_t ret;

	reply->tag = tag;
	for (;;) {
		ret = o_stream_send(conn->output, reply, reply_size);
		if (ret < 0) {
			/* master died, kill ourself too */
			io_loop_stop(ioloop);
			break;
		}

		if ((size_t)ret == reply_size)
			break;

		/* buffer full, we have to block */
		i_warning("Master transmit buffer full, blocking..");
		if (o_stream_flush(conn->output) < 0) {
			/* transmit error, probably master died */
			io_loop_stop(ioloop);
			break;
		}
	}
}

static void userdb_callback(struct user_data *user, void *context)
{
	struct master_userdb_request *master_request = context;
	struct auth_master_reply *reply;
	size_t reply_size;

	if (auth_master_connection_unref(master_request->conn)) {
		if (user == NULL) {
			master_send_reply(master_request->conn, &failure_reply,
					  sizeof(failure_reply),
					  master_request->tag);
		} else {
			reply = fill_reply(user, &reply_size);
			master_send_reply(master_request->conn, reply,
					  reply_size, master_request->tag);
		}
	}
	i_free(master_request);
}

static void master_handle_request(struct auth_master_connection *conn,
				  struct auth_master_request *request)
{
	struct auth_client_connection *client_conn;
	struct auth_request *auth_request;
	struct master_userdb_request *master_request;

	client_conn = auth_client_connection_lookup(conn, request->client_pid);
	auth_request = client_conn == NULL ? NULL :
		hash_lookup(client_conn->auth_requests,
			    POINTER_CAST(request->id));

	if (auth_request == NULL) {
		if (verbose) {
			i_info("Master request %u.%u not found",
			       request->client_pid, request->id);
		}
		master_send_reply(conn, &failure_reply, sizeof(failure_reply),
				  request->tag);
	} else {
		master_request = i_new(struct master_userdb_request, 1);
		master_request->conn = conn;
		master_request->tag = request->tag;

		conn->refcount++;
		userdb->lookup(auth_request->user, userdb_callback,
			       master_request);

		/* the auth request is finished, we don't need it anymore */
		mech_request_free(auth_request, request->id);
	}
}

static void master_input(void *context)
{
	struct auth_master_connection *conn = context;
	int ret;

	ret = net_receive(conn->fd,
			  conn->request_buf + conn->request_pos,
			  sizeof(conn->request_buf) - conn->request_pos);
	if (ret < 0) {
		/* master died, kill ourself too */
		io_loop_stop(ioloop);
		return;
	}

	conn->request_pos += ret;
	if (conn->request_pos >= sizeof(conn->request_buf)) {
		/* reply is now read */
		master_handle_request(conn, (struct auth_master_request *)
				      conn->request_buf);
		conn->request_pos = 0;
	}
}

struct auth_master_connection *
auth_master_connection_new(int fd, unsigned int pid)
{
	struct auth_master_connection *conn;

	conn = i_new(struct auth_master_connection, 1);
	conn->refcount = 1;
	conn->pid = pid;
	conn->fd = fd;
	conn->output = o_stream_create_file(MASTER_SOCKET_FD, default_pool,
					    MAX_OUTBUF_SIZE, FALSE);
	conn->io = io_add(MASTER_SOCKET_FD, IO_READ, master_input, conn);

	/* just a note to master that we're ok. if we die before,
	   master should shutdown itself. */
	o_stream_send(conn->output, "O", 1);
	return conn;
}

void auth_master_connection_free(struct auth_master_connection *conn)
{
	if (conn->fd == -1)
		return;

	conn->fd = -1;
	o_stream_close(conn->output);

	io_remove(conn->io);
	conn->io = NULL;

	auth_master_connection_unref(conn);
}

static int auth_master_connection_unref(struct auth_master_connection *conn)
{
	if (--conn->refcount > 0)
		return TRUE;

	o_stream_unref(conn->output);
	i_free(conn);
	return FALSE;
}
