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

#include <unistd.h>

#define MAX_OUTBUF_SIZE (1024*50)

static struct auth_master_reply failure_reply =
{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

struct auth_listener {
	struct auth_master_connection *master;
	int client_listener;
	int fd;
	char *path;
	struct io *io;
};

struct master_userdb_request {
	struct auth_master_connection *conn;
	unsigned int tag;
};

static void master_output(void *context);
static void auth_master_connection_close(struct auth_master_connection *conn);
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
				    sizeof(reply) + 256);
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

	ret = o_stream_send(conn->output, reply, reply_size);
	if (ret < 0) {
		/* master died, kill ourself too */
		auth_master_connection_close(conn);
		return;
	}
	i_assert((size_t)ret == reply_size);

	if (o_stream_get_buffer_used_size(conn->output) >= MAX_OUTBUF_SIZE) {
		/* buffer full, stop accepting more input */
		if (conn->io != NULL) {
			io_remove(conn->io);
			conn->io = NULL;
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
		userdb->lookup(auth_request, userdb_callback,
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
                auth_master_connection_close(conn);
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

static void master_output(void *context)
{
	struct auth_master_connection *conn = context;
	int ret;

	if ((ret = o_stream_flush(conn->output)) < 0) {
		/* transmit error, probably master died */
		auth_master_connection_close(conn);
		return;
	}

	if (o_stream_get_buffer_used_size(conn->output) <= MAX_OUTBUF_SIZE/2) {
		/* allow input again */
		conn->io = io_add(conn->fd, IO_READ, master_input, conn);
	}
}

static void master_get_handshake_reply(struct auth_master_connection *master)
{
	struct mech_module_list *list;
	buffer_t *buf;
	struct auth_client_handshake_reply reply;
	struct auth_client_handshake_mech_desc mech_desc;
	uint32_t mech_desc_offset;

	memset(&reply, 0, sizeof(reply));
	memset(&mech_desc, 0, sizeof(mech_desc));

	reply.server_pid = master->pid;

	buf = buffer_create_dynamic(default_pool, 128);

	for (list = mech_modules; list != NULL; list = list->next)
		reply.mech_count++;
	buffer_set_used_size(buf, sizeof(reply) +
			     sizeof(mech_desc) * reply.mech_count);

	mech_desc_offset = sizeof(reply);
	for (list = mech_modules; list != NULL; list = list->next) {
		mech_desc.name_idx = buffer_get_used_size(buf) - sizeof(reply);
		mech_desc.plaintext = list->module.plaintext;
		mech_desc.advertise = list->module.advertise;

		memcpy(buffer_get_space_unsafe(buf, mech_desc_offset,
					       sizeof(mech_desc)),
		       &mech_desc, sizeof(mech_desc));
		buffer_append(buf, list->module.mech_name,
			      strlen(list->module.mech_name) + 1);

		mech_desc_offset += sizeof(mech_desc);
	}

	reply.data_size = buffer_get_used_size(buf) - sizeof(reply);
	memcpy(buffer_get_space_unsafe(buf, 0, sizeof(reply)),
	       &reply, sizeof(reply));

	master->handshake_reply = buffer_free_without_data(buf);
}

static void
auth_master_connection_set_fd(struct auth_master_connection *conn, int fd)
{
	if (conn->output != NULL)
		o_stream_unref(conn->output);
	if (conn->io != NULL)
		io_remove(conn->io);

	conn->output = o_stream_create_file(fd, default_pool,
					    (size_t)-1, FALSE);
	o_stream_set_flush_callback(conn->output, master_output, conn);
	conn->io = io_add(fd, IO_READ, master_input, conn);

	conn->fd = fd;
}

struct auth_master_connection *
auth_master_connection_create(int fd, unsigned int pid)
{
	struct auth_master_connection *conn;

	conn = i_new(struct auth_master_connection, 1);
	conn->refcount = 1;
	conn->pid = pid;
	conn->fd = fd;
	conn->listeners_buf = buffer_create_dynamic(default_pool, 64);
	if (fd != -1)
                auth_master_connection_set_fd(conn, fd);
	master_get_handshake_reply(conn);
	return conn;
}

void auth_master_connection_send_handshake(struct auth_master_connection *conn)
{
	struct auth_master_handshake_reply reply;

	/* just a note to master that we're ok. if we die before, it means
	   we're broken and a simple restart most likely won't help. */
	if (conn->output != NULL) {
		memset(&reply, 0, sizeof(reply));
		reply.server_pid = conn->pid;
		if (o_stream_send(conn->output, &reply, sizeof(reply)) < 0)
                        auth_master_connection_close(conn);
	}
}

static void auth_master_connection_close(struct auth_master_connection *conn)
{
	if (!standalone)
		io_loop_stop(ioloop);

	if (close(conn->fd) < 0)
		i_error("close(): %m");
	conn->fd = -1;

	o_stream_close(conn->output);
	conn->output = NULL;

	if (conn->io != NULL) {
		io_remove(conn->io);
		conn->io = NULL;
	}
}

void auth_master_connection_destroy(struct auth_master_connection *conn)
{
	struct auth_listener **l;
	size_t i, size;

	if (conn->destroyed)
		return;
	conn->destroyed = TRUE;

	auth_client_connections_deinit(conn);

	if (conn->fd != -1)
		auth_master_connection_close(conn);

	l = buffer_get_modifyable_data(conn->listeners_buf, &size);
	size /= sizeof(*l);
	for (i = 0; i < size; i++) {
		net_disconnect(l[i]->fd);
		io_remove(l[i]->io);
		if (l[i]->path != NULL) {
			(void)unlink(l[i]->path);
			i_free(l[i]->path);
		}
		i_free(l[i]);
	}
	buffer_free(conn->listeners_buf);
	conn->listeners_buf = NULL;

	auth_master_connection_unref(conn);
}

static int auth_master_connection_unref(struct auth_master_connection *conn)
{
	if (--conn->refcount > 0)
		return TRUE;

	if (conn->output != NULL)
		o_stream_unref(conn->output);
	i_free(conn->handshake_reply);
	i_free(conn);
	return FALSE;
}

static void auth_accept(void *context)
{
	struct auth_listener *l = context;
	int fd;

	fd = net_accept(l->fd, NULL, NULL);
	if (fd < 0) {
		if (fd < -1)
			i_fatal("accept() failed: %m");
	} else {
		net_set_nonblock(fd, TRUE);
		if (l->client_listener)
			(void)auth_client_connection_create(l->master, fd);
		else {
			/* we'll just replace the previous master.. */
			auth_master_connection_set_fd(l->master, fd);
                        auth_master_connection_send_handshake(l->master);
		}
	}
}

void auth_master_connection_add_listener(struct auth_master_connection *conn,
					 int fd, const char *path, int client)
{
	struct auth_listener *l;

	l = i_new(struct auth_listener, 1);
	l->master = conn;
	l->client_listener = client;
	l->fd = fd;
	l->path = i_strdup(path);
	l->io = io_add(fd, IO_READ, auth_accept, l);

	buffer_append(conn->listeners_buf, &l, sizeof(l));
}
