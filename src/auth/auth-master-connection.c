/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "buffer.h"
#include "hash.h"
#include "str.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "network.h"
#include "mech.h"
#include "userdb.h"
#include "auth-client-connection.h"
#include "auth-master-connection.h"

#include <unistd.h>
#include <stdlib.h>

#define MAX_INBUF_SIZE 1024
#define MAX_OUTBUF_SIZE (1024*50)

struct auth_listener {
	struct auth_master_connection *master;
	int client_listener;
	int fd;
	char *path;
	struct io *io;
};

struct master_userdb_request {
	struct auth_master_connection *conn;
	unsigned int id;
};

static void master_output(void *context);
static void auth_master_connection_close(struct auth_master_connection *conn);
static int auth_master_connection_unref(struct auth_master_connection *conn);

static void master_send(struct auth_master_connection *conn,
			const char *fmt, ...) __attr_format__(2, 3);
static void master_send(struct auth_master_connection *conn,
			const char *fmt, ...)
{
	va_list args;
	string_t *str;

	t_push();
	va_start(args, fmt);
	str = t_str_new(256);
	str_vprintfa(str, fmt, args);
	str_append_c(str, '\n');
	(void)o_stream_send(conn->output, str_data(str), str_len(str));
	va_end(args);
	t_pop();
}

static void append_user_reply(string_t *str, const struct user_data *user)
{
	const char *p;

	str_append(str, user->virtual_user);
	str_printfa(str, "%s\tuid=%s\tgid=%s", user->virtual_user,
		    dec2str(user->uid), dec2str(user->gid));

	if (user->system_user != NULL)
		str_printfa(str, "\tsystem_user=%s", user->system_user);
	if (user->mail != NULL)
		str_printfa(str, "\tmail=%s", user->mail);

	p = user->home != NULL ? strstr(user->home, "/./") : NULL;
	if (p == NULL) {
		if (user->home != NULL)
			str_printfa(str, "\thome=%s", user->home);
	} else {
		/* wu-ftpd like <chroot>/./<home> */
		str_printfa(str, "\thome=%s\tchroot=%s",
			    p + 3, t_strdup_until(user->home, p));
	}
}

static void userdb_callback(const struct user_data *user, void *context)
{
	struct master_userdb_request *master_request = context;
	string_t *str;

	if (auth_master_connection_unref(master_request->conn)) {
		if (user == NULL) {
			master_send(master_request->conn, "NOTFOUND\t%u",
				    master_request->id);
		} else {
			str = t_str_new(256);
			str_printfa(str, "USER\t%u\t", master_request->id);
			append_user_reply(str,  user);
			master_send(master_request->conn, "%s", str_c(str));
		}
	}
	i_free(master_request);
}

static int
master_input_request(struct auth_master_connection *conn, const char *args)
{
	struct auth_client_connection *client_conn;
	struct master_userdb_request *master_request;
	struct auth_request *request;
	const char *const *list;
	unsigned int id, client_pid, client_id;

	/* <id> <client-pid> <client-id> */
	list = t_strsplit(args, "\t");
	if (list[0] == NULL || list[1] == NULL || list[2] == NULL) {
		i_error("BUG: Master sent broken REQUEST");
		return FALSE;
	}

	id = (unsigned int)strtoul(list[0], NULL, 10);
	client_pid = (unsigned int)strtoul(list[1], NULL, 10);
	client_id = (unsigned int)strtoul(list[2], NULL, 10);

	client_conn = auth_client_connection_lookup(conn, client_pid);
	request = client_conn == NULL ? NULL :
		hash_lookup(client_conn->auth_requests,
			    POINTER_CAST(client_id));

	if (request == NULL) {
		if (verbose) {
			i_info("Master request %u.%u not found",
			       client_pid, client_id);
		}
		master_send(conn, "NOTFOUND\t%u", id);
	} else {
		master_request = i_new(struct master_userdb_request, 1);
		master_request->conn = conn;
		master_request->id = id;

		conn->refcount++;
		userdb->lookup(request, userdb_callback, master_request);

		/* the auth request is finished, we don't need it anymore */
		auth_request_destroy(request);
	}
	return TRUE;
}

static int
master_input_die(struct auth_master_connection *conn)
{
	return TRUE;
}

static void master_input(void *context)
{
	struct auth_master_connection *conn = context;
 	char *line;
	int ret;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
                auth_master_connection_close(conn);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Master sent us more than %d bytes",
			(int)MAX_INBUF_SIZE);
                auth_master_connection_close(conn);
		return;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		t_push();
		if (strncmp(line, "REQUEST\t", 8) == 0)
			ret = master_input_request(conn, line + 8);
		else if (strcmp(line, "DIE") == 0)
			ret = master_input_die(conn);
		else {
			/* ignore unknown command */
			ret = TRUE;
		}
		t_pop();

		if (!ret) {
			auth_master_connection_close(conn);
			return;
		}
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

static void
auth_master_connection_set_fd(struct auth_master_connection *conn, int fd)
{
	if (conn->input != NULL)
		i_stream_unref(conn->input);
	if (conn->output != NULL)
		o_stream_unref(conn->output);
	if (conn->io != NULL)
		io_remove(conn->io);

	conn->input = i_stream_create_file(fd, default_pool,
					   MAX_INBUF_SIZE, FALSE);
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
	return conn;
}

void auth_master_connection_send_handshake(struct auth_master_connection *conn)
{
	/* just a note to master that we're ok. if we die before, it means
	   we're broken and a simple restart most likely won't help. */
	if (conn->output != NULL)
		master_send(conn, "SPID\t%u", conn->pid);
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
