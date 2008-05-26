/* Copyright (c) 2005-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "auth-master-listener.h"
#include "auth-master-connection.h"
#include "auth-client-connection.h"

#include <unistd.h>

struct auth_master_listener_socket {
	struct auth_master_listener *listener;

	enum listener_type type;
	int fd;
	char *path;
	struct io *io;
};

static ARRAY_DEFINE(master_listeners, struct auth_master_listener *);

struct auth_master_listener *auth_master_listener_create(struct auth *auth)
{
	struct auth_master_listener *listener;

	listener = i_new(struct auth_master_listener, 1);
	listener->auth = auth;
	listener->pid = (unsigned int)getpid();
	i_array_init(&listener->sockets, 16);
	i_array_init(&listener->masters, 16);
	i_array_init(&listener->clients, 16);
	auth_client_connections_init(listener);

	array_append(&master_listeners, &listener, 1);
	return listener;
}

static void
auth_master_listener_socket_free(struct auth_master_listener_socket *s)
{
	if (s->path != NULL) {
		(void)unlink(s->path);
		i_free(s->path);
	}

	io_remove(&s->io);
	net_disconnect(s->fd);
	i_free(s);
}

void auth_master_listener_destroy(struct auth_master_listener *listener)
{
	struct auth_master_listener *const *listeners;
	struct auth_master_listener_socket **sockets;
	struct auth_master_connection **masters;
	struct auth_client_connection **clients;
	unsigned int i, count;

	listeners = array_get(&master_listeners, &count);
	for (i = 0; i < count; i++) {
		if (listeners[i] == listener) {
			array_delete(&master_listeners, i, 1);
			break;
		}
	}

	sockets = array_get_modifiable(&listener->sockets, &count);
	for (i = count; i > 0; i--)
		auth_master_listener_socket_free(sockets[i-1]);

	masters = array_get_modifiable(&listener->masters, &count);
	for (i = count; i > 0; i--)
		auth_master_connection_destroy(&masters[i-1]);

	clients = array_get_modifiable(&listener->clients, &count);
	for (i = count; i > 0; i--)
		auth_client_connection_destroy(&clients[i-1]);

        auth_client_connections_deinit(listener);
	array_free(&listener->sockets);
	array_free(&listener->masters);
	array_free(&listener->clients);
	i_free(listener);
}

static void auth_master_listener_accept(struct auth_master_listener_socket *s)
{
	struct auth_master_connection *master;
	int fd;

	fd = net_accept(s->fd, NULL, NULL);
	if (fd < 0) {
		if (fd < -1)
			i_error("accept(type %d) failed: %m", s->type);
	} else {
		net_set_nonblock(fd, TRUE);

		switch (s->type) {
		case LISTENER_CLIENT:
			(void)auth_client_connection_create(s->listener, fd);
			break;
		case LISTENER_MASTER:
			/* we'll just replace the previous master.. */
			master = auth_master_connection_create(s->listener, fd);
			auth_master_connection_send_handshake(master);
			break;
		}
	}
}

void auth_master_listener_add(struct auth_master_listener *listener,
			      int fd, const char *path,
			      enum listener_type type)
{
	struct auth_master_listener_socket *s;

	s = i_new(struct auth_master_listener_socket, 1);
	s->listener = listener;
	s->fd = fd;
	s->path = i_strdup(path);
	s->type = type;
	s->io = io_add(fd, IO_READ, auth_master_listener_accept, s);

	array_append(&listener->sockets, &s, 1);
}

static void
auth_master_listener_send_handshakes(struct auth_master_listener *listener)
{
        struct auth_master_connection *const *masters;
	unsigned int i, count;

	masters = array_get(&listener->masters, &count);
	for (i = 0; i < count; i++)
		auth_master_connection_send_handshake(masters[i]);
}

void auth_master_listeners_send_handshake(void)
{
        struct auth_master_listener *const *listeners;
	unsigned int i, count;

	listeners = array_get(&master_listeners, &count);
	for (i = 0; i < count; i++)
		auth_master_listener_send_handshakes(listeners[i]);
}

bool auth_master_listeners_masters_left(void)
{
        struct auth_master_listener *const *listeners;
	unsigned int i, count;

	listeners = array_get(&master_listeners, &count);
	for (i = 0; i < count; i++) {
		if (array_count(&listeners[i]->masters) > 0)
			return TRUE;
	}
	return FALSE;
}

void auth_master_listeners_init(void)
{
	i_array_init(&master_listeners, 2);
}

void auth_master_listeners_deinit(void)
{
        struct auth_master_listener **listeners;
	unsigned int i, count;

	listeners = array_get_modifiable(&master_listeners, &count);
	for (i = count; i > 0; i--)
		auth_master_listener_destroy(listeners[i-1]);
	array_free(&master_listeners);
}
