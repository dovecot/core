/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

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

struct master_auth {
	struct master_service *service;
	pool_t pool;

	int fd;
	struct io *io;

	unsigned int tag_counter;
	struct hash_table *requests;

	char buf[sizeof(struct master_auth_reply)];
	unsigned int buf_pos;

	/* linked list, node->context is the next pointer */
	struct master_auth_request_node *free_nodes;
};

struct master_auth_request_node {
	master_auth_callback_t *callback;
	void *context;
};

static struct master_auth_request_node aborted_node;

unsigned int master_auth_request(struct master_service *service, int fd,
				 const struct master_auth_request *request,
				 const unsigned char *data,
				 master_auth_callback_t *callback,
				 void *context)
{
	struct master_auth *auth = service->auth;
        struct master_auth_request_node *node;
	struct master_auth_request req;
	buffer_t *buf;
	struct stat st;
	ssize_t ret;

	i_assert(request->auth_pid != 0);

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

	ret = fd_send(auth->fd, fd, buf->data, buf->used);
	if (ret < 0)
		i_fatal("fd_send(%d) failed: %m", fd);
	if ((size_t)ret != buf->used) {
		i_fatal("fd_send() sent only %d of %d bytes",
			(int)ret, (int)buf->used);
	}

	if (auth->free_nodes == NULL)
		node = p_new(auth->pool, struct master_auth_request_node, 1);
	else {
		node = auth->free_nodes;
                auth->free_nodes = node->context;
	}
	node->callback = callback;
	node->context = context;

	hash_table_insert(auth->requests, POINTER_CAST(req.tag), node);
	return req.tag;
}

void master_auth_request_abort(struct master_service *service, unsigned int tag)
{
	struct master_auth *auth = service->auth;
        struct master_auth_request_node *node;

	node = hash_table_lookup(auth->requests, POINTER_CAST(tag));
	if (node == NULL)
		i_panic("master_auth_request_abort(): tag %u not found", tag);

	i_assert(node != &aborted_node);
	hash_table_update(auth->requests, POINTER_CAST(tag), &aborted_node);

	node->callback = NULL;
	node->context = auth->free_nodes;
	auth->free_nodes = node;
}

static void
master_notify_have_more_avail_processes(struct master_service *service,
					bool have_more)
{
	if (!have_more) {
		/* make sure we're listening for more connections */
		master_service_io_listeners_add(service);
	}
	service->call_avail_overflow = !have_more;
}

static void request_handle(struct master_auth *auth,
			   struct master_auth_reply *reply)
{
        struct master_auth_request_node *node;

	if (reply->tag == 0) {
		/* notification from master */
		master_notify_have_more_avail_processes(auth->service,
							reply->status == 0);
		return;
	}

	node = hash_table_lookup(auth->requests, POINTER_CAST(reply->tag));
	if (node == NULL)
		i_error("Master sent reply with unknown tag %u", reply->tag);

	if (node != &aborted_node) {
		node->callback(reply, node->context);

		/* the callback may have called master_auth_request_abort(),
		   which would have put the node to free_nodes list already */
		if (node->callback != NULL) {
			node->callback = NULL;
			node->context = auth->free_nodes;
			auth->free_nodes = node;
		}
	}

	hash_table_remove(auth->requests, POINTER_CAST(reply->tag));
}

static void master_auth_input(void *context)
{
	struct master_auth *auth = context;
	int ret;

	ret = net_receive(auth->fd, auth->buf + auth->buf_pos,
			  sizeof(auth->buf) - auth->buf_pos);
	if (ret < 0) {
		/* master died, kill all clients logging in */
                master_service_stop(auth->service);
		return;
	}

	auth->buf_pos += ret;
	if (auth->buf_pos < sizeof(auth->buf))
		return;

	/* reply is now read */
	request_handle(auth, (struct master_auth_reply *) auth->buf);
	auth->buf_pos = 0;
}

void master_auth_init(struct master_service *service)
{
	struct master_auth *auth;
	struct ip_addr ip;
	pool_t pool;

	i_assert(service->auth == NULL);

	if (getenv("MASTER_AUTH_FD") == NULL)
		i_fatal("auth_dest_service setting not set");

	if (net_getsockname(MASTER_AUTH_FD, &ip, NULL) < 0 ||
	    ip.family != AF_UNIX)
		i_fatal("MASTER_AUTH_FD not given");

	pool = pool_alloconly_create("master auth", 1024);
	auth = p_new(pool, struct master_auth, 1);
	auth->pool = pool;
	auth->service = service;
	auth->fd = MASTER_AUTH_FD;
	auth->requests = hash_table_create(default_pool, pool, 0, NULL, NULL);
	auth->io = io_add(auth->fd, IO_READ, master_auth_input, auth);

	service->auth = auth;
}

void master_auth_deinit(struct master_service *service)
{
	struct master_auth *auth = service->auth;

	i_assert(service->auth != NULL);

	hash_table_destroy(&auth->requests);
	if (auth->io != NULL)
		io_remove(&auth->io);
	if (close(auth->fd) < 0)
		i_fatal("close(master auth) failed: %m");
	pool_unref(&auth->pool);
	service->auth = NULL;
}
