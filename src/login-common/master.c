/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "hash.h"
#include "ioloop.h"
#include "network.h"
#include "fdpass.h"
#include "master.h"
#include "client-common.h"

#include <unistd.h>

static struct io *io_master;
static struct hash_table *master_requests;

static unsigned int master_pos;
static char master_buf[sizeof(struct master_login_reply)];

static void request_handle(struct master_login_reply *reply)
{
	struct client *client;

	client = hash_lookup(master_requests, POINTER_CAST(reply->tag));
	if (client == NULL)
		i_fatal("Master sent reply with unknown tag %u", reply->tag);

	client->master_callback(client, reply->success);

	hash_remove(master_requests, POINTER_CAST(reply->tag));
}

void master_request_imap(struct client *client, master_callback_t *callback,
			 unsigned int auth_pid, unsigned int auth_id)
{
	struct master_login_request req;

	memset(&req, 0, sizeof(req));
	req.tag = client->fd;
	req.auth_pid = auth_pid;
	req.auth_id = auth_id;
	req.ip = client->ip;

	if (fd_send(LOGIN_MASTER_SOCKET_FD,
		    client->fd, &req, sizeof(req)) != sizeof(req))
		i_fatal("fd_send() failed: %m");

	client->master_callback = callback;
	hash_insert(master_requests, POINTER_CAST(req.tag), client);
}

void master_notify_finished(void)
{
	struct master_login_request req;

	if (io_master == NULL)
		return;

	memset(&req, 0, sizeof(req));

	/* sending -1 as fd does the notification */
	if (fd_send(LOGIN_MASTER_SOCKET_FD,
		    -1, &req, sizeof(req)) != sizeof(req))
		i_fatal("fd_send() failed: %m");
}

void master_close(void)
{
	if (io_master == NULL)
		return;

	clients_destroy_all();

	if (close(LOGIN_MASTER_SOCKET_FD) < 0)
		i_fatal("close(master) failed: %m");

	io_remove(io_master);
	io_master = NULL;

        main_close_listen();
	main_unref();
}

static void master_input(void *context __attr_unused__)
{
	int ret;

	ret = net_receive(LOGIN_MASTER_SOCKET_FD, master_buf + master_pos,
			  sizeof(master_buf) - master_pos);
	if (ret < 0) {
		/* master died, kill all clients logging in */
		master_close();
		return;
	}

	master_pos += ret;
	if (master_pos < sizeof(master_buf))
		return;

	/* reply is now read */
	request_handle((struct master_login_reply *) master_buf);
	master_pos = 0;
}

void master_init(void)
{
	main_ref();

	master_requests = hash_create(default_pool, default_pool,
				      0, NULL, NULL);

        master_pos = 0;
	io_master = io_add(LOGIN_MASTER_SOCKET_FD, IO_READ, master_input, NULL);

	/* just a note to master that we're ok. if we die before,
	   master should shutdown itself. */
        master_notify_finished();
}

void master_deinit(void)
{
	hash_destroy(master_requests);

	if (io_master != NULL)
		io_remove(io_master);
}
