/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "fdpass.h"
#include "master.h"
#include "client.h"

#include <unistd.h>

struct waiting_request {
	struct waiting_request *next;

	unsigned int id;
	MasterCallback callback;
	void *context;
};

static struct io *io_master;
static struct waiting_request *requests, **next_request;

static unsigned int master_pos;
static char master_buf[sizeof(struct master_reply)];

static void push_request(unsigned int id, MasterCallback callback,
			 void *context)
{
	struct waiting_request *req;

	req = i_new(struct waiting_request, 1);
	req->id = id;
	req->callback = callback;
	req->context = context;

	*next_request = req;
	next_request = &req->next;
}

static void pop_request(struct master_reply *reply)
{
	struct waiting_request *req;

	req = requests;
	if (req == NULL) {
		i_error("Master sent us unrequested reply for id %d",
			reply->id);
		return;
	}

	if (reply->id != req->id) {
		i_fatal("Master sent invalid id for reply "
			"(got %d, expecting %d)", reply->id, req->id);
	}

	req->callback(reply->result, req->context);

	requests = req->next;
	if (requests == NULL)
		next_request = &requests;

	i_free(req);
}

void master_request_imap(int fd, unsigned int auth_process,
			 const char *login_tag,
			 unsigned char cookie[AUTH_COOKIE_SIZE],
			 struct ip_addr *ip,
			 MasterCallback callback, void *context)
{
	struct master_request req;

	i_assert(fd > 1);

	memset(&req, 0, sizeof(req));
	req.id = fd;
	req.auth_process = auth_process;
	memcpy(&req.ip, ip, sizeof(struct ip_addr));
	memcpy(req.cookie, cookie, AUTH_COOKIE_SIZE);

	if (strocpy(req.login_tag, login_tag, sizeof(req.login_tag)) < 0)
		strocpy(req.login_tag, "*", sizeof(req.login_tag));

	if (fd_send(LOGIN_MASTER_SOCKET_FD,
		    fd, &req, sizeof(req)) != sizeof(req))
		i_fatal("fd_send() failed: %m");

	push_request(req.id, callback, context);
}

void master_notify_finished(void)
{
	struct master_request req;

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

static void master_input(void *context __attr_unused__, int fd,
			 struct io *io __attr_unused__)
{
	int ret;

	ret = net_receive(fd, master_buf + master_pos,
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
	pop_request((struct master_reply *) master_buf);
	master_pos = 0;
}

void master_init(void)
{
	main_ref();

	requests = NULL;
	next_request = &requests;

        master_pos = 0;
	io_master = io_add(LOGIN_MASTER_SOCKET_FD, IO_READ, master_input, NULL);
}

void master_deinit(void)
{
	struct waiting_request *next;

	while (requests != NULL) {
		next = requests->next;
		i_free(requests);
		requests = next;
	}

	if (io_master != NULL)
		io_remove(io_master);
}
