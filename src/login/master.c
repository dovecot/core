/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "fdpass.h"
#include "master.h"

typedef struct _WaitingRequest WaitingRequest;

struct _WaitingRequest {
	WaitingRequest *next;

	int id;
	MasterCallback callback;
	void *context;
};

static IO io_master;
static WaitingRequest *requests, **next_request;

static unsigned int master_pos;
static char master_buf[sizeof(MasterReply)];

static void push_request(int id, MasterCallback callback, void *context)
{
	WaitingRequest *req;

	req = i_new(WaitingRequest, 1);
	req->id = id;
	req->callback = callback;
	req->context = context;

	*next_request = req;
	next_request = &req->next;
}

static void pop_request(MasterReply *reply)
{
	WaitingRequest *req;

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

void master_request_imap(int fd, int auth_process, const char *login_tag,
			 unsigned char cookie[AUTH_COOKIE_SIZE],
			 MasterCallback callback, void *context)
{
	MasterRequest req;

	i_assert(fd > 1);

	memset(&req, 0, sizeof(req));
	req.id = fd;
	req.auth_process = auth_process;
	memcpy(req.cookie, cookie, AUTH_COOKIE_SIZE);

	if (strlen(login_tag) >= sizeof(req.login_tag))
		strcpy(req.login_tag, "*");
	else
		strcpy(req.login_tag, login_tag);

	if (fd_send(LOGIN_MASTER_SOCKET_FD,
		    fd, &req, sizeof(req)) != sizeof(req))
		i_fatal("fd_send() failed: %m");

	push_request(req.id, callback, context);
}

static void master_input(void *context __attr_unused__, int fd,
			 IO io __attr_unused__)
{
	int ret;

	ret = net_receive(fd, master_buf + master_pos,
			  sizeof(master_buf) - master_pos);
	if (ret < 0) {
		/* master died, kill ourself too */
		io_loop_stop(ioloop);
		return;
	}

	master_pos += ret;
	if (master_pos < sizeof(master_buf))
		return;

	/* reply is now read */
	pop_request((MasterReply *) master_buf);
	master_pos = 0;
}

void master_init(void)
{
	requests = NULL;
	next_request = &requests;

        master_pos = 0;
	io_master = io_add(LOGIN_MASTER_SOCKET_FD, IO_READ, master_input, NULL);
}

void master_deinit(void)
{
	WaitingRequest *next;

	while (requests != NULL) {
		next = requests->next;
		i_free(requests);
		requests = next;
	}
	io_remove(io_master);
}
