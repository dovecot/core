/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "ostream.h"
#include "network.h"
#include "cookie.h"
#include "master.h"

#define MAX_OUTBUF_SIZE (10 * sizeof(struct auth_cookie_reply_data))

static struct auth_cookie_reply_data failure_reply;

static struct ostream *output;
static struct io *io_master;

static unsigned int master_pos;
static char master_buf[sizeof(struct auth_cookie_request_data)];

static void master_handle_request(struct auth_cookie_request_data *request,
				  int fd __attr_unused__)
{
	struct cookie_data *cookie;
        struct auth_cookie_reply_data *reply, temp_reply;

	cookie = cookie_lookup_and_remove(request->login_pid, request->cookie);
	if (cookie == NULL)
		reply = &failure_reply;
	else {
		if (cookie->auth_fill_reply(cookie, &temp_reply))
			reply = &temp_reply;
		else
			reply = &failure_reply;
		cookie->free(cookie);
	}

	reply->id = request->id;
	switch (o_stream_send(output, reply, sizeof(*reply))) {
	case -2:
		i_fatal("Master transmit buffer full, aborting");
	case -1:
		/* master died, kill ourself too */
		io_loop_stop(ioloop);
		break;
	}
}

static void master_input(void *context __attr_unused__, int fd,
			 struct io *io __attr_unused__)
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
	master_handle_request((struct auth_cookie_request_data *) master_buf,
			      fd);
	master_pos = 0;
}

void master_init(void)
{
	memset(&failure_reply, 0, sizeof(failure_reply));

	master_pos = 0;
	output = o_stream_create_file(MASTER_SOCKET_FD, default_pool,
				      MAX_OUTBUF_SIZE, IO_PRIORITY_DEFAULT,
				      FALSE);
	io_master = io_add(MASTER_SOCKET_FD, IO_READ, master_input, NULL);

	/* just a note to master that we're ok. if we die before,
	   master should shutdown itself. */
	o_stream_send(output, "O", 1);
}

void master_deinit(void)
{
	o_stream_unref(output);
	io_remove(io_master);
}
