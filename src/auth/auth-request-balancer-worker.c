/* Copyright (C) 2002-2005 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "safe-memset.h"
#include "auth-request-handler.h"
#include "auth-request-balancer.h"

#include <stdlib.h>
#include <unistd.h>

struct auth_balancer_worker {
	int fd;

	struct auth_request_handler *request_handler;

	struct io *io;
	struct istream *input;
	struct ostream *output;
};

static unsigned int next_uint(const char **line)
{
	const char *p, *value = *line;

	p = strchr(*line, '\t');
	if (p == NULL)
		*line += strlen(value);
	else {
		value = t_strdup_until(value, p);
		*line = p + 1;
	}
	return (unsigned int)strtoul(value, NULL, 10);
}

static char *balancer_socket_path;
static struct timeout *to_connect;

static void
auth_client_handle_line(struct auth_balancer_worker *worker, const char *line)
{
	struct auth_request_handler *rh = worker->request_handler;
	unsigned int connect_uid, client_pid, id;

	connect_uid = next_uint(&line);
	client_pid = next_uint(&line);

        auth_request_handler_set(rh, connect_uid, client_pid);

	if (strncmp(line, "AUTH\t", 5) == 0)
		(void)auth_request_handler_auth_begin(rh, line + 5);
	else if (strncmp(line, "CONT\t", 5) == 0)
		(void)auth_request_handler_auth_continue(rh, line + 5);
	else if (strncmp(line, "REQUEST\t", 8) == 0) {
		id = (unsigned int)strtoul(line + 8, NULL, 10);
		(void)auth_request_handler_master_request(rh, id, id);
	}
}

static void balancer_worker_input(void *context)
{
	struct auth_balancer_worker *worker = context;
	char *line;

	switch (i_stream_read(worker->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_request_balancer_worker_destroy(worker);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth balancer server sent us more than %d bytes",
			(int)AUTH_BALANCER_MAX_LINE_LENGTH);
		auth_request_balancer_worker_destroy(worker);
		return;
	}

	while ((line = i_stream_next_line(worker->input)) != NULL) {
		t_push();

		auth_client_handle_line(worker, line);
		safe_memset(line, 0, strlen(line));

		t_pop();
	}
}

static int balancer_worker_output(void *context)
{
	struct auth_balancer_worker *worker = context;

	if (o_stream_flush(worker->output) < 0) {
		auth_request_balancer_worker_destroy(worker);
		return 1;
	}

	/* FIXME: throttle control.. */
	return 1;
}

static void auth_callback(const char *reply, void *context)
{
	struct auth_balancer_worker *worker = context;
	struct const_iovec iov[2];

	if (reply == NULL) {
		/* request handler was destroyed */
		return;
	}

	iov[0].iov_base = reply;
	iov[0].iov_len = strlen(reply);
	iov[1].iov_base = "\n";
	iov[1].iov_len = 1;

	(void)o_stream_sendv(worker->output, iov, 2);
}

void auth_request_balancer_add_worker(struct auth *auth, int fd)
{
	struct auth_balancer_worker *worker;

	net_set_nonblock(fd, TRUE);

	worker = i_new(struct auth_balancer_worker, 1);
	worker->fd = fd;
	worker->input =
		i_stream_create_file(fd, default_pool,
				     AUTH_BALANCER_MAX_LINE_LENGTH, FALSE);
	worker->output =
		o_stream_create_file(fd, default_pool, (size_t)-1, FALSE);
	o_stream_set_flush_callback(worker->output, balancer_worker_output,
				    worker);
	worker->io = io_add(fd, IO_READ, balancer_worker_input, worker);

	worker->request_handler =
		auth_request_handler_create(auth, TRUE, auth_callback, worker,
					    auth_callback, worker);

	i_assert(auth->balancer_worker == NULL);
        auth->balancer_worker = worker;
}

void auth_request_balancer_worker_destroy(struct auth_balancer_worker *worker)
{
	io_loop_stop(ioloop);
	auth_request_handler_unref(worker->request_handler);

	if (worker->io != NULL)
		io_remove(worker->io);

	i_stream_unref(worker->input);
	o_stream_unref(worker->output);

	if (close(worker->fd) < 0)
		i_error("close(balancer) failed: %m");
	i_free(worker);
}

static int auth_request_balancer_connect(struct auth *auth)
{
	int fd;

	fd = net_connect_unix(balancer_socket_path);
	if (fd < 0) {
		if (errno != EAGAIN) {
			i_fatal("net_connect_unix(%s) failed: %m",
				balancer_socket_path);
		}
		/* busy */
		return FALSE;
	}

	auth_request_balancer_add_worker(auth, fd);
	return TRUE;
}

static void balancer_connect_timeout(void *context)
{
	struct auth *auth = context;

	if (auth_request_balancer_connect(auth)) {
		timeout_remove(to_connect);
		to_connect = NULL;
	}
}

void auth_request_balancer_worker_init(struct auth *auth)
{
	const char *name;

	name = getenv("AUTH_NAME");
	if (name == NULL) name = "auth";
	balancer_socket_path = i_strconcat(name, "-balancer", NULL);

	if (!auth_request_balancer_connect(auth)) {
		/* couldn't connect to balancer yet, it's probably still
		   starting. try again later. */
		to_connect = timeout_add(1000, balancer_connect_timeout, auth);
	}
}

void auth_request_balancer_worker_deinit(void)
{
	if (to_connect != NULL)
		timeout_remove(to_connect);
	i_free(balancer_socket_path);
}
