/* Copyright (C) 2002-2005 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "buffer.h"
#include "hash.h"
#include "istream.h"
#include "ostream.h"
#include "auth-request-balancer.h"

#include <stdlib.h>
#include <unistd.h>

struct auth_balancer_child {
	unsigned int id;
	int fd;

	struct io *io;
	struct istream *input;
	struct ostream *output;
};

static buffer_t *balancer_children;
static struct hash_table *balancer_handlers;
static unsigned int balancer_next_idx = 0;

static void
auth_request_balancer_remove_child(struct auth_balancer_child *child);

static void balancer_input(void *context)
{
	struct auth_balancer_child *child = context;
	struct auth_request_handler *handler;
	const char *line, *id_str;
	unsigned int id;

	switch (i_stream_read(child->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_request_balancer_remove_child(child);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth balancer child sent us more than %d bytes",
			(int)AUTH_BALANCER_MAX_LINE_LENGTH);
		auth_request_balancer_remove_child(child);
		return;
	}

	while ((line = i_stream_next_line(child->input)) != NULL) {
		id_str = line;
		line = strchr(line, '\t');
		if (line == NULL)
			continue;

		t_push();
		id = (unsigned int)strtoul(t_strcut(id_str, '\t'), NULL, 10);
		handler = hash_lookup(balancer_handlers, POINTER_CAST(id));
		t_pop();

		if (handler != NULL) {
			auth_request_handler_balancer_reply(handler,
							    line + 1);
		}
	}
}

static int balancer_output(void *context)
{
	struct auth_balancer_child *child = context;

	if (o_stream_flush(child->output) < 0) {
		auth_request_balancer_remove_child(child);
		return 1;
	}

	/* FIXME: throttle control.. */
	return 1;
}

void auth_request_balancer_add_child(int fd)
{
	static unsigned int balancer_id_counter = 0;
	struct auth_balancer_child *child;

	net_set_nonblock(fd, TRUE);

	child = i_new(struct auth_balancer_child, 1);
	child->id = ++balancer_id_counter;
	child->fd = fd;
	child->input =
		i_stream_create_file(fd, default_pool,
				     AUTH_BALANCER_MAX_LINE_LENGTH, FALSE);
	child->output =
		o_stream_create_file(fd, default_pool, (size_t)-1, FALSE);
	o_stream_set_flush_callback(child->output, balancer_output, child);
	child->io = io_add(fd, IO_READ, balancer_input, child);

	buffer_append(balancer_children, &child, sizeof(child));
}

static void
auth_request_balancer_remove_child(struct auth_balancer_child *child)
{
	struct auth_balancer_child **children;
	size_t i, size;

	children = buffer_get_modifyable_data(balancer_children, &size);
	size /= sizeof(*children);

	for (i = 0; i < size; i++) {
		if (children[i] == child) {
			buffer_delete(balancer_children,
				      i * sizeof(child), sizeof(child));
			break;
		}
	}
	i_assert(i != size);

	if (child->io != NULL)
		io_remove(child->io);

	i_stream_unref(child->input);
	o_stream_unref(child->output);

	if (close(child->fd) < 0)
		i_error("close(balancer) failed: %m");
	i_free(child);
}

static void balancer_send(struct auth_balancer_child *child, const char *line)
{
	struct const_iovec iov[2];

	iov[0].iov_base = line;
	iov[0].iov_len = strlen(line);
	iov[1].iov_base = "\n";
	iov[1].iov_len = 1;

	(void)o_stream_sendv(child->output, iov, 2);
	/* FIXME: throttle control */
}

unsigned int auth_request_balancer_send(const char *line)
{
	struct auth_balancer_child **child, *min_child;
	size_t size, used_size, min_size;
	unsigned int i, start;

	child = buffer_get_modifyable_data(balancer_children, &size);
	size /= sizeof(*child);

	i_assert(size > 0);

	start = i = balancer_next_idx % size;
	balancer_next_idx++;

	min_size = (size_t)-1;
	min_child = NULL;
	do {
		used_size = o_stream_get_buffer_used_size(child[i]->output);
		if (used_size == 0) {
			/* nothing in output buffer, use this */
			balancer_send(child[i], line);
			return child[i]->id;
		}
		if (used_size < min_size) {
			min_size = used_size;
			min_child = child[i];
		}
	} while (++i != start);

	/* min_child has the smallest amount of data in output buffer */
	balancer_send(min_child, line);
	return min_child->id;
}

void auth_request_balancer_send_to(unsigned int id, const char *line)
{
	struct auth_balancer_child **child;
	size_t i, size;

	child = buffer_get_modifyable_data(balancer_children, &size);
	size /= sizeof(*child);

	for (i = 0; i < size; i++) {
		if (child[i]->id == id) {
			balancer_send(child[i], line);
			return;
		}
	}

	// FIXME: ?
}

void auth_request_balancer_add_handler(struct auth_request_handler *handler,
				       unsigned int connect_uid)
{
	hash_insert(balancer_handlers, POINTER_CAST(connect_uid), handler);
}

void auth_request_balancer_remove_handler(unsigned int connect_uid)
{
	hash_remove(balancer_handlers, POINTER_CAST(connect_uid));
}

void auth_request_balancer_child_init(void)
{
	balancer_children = buffer_create_dynamic(default_pool, 32);
	balancer_handlers =
		hash_create(default_pool, default_pool, 0, NULL, NULL);
}

void auth_request_balancer_child_deinit(void)
{
	while (balancer_children->used > 0) {
		struct auth_balancer_child **child;

		child = buffer_get_modifyable_data(balancer_children, NULL);
		auth_request_balancer_remove_child(*child);
	}
	buffer_free(balancer_children);
	hash_destroy(balancer_handlers);
}
