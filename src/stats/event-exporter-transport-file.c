/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "ioloop.h"
#include "str.h"
#include "eacces-error.h"
#include "ostream.h"
#include "ostream-unix.h"
#include "event-exporter.h"

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

struct exporter_file {
	struct exporter_file *next;
	char *fname;
	struct ostream *output;
	int fd;
	time_t last_error;
	unsigned int connect_timeout_msecs;
	bool unix_socket:1;
};

#define EXPORTER_LAST_ERROR_DELAY 60

static struct exporter_file *exporter_file_list_head = NULL;

static void exporter_file_close(struct exporter_file *node)
{
	if (o_stream_finish(node->output) < 0) {
		i_error("write(%s) failed: %s", node->fname,
			o_stream_get_error(node->output));
		node->last_error = ioloop_time;
	}
	o_stream_destroy(&node->output);
	i_close_fd(&node->fd);
}

static void exporter_file_destroy(struct exporter_file **_node)
{
	struct exporter_file *node = *_node;
	if (node == NULL)
		return;
	*_node = NULL;

	exporter_file_close(node);
	i_free(node->fname);
	i_free(node);
}

void event_export_transport_file_deinit(void)
{
	struct exporter_file *node, *next = exporter_file_list_head;
	exporter_file_list_head = NULL;
	while (next != NULL) {
		node = next;
		next = node->next;
		exporter_file_destroy(&node);
	}
}

static struct exporter_file *exporter_file_init(const struct exporter *exporter,
						bool unix_socket)
{
	struct exporter_file *node;
	node = i_new(struct exporter_file, 1);
	node->fname = i_strdup(t_strcut(exporter->transport_args, ' '));
	node->fd = -1;
	node->unix_socket = unix_socket;
	node->connect_timeout_msecs = exporter->transport_timeout;
	node->next = exporter_file_list_head;
	exporter_file_list_head = node;
	event_export_transport_assign_context(exporter, node);
	return node;
}

static void exporter_file_open_error(struct exporter_file *node, const char *func)
{
	if (errno != EACCES)
		i_error("%s(%s) failed: %m", func, node->fname);
	else
		i_error("%s", eacces_error_get_creating(func, node->fname));
	node->last_error = ioloop_time;
}

static bool exporter_file_open_unix(struct exporter_file *node)
{
	node->fd = net_connect_unix_with_retries(node->fname ,
						 node->connect_timeout_msecs);
	if (node->fd == -1) {
		if (ioloop_time - node->last_error > EXPORTER_LAST_ERROR_DELAY)
			exporter_file_open_error(node, "connect");
		return FALSE;
	}
	node->output = o_stream_create_unix(node->fd, IO_BLOCK_SIZE);
	return TRUE;
}

static bool exporter_file_open_plain(struct exporter_file *node)
{
	node->fd = open(node->fname, O_CREAT|O_APPEND|O_WRONLY, 0600);
	if (node->fd == -1) {
		if (ioloop_time - node->last_error > EXPORTER_LAST_ERROR_DELAY)
			exporter_file_open_error(node, "open");
		return FALSE;
	}
	node->output = o_stream_create_fd_file(node->fd, UOFF_T_MAX, FALSE);
	return TRUE;
}

static bool exporter_file_open(struct exporter_file *node)
{
	if (likely(node->output != NULL && !node->output->closed))
		return TRUE;
	o_stream_destroy(&node->output);
	i_close_fd(&node->fd);
	if (node->unix_socket) {
		if (!exporter_file_open_unix(node))
			return FALSE;
	} else if (!exporter_file_open_plain(node))
		return FALSE;
	o_stream_set_name(node->output, node->fname);
	return TRUE;
}

static void event_export_transport_file_write(struct exporter_file *node,
					      const buffer_t *buf)
{
	const struct const_iovec vec[] = {
		{ .iov_base = buf->data, .iov_len = buf->used },
		{ .iov_base = "\n", .iov_len = 1 }
	};
	if (o_stream_sendv(node->output, vec, N_ELEMENTS(vec)) < 0) {
		if (ioloop_time - node->last_error > EXPORTER_LAST_ERROR_DELAY) {
			i_error("write(%s): %s", o_stream_get_name(node->output),
				o_stream_get_error(node->output));
			node->last_error = ioloop_time;
		}
		o_stream_close(node->output);
	}
}

void event_export_transport_file(const struct exporter *exporter,
				 const buffer_t *buf)
{
	struct exporter_file *node = exporter->transport_context;
	if (node == NULL)
		node = exporter_file_init(exporter, FALSE);
	if (!exporter_file_open(node))
		return;
	event_export_transport_file_write(node, buf);
}

void event_export_transport_unix(const struct exporter *exporter,
				 const buffer_t *buf)
{
	struct exporter_file *node = exporter->transport_context;
	if (node == NULL)
		node = exporter_file_init(exporter, TRUE);
	if (!exporter_file_open(node))
		return;
	event_export_transport_file_write(node, buf);
}
