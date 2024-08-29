/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "ioloop.h"
#include "str.h"
#include "eacces-error.h"
#include "ostream.h"
#include "ostream-unix.h"
#include "settings.h"
#include "settings-parser.h"
#include "event-exporter.h"

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

struct file_event_exporter {
	struct event_exporter exporter;

	char *fname;
	struct ostream *output;
	int fd;
	time_t last_error;
	unsigned int connect_timeout_msecs;
	bool unix_socket:1;
};

#define EXPORTER_LAST_ERROR_DELAY 60

struct event_exporter_file_settings {
	pool_t pool;

	const char *event_exporter_file_path;
	const char *event_exporter_unix_path;
	unsigned int event_exporter_unix_connect_timeout_msecs;
};

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name, struct event_exporter_file_settings)
#undef DEF_MSECS
#define DEF_MSECS(type, name) \
	SETTING_DEFINE_STRUCT_##type(#name, name##_msecs, struct event_exporter_file_settings)

static const struct setting_define event_exporter_file_setting_defines[] = {
	DEF(STR, event_exporter_file_path),
	DEF(STR, event_exporter_unix_path),
	DEF_MSECS(TIME_MSECS, event_exporter_unix_connect_timeout),

	SETTING_DEFINE_LIST_END
};

static const struct event_exporter_file_settings event_exporter_file_default_settings = {
	.event_exporter_file_path = "",
	.event_exporter_unix_path = "",
	.event_exporter_unix_connect_timeout_msecs = 250,
};

const struct setting_parser_info event_exporter_file_setting_parser_info = {
	.name = "event_exporter_file",

	.defines = event_exporter_file_setting_defines,
	.defaults = &event_exporter_file_default_settings,

	.struct_size = sizeof(struct event_exporter_file_settings),
	.pool_offset1 = 1 + offsetof(struct event_exporter_file_settings, pool),
};

static void exporter_file_close(struct file_event_exporter *node)
{
	if (node->fd == -1)
		return;
	if (o_stream_finish(node->output) < 0) {
		i_error("write(%s) failed: %s", node->fname,
			o_stream_get_error(node->output));
		node->last_error = ioloop_time;
	}
	o_stream_destroy(&node->output);
	i_close_fd(&node->fd);
}

static void event_exporter_file_deinit(struct event_exporter *_exporter)
{
	struct file_event_exporter *node =
		container_of(_exporter, struct file_event_exporter, exporter);

	exporter_file_close(node);
	i_free(node->fname);
}

static int
event_exporter_file_init_common(pool_t pool, struct event *event,
				bool unix_socket,
				struct event_exporter **exporter_r,
				const char **error_r)
{
	struct file_event_exporter *node =
		p_new(pool, struct file_event_exporter, 1);
	node->fd = -1;
	node->unix_socket = unix_socket;

	const struct event_exporter_file_settings *set;
	if (settings_get(event, &event_exporter_file_setting_parser_info, 0,
			 &set, error_r) < 0)
		return -1;

	if (unix_socket)
		node->fname = i_strdup(set->event_exporter_unix_path);
	else
		node->fname = i_strdup(set->event_exporter_file_path);
	node->connect_timeout_msecs = set->event_exporter_unix_connect_timeout_msecs;
	settings_free(set);

	*exporter_r = &node->exporter;
	return 0;
}

static int
event_exporter_file_init(pool_t pool, struct event *event,
			 struct event_exporter **exporter_r,
			 const char **error_r)
{
	return event_exporter_file_init_common(pool, event, FALSE,
					       exporter_r, error_r);
}

static int
event_exporter_unix_init(pool_t pool, struct event *event,
			 struct event_exporter **exporter_r,
			 const char **error_r)
{
	return event_exporter_file_init_common(pool, event, TRUE,
					       exporter_r, error_r);
}

static void exporter_file_open_error(struct file_event_exporter *node, const char *func)
{
	if (errno != EACCES)
		i_error("%s(%s) failed: %m", func, node->fname);
	else
		i_error("%s", eacces_error_get_creating(func, node->fname));
	node->last_error = ioloop_time;
}

static bool exporter_file_open_unix(struct file_event_exporter *node)
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

static bool exporter_file_open_plain(struct file_event_exporter *node)
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

static bool exporter_file_open(struct file_event_exporter *node)
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

static void event_exporter_file_write(struct file_event_exporter *node,
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

static void
event_exporter_file_send(struct event_exporter *_exporter, const buffer_t *buf)
{
	struct file_event_exporter *node =
		container_of(_exporter, struct file_event_exporter, exporter);
	if (!exporter_file_open(node))
		return;
	event_exporter_file_write(node, buf);
}

static void event_exporter_file_reopen(struct event_exporter *_exporter)
{
	struct file_event_exporter *node =
		container_of(_exporter, struct file_event_exporter, exporter);
	exporter_file_close(node);
}

const struct event_exporter_transport event_exporter_transport_file = {
	.name = "file",

	.init = event_exporter_file_init,
	.send = event_exporter_file_send,
	.reopen = event_exporter_file_reopen,
};

const struct event_exporter_transport event_exporter_transport_unix = {
	.name = "unix",

	.init = event_exporter_unix_init,
	.deinit = event_exporter_file_deinit,
	.send = event_exporter_file_send,
};
