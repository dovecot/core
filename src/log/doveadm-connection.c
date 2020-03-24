/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "master-service.h"
#include "log-error-buffer.h"
#include "doveadm-connection.h"

#include <unistd.h>

struct doveadm_connection {
	struct log_error_buffer *errorbuf;

	int fd;
	struct ostream *output;
};

static void doveadm_connection_destroy(struct doveadm_connection **_conn);

static int doveadm_connection_send_errors(struct doveadm_connection *conn)
{
	struct log_error_buffer_iter *iter;
	const struct log_error *error;
	string_t *str = t_str_new(256);
	int ret = 0;

	iter = log_error_buffer_iter_init(conn->errorbuf);
	while ((error = log_error_buffer_iter_next(iter)) != NULL) {
		str_truncate(str, 0);
		str_printfa(str, "%s\t%ld\t",
			    failure_log_type_names[error->type],
			    (long)error->timestamp);
		str_append_tabescaped(str, error->prefix);
		str_append_c(str, '\t');
		str_append_tabescaped(str, error->text);
		str_append_c(str, '\n');
		if (o_stream_send(conn->output,
				  str_data(str), str_len(str)) < 0) {
			ret = -1;
			break;
		}
	}
	log_error_buffer_iter_deinit(&iter);
	return ret;
}

static int doveadm_output(struct doveadm_connection *conn)
{
	if (o_stream_flush(conn->output) != 0) {
		/* error / finished */
		doveadm_connection_destroy(&conn);
	}
	return 1;
}

void doveadm_connection_create(struct log_error_buffer *errorbuf, int fd)
{
	struct doveadm_connection *conn;

	conn = i_new(struct doveadm_connection, 1);
	conn->errorbuf = errorbuf;
	conn->fd = fd;
	conn->output = o_stream_create_fd(conn->fd, (size_t)-1);
	if (doveadm_connection_send_errors(conn) < 0)
		doveadm_connection_destroy(&conn);
	else {
		o_stream_set_flush_callback(conn->output, doveadm_output, conn);
		o_stream_set_flush_pending(conn->output, TRUE);
	}
}

static void doveadm_connection_destroy(struct doveadm_connection **_conn)
{
	struct doveadm_connection *conn = *_conn;

	*_conn = NULL;

	o_stream_destroy(&conn->output);
	if (close(conn->fd) < 0)
		i_error("close(doveadm connection) failed: %m");
	i_free(conn);

	master_service_client_connection_destroyed(master_service);
}
