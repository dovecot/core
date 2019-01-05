/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "ostream.h"
#include "master-service.h"

#include "auth-master-private.h"

void auth_request_lookup_abort(struct auth_master_connection *conn)
{
	io_loop_stop(conn->ioloop);
	conn->aborted = TRUE;
}

int auth_master_run_cmd_pre(struct auth_master_connection *conn,
			    const char *cmd)
{
	auth_master_set_io(conn);

	if (!conn->connected) {
		if (auth_master_connect(conn) < 0) {
			auth_master_unset_io(conn);
			return -1;
		}
		i_assert(conn->connected);
		connection_input_resume(&conn->conn);
	}

	o_stream_cork(conn->conn.output);
	if (!conn->sent_handshake) {
		const struct connection_settings *set = &conn->conn.list->set;

		o_stream_nsend_str(conn->conn.output,
			t_strdup_printf("VERSION\t%u\t%u\n",
					set->major_version,
					set->minor_version));
		conn->sent_handshake = TRUE;
	}

	o_stream_nsend_str(conn->conn.output, cmd);
	o_stream_uncork(conn->conn.output);

	if (o_stream_flush(conn->conn.output) < 0) {
		e_error(conn->event, "write(auth socket) failed: %s",
			o_stream_get_error(conn->conn.output));
		auth_master_unset_io(conn);
		auth_master_disconnect(conn);
		return -1;
	}
	return 0;
}

int auth_master_run_cmd_post(struct auth_master_connection *conn)
{
	auth_master_unset_io(conn);
	if (conn->aborted) {
		conn->aborted = FALSE;
		auth_master_disconnect(conn);
		return -1;
	}
	return 0;
}

static void auth_master_stop(struct auth_master_connection *conn)
{
	if (master_service_is_killed(master_service)) {
		auth_request_lookup_abort(conn);
		io_loop_stop(conn->ioloop);
	}
}

int auth_master_run_cmd(struct auth_master_connection *conn, const char *cmd)
{
	if (auth_master_run_cmd_pre(conn, cmd) < 0)
		return -1;
	/* add stop handler */
	struct timeout *to = timeout_add_short(100, auth_master_stop, conn);
	io_loop_run(conn->ioloop);
	timeout_remove(&to);
	return auth_master_run_cmd_post(conn);
}

unsigned int auth_master_next_request_id(struct auth_master_connection *conn)
{
	if (++conn->request_counter == 0) {
		/* avoid zero */
		conn->request_counter++;
	}
	return conn->request_counter;
}
