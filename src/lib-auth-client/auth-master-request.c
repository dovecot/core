/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "ostream.h"
#include "master-service.h"

#include "auth-master-private.h"

void auth_request_lookup_abort(struct auth_master_connection *conn)
{
	if (conn->ioloop != NULL)
		io_loop_stop(conn->ioloop);
	conn->aborted = TRUE;
}

static void
auth_master_request_send(struct auth_master_connection *conn,
			 const char *cmd, unsigned int id,
			 const unsigned char *args, size_t args_size)
{
	const char *id_str = dec2str(id);

	const struct const_iovec iov[] = {
		{ cmd, strlen(cmd), },
		{ "\t", 1 },
		{ id_str, strlen(id_str), },
		{ "\t", args_size > 0 ? 1 : 0 },
		{ args, args_size },
		{ "\r\n", 2 },
	};
	unsigned int iovc = N_ELEMENTS(iov);

	o_stream_nsendv(conn->conn.output, iov, iovc);
}

int auth_master_run_cmd_pre(struct auth_master_connection *conn,
			    const char *cmd, const unsigned char *args,
			    size_t args_size)
{
	unsigned int id;

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

	if (++conn->id_counter == 0) {
		/* avoid zero */
		conn->id_counter++;
	}
	id = conn->id_counter;

	auth_master_request_send(conn, cmd, id, args, args_size);
	o_stream_uncork(conn->conn.output);

	if (o_stream_flush(conn->conn.output) < 0) {
		e_error(conn->conn.event, "write(auth socket) failed: %s",
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

int auth_master_run_cmd(struct auth_master_connection *conn, const char *cmd,
		        const unsigned char *args, size_t args_size)
{
	if (auth_master_run_cmd_pre(conn, cmd, args, args_size) < 0)
		return -1;
	/* add stop handler */
	struct timeout *to = timeout_add_short(100, auth_master_stop, conn);
	io_loop_run(conn->ioloop);
	timeout_remove(&to);
	return auth_master_run_cmd_post(conn);
}
