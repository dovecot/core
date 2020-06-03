/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "master-service.h"

#include "auth-master-private.h"

static void auth_master_request_update_event(struct auth_master_request *req)
{
	event_add_int(req->event, "id", req->id);
	event_set_append_log_prefix(req->event,
				    t_strdup_printf("request [%u]: ", req->id));
}

static void auth_master_request_remove(struct auth_master_request *req)
{
	struct auth_master_connection *conn = req->conn;

	if (req->removed)
		return;
	req->removed = TRUE;

	DLLIST2_REMOVE(&conn->requests_head, &conn->requests_tail, req);
	conn->requests_count--;

	if (conn->waiting) {
		i_assert(conn->ioloop != NULL);
		io_loop_stop(conn->ioloop);
	} else if (conn->requests_head == NULL) {
		auth_master_unset_io(conn);
	}
}

static void auth_master_request_free(struct auth_master_request **_req)
{
	struct auth_master_request *req = *_req;

	*_req = NULL;

	if (req == NULL)
		return;

	auth_master_request_remove(req);
	event_unref(&req->event);
	pool_unref(&req->pool);
}

void auth_master_request_set_event(struct auth_master_request *req,
				   struct event *event)
{
	event_unref(&req->event);
	req->event = event_create(event);
	event_set_forced_debug(req->event,
			       HAS_ALL_BITS(req->conn->flags,
					    AUTH_MASTER_FLAG_DEBUG));
	auth_master_request_update_event(req);
}

static int
auth_master_request_callback(struct auth_master_request *req,
			     const struct auth_master_reply *mreply)
{
	auth_master_request_callback_t *callback = req->callback;
	int ret;

	req->callback = NULL;

	/* Disallow running an ioloop for this auth master client from inside
	   one of its own callbacks; i.e. thereby eventually triggering a
	   callback in a callback. This is not supported and can cause nasty
	   bugs.
	 */
	i_assert(!req->in_callback);

	if (callback == NULL)
		return 1;

	req->in_callback = TRUE;
	ret = callback(mreply, req->context);
	req->in_callback = FALSE;

	if (ret == 0) {
		/* Application expects more replies for this request. */
		req->callback = callback;
	}
	return ret;
}

int auth_master_request_got_reply(struct auth_master_request **_req,
				  const char *reply, const char *const *args)
{
	struct auth_master_request *req = *_req;
	struct auth_master_connection *conn = req->conn;
	int ret;

	*_req = NULL;

	i_assert(!req->in_callback);

	e_debug(req->event, "Got reply: %s %s",
		reply, t_strarray_join(args, " "));

	const struct auth_master_reply mreply = {
		.reply = reply,
		.args = args,
	};

	ret = auth_master_request_callback(req, &mreply);
	if (ret == 0) {
		if (conn->waiting) {
			i_assert(conn->ioloop != NULL);
			io_loop_stop(conn->ioloop);
		}
	} else {
		auth_master_request_remove(req);
		auth_master_request_free(&req);
	}
	return ret;
}

void auth_master_request_abort(struct auth_master_request **_req)
{
	struct auth_master_request *req = *_req;

	*_req = NULL;

	if (req == NULL)
		return;
	if (req->in_callback)
		return;

	e_debug(req->event, "Aborted");

	auth_master_request_remove(req);
	auth_master_request_free(&req);
}

void auth_master_request_fail(struct auth_master_request **_req,
			      const char *reason)
{
	struct auth_master_request *req = *_req;

	if (req->in_callback)
		return;

	e_debug(req->event, "Failed: %s", reason);

	const struct auth_master_reply mreply = {
		.reply = "FAIL",
		.errormsg = reason,
	};

	i_assert(req->callback != NULL);
	(void)auth_master_request_callback(req, &mreply);

	auth_master_request_abort(_req);
}

static void auth_master_request_send(struct auth_master_request *req)
{
	struct auth_master_connection *conn = req->conn;
	const char *id_str = dec2str(req->id);

	const struct const_iovec iov[] = {
		{ req->cmd, strlen(req->cmd), },
		{ "\t", 1 },
		{ id_str, strlen(id_str), },
		{ "\t", req->args_size > 0 ? 1 : 0 },
		{ req->args, req->args_size },
		{ "\r\n", 2 },
	};
	unsigned int iovc = N_ELEMENTS(iov);

	o_stream_nsendv(conn->conn.output, iov, iovc);
}

#undef auth_master_request
struct auth_master_request *
auth_master_request(struct auth_master_connection *conn, const char *cmd,
		    const unsigned char *args, size_t args_size,
		    auth_master_request_callback_t *callback, void *context)
{
	pool_t pool;
	struct auth_master_request *req;

	pool = pool_alloconly_create("auth_master_request", 256 + args_size);
	req = p_new(pool, struct auth_master_request, 1);
	req->pool = pool;
	req->conn = conn;

	if (++conn->id_counter == 0) {
		/* avoid zero */
		conn->id_counter++;
	}
	req->id = conn->id_counter;

	req->event = event_create(conn->conn.event);
	event_drop_parent_log_prefixes(req->event, 1);
	auth_master_request_update_event(req);

	req->callback = callback;
	req->context = context;

	DLLIST2_APPEND(&conn->requests_head, &conn->requests_tail, req);
	conn->requests_count++;

	req->cmd = p_strdup(req->pool, cmd);
	if (args_size > 0)
		req->args = p_memdup(req->pool, args, args_size);
	req->args_size = args_size;

	return req;
}

int auth_master_request_submit(struct auth_master_request **_req)
{
	struct auth_master_request *req = *_req;
	struct auth_master_connection *conn = req->conn;

	if (req == NULL)
		return -1;

	auth_master_set_io(conn);

	if (!conn->connected) {
		if (auth_master_connect(conn) < 0) {
			auth_master_unset_io(conn);
			auth_master_request_free(_req);
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

	auth_master_request_send(req);
	o_stream_uncork(conn->conn.output);

	if (o_stream_flush(conn->conn.output) < 0) {
		e_error(conn->conn.event, "write(auth socket) failed: %s",
			o_stream_get_error(conn->conn.output));
		auth_master_unset_io(conn);
		auth_master_disconnect(conn);
		auth_master_request_free(_req);
		return -1;
	}
	return 0;
}

static void auth_master_request_stop(struct auth_master_request *req)
{
	struct auth_master_connection *conn = req->conn;

	if (master_service_is_killed(master_service)) {
		auth_master_request_abort(&req);
		io_loop_stop(conn->ioloop);
	}
}

bool auth_master_request_wait(struct auth_master_request *req)
{
	struct auth_master_connection *conn = req->conn;
	struct timeout *to;
	bool was_corked = FALSE;

	if (conn->conn.input != NULL &&
	    i_stream_get_data_size(conn->conn.input) > 0)
		i_stream_set_input_pending(conn->conn.input, TRUE);
	if (conn->conn.output != NULL) {
		was_corked = o_stream_is_corked(conn->conn.output);
		o_stream_uncork(conn->conn.output);
	}

	/* add stop handler */
	to = timeout_add_short(100, auth_master_request_stop, req);

	conn->waiting = TRUE;
	io_loop_run(conn->ioloop);
	conn->waiting = FALSE;

	timeout_remove(&to);

	if (conn->conn.output != NULL && was_corked)
		o_stream_cork(conn->conn.output);

	if (conn->requests_head != NULL)
		return FALSE;

	auth_master_unset_io(conn);
	return TRUE;
}
