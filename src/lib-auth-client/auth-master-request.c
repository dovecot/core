/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "hash.h"
#include "llist.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "time-util.h"
#include "master-service.h"

#include "auth-master-private.h"

static void auth_master_request_update_event(struct auth_master_request *req)
{
	event_add_int(req->event, "id", req->id);
	event_set_append_log_prefix(req->event,
				    t_strdup_printf("request [%u]: ", req->id));
}

unsigned int
auth_master_request_get_timeout_msecs(struct auth_master_request *req)
{
	struct timeval expires = req->create_stamp;
	int msecs;

	timeval_add_msecs(&expires, req->conn->timeout_msecs);

	msecs = timeval_diff_msecs(&expires, &ioloop_timeval);
	return (unsigned int)(msecs < 0 ? 0 : msecs);
}

static void auth_master_request_remove(struct auth_master_request *req)
{
	struct auth_master_connection *conn = req->conn;

	if (req->removed)
		return;
	req->removed = TRUE;

	e_debug(req->event, "Remove");

	if (req->sent)
		hash_table_remove(conn->requests, POINTER_CAST(req->id));
	DLLIST2_REMOVE(&conn->requests_head, &conn->requests_tail, req);
	conn->requests_count--;

	auth_master_connection_update_timeout(conn);
	auth_master_check_idle(conn);

	if (conn->waiting) {
		i_assert(conn->ioloop != NULL);
		io_loop_stop(conn->ioloop);
	}
}

static void auth_master_request_ref(struct auth_master_request *req)
{
	req->refcount++;
}

static bool auth_master_request_unref(struct auth_master_request **_req)
{
	struct auth_master_request *req = *_req;
	const struct auth_master_request_destroy_callback *dc;

	*_req = NULL;

	if (req == NULL)
		return TRUE;

	i_assert(req->refcount > 0);
	if (--req->refcount > 0)
		return TRUE;

	e_debug(req->event, "Destroy");

	auth_master_request_remove(req);

	if (array_is_created(&req->destroy_callbacks)) {
		array_foreach(&req->destroy_callbacks, dc)
			dc->callback(dc->context);
		array_free(&req->destroy_callbacks);
	}

	event_unref(&req->event);
	pool_unref(&req->pool);
	return FALSE;
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
	struct auth_master_connection *conn = req->conn;
	auth_master_request_callback_t *callback = req->callback;
	struct auth_master_request *tmp_req = req;
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

	if (conn->prev_ioloop != NULL) {
		/* Don't let callback see that we've created our
		   internal ioloop in case it wants to add some ios
		   or timeouts. */
		current_ioloop = conn->prev_ioloop;
	}

	auth_master_request_ref(tmp_req);
	req->in_callback = TRUE;
	ret = callback(mreply, req->context);
	req->in_callback = FALSE;
	auth_master_request_unref(&tmp_req);

	if (conn->prev_ioloop != NULL)
		current_ioloop = conn->ioloop;

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

	if (req->state < AUTH_MASTER_REQUEST_STATE_FINISHED)
		req->state = AUTH_MASTER_REQUEST_STATE_REPLIED;

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
		if (req->state < AUTH_MASTER_REQUEST_STATE_FINISHED)
			req->state = AUTH_MASTER_REQUEST_STATE_FINISHED;
		auth_master_request_remove(req);
		auth_master_request_unref(&req);
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

	if (req->state >= AUTH_MASTER_REQUEST_STATE_FINISHED)
		return;
	req->state = AUTH_MASTER_REQUEST_STATE_ABORTED;

	e_debug(req->event, "Aborted");

	auth_master_request_remove(req);
	auth_master_request_unref(&req);
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
	req->refcount = 1;
	req->conn = conn;
	req->create_stamp = ioloop_timeval;

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

	e_debug(req->event, "Created");

	return req;
}

int auth_master_request_submit(struct auth_master_request **_req)
{
	struct auth_master_request *req = *_req;
	struct auth_master_connection *conn = req->conn;

	if (req == NULL)
		return -1;

	if (!conn->connected) {
		if (auth_master_connect(conn) < 0) {
			// FIXME: handle
			/* we couldn't connect to auth now,
			   so we probably can't in future either. */
			auth_master_request_unref(_req);
			return -1;
		}
		// FIXME: allow asynchronous connection
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
		auth_master_disconnect(conn);
		auth_master_request_unref(_req);
		return -1;
	}

	hash_table_insert(conn->requests, POINTER_CAST(req->id), req);
	req->sent = TRUE;

	auth_master_connection_start_timeout(conn);
	auth_master_stop_idle(conn);

	e_debug(req->event, "Submitted");

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
	struct ioloop *ioloop, *prev_ioloop;
	enum auth_master_request_state last_state;
	struct timeout *to;
	bool waiting = conn->waiting, was_corked = FALSE, freed;

	if (req->state >= AUTH_MASTER_REQUEST_STATE_FINISHED)
		return TRUE;

	i_assert(auth_master_request_count(conn) > 0);

	e_debug(req->event, "Waiting for request to complete");

	if ((conn->flags & AUTH_MASTER_FLAG_NO_INNER_IOLOOP) != 0)
		ioloop = conn->ioloop;
	else {
		prev_ioloop = conn->ioloop;
		if (!waiting)
			conn->prev_ioloop = prev_ioloop;
		ioloop = io_loop_create();
		auth_master_switch_ioloop_to(conn, ioloop);
	}

	if (conn->conn.input != NULL &&
	    i_stream_get_data_size(conn->conn.input) > 0)
		i_stream_set_input_pending(conn->conn.input, TRUE);
	if (conn->conn.output != NULL) {
		was_corked = o_stream_is_corked(conn->conn.output);
		o_stream_uncork(conn->conn.output);
	}

	/* either we're waiting for network I/O or we're getting out of a
	   callback using timeout_add_short(0) */
	i_assert(io_loop_have_ios(ioloop) ||
		 io_loop_have_immediate_timeouts(ioloop));

	auth_master_request_ref(req);
	req->state = AUTH_MASTER_REQUEST_STATE_SENT;

	/* add stop handler */
	to = timeout_add_short(100, auth_master_request_stop, req);

	conn->waiting = TRUE;
	while (req->state < AUTH_MASTER_REQUEST_STATE_REPLIED)
		io_loop_run(conn->ioloop);
	conn->waiting = waiting;

	e_debug(req->event, "Finished waiting for request");

	timeout_remove(&to);

	if (conn->conn.output != NULL && was_corked)
		o_stream_cork(conn->conn.output);

	last_state = req->state;
	freed = !auth_master_request_unref(&req);

	if ((conn->flags & AUTH_MASTER_FLAG_NO_INNER_IOLOOP) == 0) {
		auth_master_switch_ioloop_to(conn, prev_ioloop);
		io_loop_destroy(&ioloop);
		if (!waiting)
			conn->prev_ioloop = NULL;
	}

	return (freed || last_state >= AUTH_MASTER_REQUEST_STATE_FINISHED);
}

unsigned int auth_master_request_count(struct auth_master_connection *conn)
{
	return conn->requests_count;
}

#undef auth_master_request_add_destroy_callback
void auth_master_request_add_destroy_callback(
	struct auth_master_request *req,
	auth_master_request_destroy_callback_t *callback, void *context)
{
	struct auth_master_request_destroy_callback *dc;

	if (!array_is_created(&req->destroy_callbacks))
		i_array_init(&req->destroy_callbacks, 2);
	dc = array_append_space(&req->destroy_callbacks);
	dc->callback = callback;
	dc->context = context;
}

void auth_master_request_remove_destroy_callback(
	struct auth_master_request *req,
	auth_master_request_destroy_callback_t *callback)
{
	const struct auth_master_request_destroy_callback *dcs;
	unsigned int i, count;

	dcs = array_get(&req->destroy_callbacks, &count);
	for (i = 0; i < count; i++) {
		if (dcs[i].callback == callback) {
			array_delete(&req->destroy_callbacks, i, 1);
			return;
		}
	}
	i_unreached();
}
