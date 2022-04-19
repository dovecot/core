/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "ioloop.h"
#include "array.h"
#include "aqueue.h"
#include "connection.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "hex-binary.h"
#include "str.h"
#include "strescape.h"
#include "eacces-error.h"
#include "auth-request.h"
#include "auth-worker-server.h"
#include "auth-worker-connection.h"

#include <unistd.h>

/* Initial lookup timeout */
#define AUTH_WORKER_LOOKUP_TIMEOUT_SECS 60
/* Timeout for multi-line replies, e.g. listing users. This should be a much
   higher value, because e.g. doveadm could be doing some long-running commands
   for the users. And because of buffering this timeout is for handling
   multiple users, not just one. */
#define AUTH_WORKER_RESUME_TIMEOUT_SECS (30*60)
#define AUTH_WORKER_MAX_IDLE_SECS (5*60)
#define AUTH_WORKER_ABORT_SECS 60
#define AUTH_WORKER_DELAY_WARN_SECS 3
#define AUTH_WORKER_DELAY_WARN_MIN_INTERVAL_SECS (5*60)
#define AUTH_WORKER_CONNECT_RETRY_TIMEOUT_MSECS (5*1000)

struct auth_worker_request {
	unsigned int id;
	time_t created;
	const char *username;
	const char *data;
	auth_worker_callback_t *callback;
	void *context;
};

struct auth_worker_connection {
	struct connection conn;
	struct timeout *to_lookup;
	struct auth_worker_request *request;
	unsigned int id_counter;

	bool received_error:1;
	bool restart:1;
	bool shutdown:1;
	bool timeout_pending_resume:1;
	bool resuming:1;
};

static struct connection_list *connections = NULL;
static unsigned int idle_count = 0, auth_workers_with_errors = 0;
static ARRAY(struct auth_worker_request *) worker_request_array;
static struct aqueue *worker_request_queue;
static time_t auth_worker_last_warn;
static unsigned int auth_workers_throttle_count;
static unsigned int auth_worker_process_limit = 0;

static const char *worker_socket_path;

static void auth_worker_deinit(struct auth_worker_connection **worker,
			       const char *reason, bool restart) ATTR_NULL(2);

static void auth_worker_idle_timeout(struct auth_worker_connection *worker)
{
	i_assert(worker->request == NULL);

	if (idle_count > 1)
		auth_worker_deinit(&worker, NULL, FALSE);
	else
		timeout_reset(worker->to_lookup);
}

static void auth_worker_call_timeout(struct auth_worker_connection *worker)
{
	i_assert(worker->request != NULL);

	auth_worker_deinit(&worker, "Lookup timed out", TRUE);
}

static bool auth_worker_request_send(struct auth_worker_connection *worker,
				     struct auth_worker_request *request)
{
	struct const_iovec iov[3];
	unsigned int age_secs = ioloop_time - request->created;

	i_assert(worker->to_lookup != NULL);

	if (age_secs >= AUTH_WORKER_ABORT_SECS) {
		e_error(worker->conn.event,
			"Aborting auth request that was queued for %d secs, "
			"%d left in queue",
			age_secs, aqueue_count(worker_request_queue));
		const char *const args[] = {
			"FAIL",
			t_strdup_printf("%d", PASSDB_RESULT_INTERNAL_FAILURE),
			NULL,
		};
		request->callback(worker, args, request->context);
		return FALSE;
	}
	if (age_secs >= AUTH_WORKER_DELAY_WARN_SECS &&
	    ioloop_time - auth_worker_last_warn >
	    AUTH_WORKER_DELAY_WARN_MIN_INTERVAL_SECS) {
		auth_worker_last_warn = ioloop_time;
		e_error(worker->conn.event, "Auth request was queued for %d "
			"seconds, %d left in queue "
			"(see service auth-worker { process_limit })",
			age_secs, aqueue_count(worker_request_queue));
	}

	request->id = ++worker->id_counter;

	iov[0].iov_base = t_strdup_printf("%d\t", request->id);
	iov[0].iov_len = strlen(iov[0].iov_base);
	iov[1].iov_base = request->data;
	iov[1].iov_len = strlen(request->data);
	iov[2].iov_base = "\n";
	iov[2].iov_len = 1;

	o_stream_nsendv(worker->conn.output, iov, 3);

	i_assert(worker->request == NULL);
	worker->request = request;

	timeout_remove(&worker->to_lookup);
	worker->to_lookup = timeout_add(AUTH_WORKER_LOOKUP_TIMEOUT_SECS * 1000,
					auth_worker_call_timeout, worker);

	i_assert(idle_count > 0);
	idle_count--;
	return TRUE;
}

static void auth_worker_request_send_next(struct auth_worker_connection *worker)
{
	struct auth_worker_request *request;

	do {
		if (aqueue_count(worker_request_queue) == 0)
			return;

		request = array_idx_elem(&worker_request_array,
					 aqueue_idx(worker_request_queue, 0));
		aqueue_delete_tail(worker_request_queue);
	} while (!auth_worker_request_send(worker, request));
}

static int auth_worker_handshake_args(struct connection *conn,
				      const char *const *args)
{
	if (!conn->version_received) {
		if (connection_handshake_args_default(conn, args) < 0)
			return -1;
		return 0;
	}

	if (strcmp(args[0], "PROCESS-LIMIT") == 0) {
		if (str_to_uint(args[1], &auth_worker_process_limit) < 0 ||
		    auth_worker_process_limit == 0) {
			e_error(conn->event,
				"Worker sent invalid process limit '%s'",
				args[1]);
			return -1;
		}

		e_debug(conn->event, "Worker sent process limit '%s'", args[1]);
		auth_workers_throttle_count = auth_worker_process_limit;
	}

	if (auth_workers_throttle_count == 0) {
		e_error(conn->event, "Worker did not send process limit");
		return -1;
	}

	return 1;
}

static void auth_worker_connection_connected(struct connection *conn,
					     bool success)
{
	if (!success)
		return;

	/* send outgoing handshake:
	   DBHASH	<passdb_md5>	<userdb_md5> */
	unsigned char passdb_md5[MD5_RESULTLEN];
	unsigned char userdb_md5[MD5_RESULTLEN];

	string_t *str = t_str_new(128);

	passdbs_generate_md5(passdb_md5);
	userdbs_generate_md5(userdb_md5);
	str_append(str, "DBHASH\t");
	binary_to_hex_append(str, passdb_md5, sizeof(passdb_md5));
	str_append_c(str, '\t');
	binary_to_hex_append(str, userdb_md5, sizeof(userdb_md5));
	str_append_c(str, '\n');

	o_stream_nsend(conn->output, str_data(str), str_len(str));
}

static void auth_worker_destroy(struct connection *conn)
{
	struct auth_worker_connection *worker =
		container_of(conn, struct auth_worker_connection, conn);

	const char *reason;
	bool restart;
	if (conn->disconnect_reason == CONNECTION_DISCONNECT_DEINIT) {
		reason = "Shutting down";
		restart = FALSE;
	} else {
		reason = t_strdup_printf("Worker process died unexpectedly: %s",
					 connection_disconnect_reason(conn));
		restart = TRUE;
	}
	auth_worker_deinit(&worker, reason, restart);
}

static struct auth_worker_connection *auth_worker_create(void)
{
	/* first connection will negotiate auth_worker_process_limit
	   via handshake */
	if (auth_worker_process_limit > 0 &&
	    connections->connections_count >= auth_workers_throttle_count)
		return NULL;

	struct auth_worker_connection *worker = i_new(struct auth_worker_connection, 1);

	worker->conn.event_parent = auth_event;
	connection_init_client_unix(connections, &worker->conn,
				    worker_socket_path);
	if (connection_client_connect(&worker->conn) < 0) {
		e_error(worker->conn.event,
			"Unable to connect worker: net_connect_unix(%s) failed: %m",
			worker->conn.name);
		connection_deinit(&worker->conn);
		i_free(worker);
		return NULL;
	}

	event_set_append_log_prefix(worker->conn.event, "auth-worker: ");

	worker->to_lookup = timeout_add(AUTH_WORKER_MAX_IDLE_SECS * 1000,
					auth_worker_idle_timeout, worker);

	idle_count++;
	return worker;
}

static void auth_worker_deinit(struct auth_worker_connection **_worker,
			       const char *reason, bool restart)
{
	struct auth_worker_connection *worker = *_worker;

	*_worker = NULL;

	if (worker->received_error) {
		i_assert(auth_workers_with_errors > 0);
		i_assert(auth_workers_with_errors <= connections->connections_count);
		auth_workers_with_errors--;
	}

	if (worker->request == NULL)
		idle_count--;
	else {
		e_error(worker->conn.event, "Aborted %s request for %s: %s",
			t_strcut(worker->request->data, '\t'),
			worker->request->username, reason);
		const char *const args[] = {
			"FAIL",
			t_strdup_printf("%d", PASSDB_RESULT_INTERNAL_FAILURE),
			NULL,
		};
		worker->request->callback(worker, args, worker->request->context);
	}

	timeout_remove(&worker->to_lookup);
	connection_deinit(&worker->conn);

	i_free(worker);

	if (idle_count == 0 && restart) {
		worker = auth_worker_create();
		if (worker != NULL)
			auth_worker_request_send_next(worker);
	}
}

static struct auth_worker_connection *auth_worker_find_free(void)
{
	if (idle_count == 0)
		return NULL;

	struct connection *conn = connections->connections;
	while (conn != NULL) {
		struct auth_worker_connection *worker =
			container_of(conn, struct auth_worker_connection, conn);
		if (worker->request == NULL)
			return worker;

		conn = conn->next;
	}

	i_unreached();
}

static int auth_worker_request_handle(struct auth_worker_connection *worker,
				      const char *const *args)
{
	struct auth_worker_request *_request = worker->request;

	/* lines starting with '*' denote a multi-line request
	   if they do, reset timeouts
	   if they do not, mark this request as handled */
	if (args[0][0] == '*') {
		if (worker->resuming)
			timeout_reset(worker->to_lookup);
		else {
			worker->resuming = TRUE;
			timeout_remove(&worker->to_lookup);
			worker->to_lookup = timeout_add(AUTH_WORKER_RESUME_TIMEOUT_SECS * 1000,
							auth_worker_call_timeout, worker);
		}
	} else {
		worker->resuming = FALSE;
		worker->request = NULL;
		worker->timeout_pending_resume = FALSE;
		timeout_remove(&worker->to_lookup);
		worker->to_lookup = timeout_add(AUTH_WORKER_MAX_IDLE_SECS * 1000,
						auth_worker_idle_timeout, worker);
		idle_count++;
	}

	if (!_request->callback(worker, args, _request->context)) {
		worker->timeout_pending_resume = FALSE;
		timeout_remove(&worker->to_lookup);
		return -1;
	}
	return 1;
}

static bool auth_worker_error(struct auth_worker_connection *worker)
{
	if (worker->received_error)
		return TRUE;
	worker->received_error = TRUE;
	auth_workers_with_errors++;
	i_assert(auth_workers_with_errors <= connections->connections_count);

	if (auth_workers_with_errors == 1) {
		/* this is the only failing auth worker connection.
		   don't create new ones until this one sends SUCCESS. */
		auth_workers_throttle_count = connections->connections_count;
		return TRUE;
	}

	/* too many auth workers, reduce them */
	i_assert(connections->connections_count > 1);
	if (auth_workers_throttle_count >= connections->connections_count)
		auth_workers_throttle_count = connections->connections_count-1;
	else if (auth_workers_throttle_count > 1)
		auth_workers_throttle_count--;
	auth_worker_deinit(&worker, "Internal auth worker failure", FALSE);
	return FALSE;
}

static void auth_worker_success(struct auth_worker_connection *worker)
{
	if (!worker->received_error)
		return;

	i_assert(auth_workers_with_errors > 0);
	i_assert(auth_workers_with_errors <= connections->connections_count);
	auth_workers_with_errors--;

	if (auth_workers_with_errors == 0) {
		/* all workers are succeeding now, set the limit back to
		   original. */
		auth_workers_throttle_count = auth_worker_process_limit;
	} else if (auth_workers_throttle_count < auth_worker_process_limit)
		auth_workers_throttle_count++;
	worker->received_error = FALSE;
}

static int worker_input_args(struct connection *conn, const char *const *args)
{
	struct auth_worker_connection *worker =
		container_of(conn, struct auth_worker_connection, conn);

	if (strcmp(args[0], "ERROR") == 0) {
		if (!auth_worker_error(worker))
			return -1;
		return 1;
	} else if (strcmp(args[0], "SUCCESS") == 0) {
		auth_worker_success(worker);
		return 1;
	} else if (strcmp(args[0], "SHUTDOWN") == 0) {
		worker->shutdown = TRUE;
		return 1;
	} else if (strcmp(args[0],  "RESTART") == 0) {
		worker->restart = TRUE;
		return 1;
	}

	/* skip invalid lines */
	unsigned int id;
	if (str_to_uint(args[0], &id) < 0) {
		e_error(conn->event, "Invalid ID: %s", args[0]);
		return 1;
	}

	int ret = 0;
	if (worker->request != NULL && id == worker->request->id)
		 ret = auth_worker_request_handle(worker, args + 1);
	else {
		if (worker->request != NULL) {
			e_error(conn->event,
				"BUG: Worker sent reply with id %u, "
				"expected %u", id, worker->request->id);
		} else {
			e_error(conn->event,
				"BUG: Worker sent reply with id %u, "
				"none was expected", id);
		}
		auth_worker_deinit(&worker, "Worker is buggy", TRUE);
		return -1;
	}

	if (worker->request != NULL) {
		/* there's still a pending request */
	} else if (worker->restart) {
		auth_worker_deinit(&worker, "Max requests limit", TRUE);
		ret = 0;
	} else if (worker->shutdown) {
		auth_worker_deinit(&worker, "Idle kill", FALSE);
		ret = 0;
	} else {
		auth_worker_request_send_next(worker);
		ret = 1;
	}

	return ret;
}

static void worker_input_resume(struct auth_worker_connection *worker)
{
	worker->timeout_pending_resume = FALSE;
	timeout_remove(&worker->to_lookup);
	worker->to_lookup = timeout_add(AUTH_WORKER_RESUME_TIMEOUT_SECS * 1000,
					auth_worker_call_timeout, worker);
	connection_input_resume(&worker->conn);
}

static const struct connection_settings auth_worker_connection_settings =
{
	.service_name_in = AUTH_WORKER_NAME,
	.service_name_out = AUTH_MASTER_NAME,
	.major_version = AUTH_WORKER_PROTOCOL_MAJOR_VERSION,
	.minor_version = AUTH_WORKER_PROTOCOL_MINOR_VERSION,
	.client = TRUE,
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.unix_client_connect_msecs = AUTH_WORKER_CONNECT_RETRY_TIMEOUT_MSECS,
};

static const struct connection_vfuncs auth_worker_connection_funcs =
{
	.client_connected = auth_worker_connection_connected,
	.destroy = auth_worker_destroy,
	.handshake_args = auth_worker_handshake_args,
	.input_args = worker_input_args,
};

void auth_worker_call(pool_t pool, const char *username, const char *data,
		      auth_worker_callback_t *callback, void *context)
{
	struct auth_worker_connection *worker;
	struct auth_worker_request *request;

	request = p_new(pool, struct auth_worker_request, 1);
	request->created = ioloop_time;
	request->username = p_strdup(pool, username);
	request->data = p_strdup(pool, data);
	request->callback = callback;
	request->context = context;

	if (aqueue_count(worker_request_queue) > 0) {
		/* requests are already being queued, no chance of
		   finding/creating a worker */
		worker = NULL;
	} else {
		worker = auth_worker_find_free();
		if (worker == NULL) {
			/* no free connections, create a new one */
			worker = auth_worker_create();
		}
	}
	if (worker != NULL) {
		if (!auth_worker_request_send(worker, request))
			i_unreached();
	} else {
		/* reached the limit, queue the request */
		aqueue_append(worker_request_queue, &request);
	}
}

void auth_worker_connection_resume_input(struct auth_worker_connection *worker)
{
	if (worker->request == NULL) {
		/* request was just finished, don't try to resume it */
		return;
	}

	if (!worker->timeout_pending_resume) {
		worker->timeout_pending_resume = TRUE;
		timeout_remove(&worker->to_lookup);
		worker->to_lookup = timeout_add_short(0, worker_input_resume, worker);
	}
}

void auth_worker_connection_init(void)
{
	worker_socket_path = "auth-worker";

	i_array_init(&worker_request_array, 128);
	worker_request_queue = aqueue_init(&worker_request_array.arr);

	connections = connection_list_init(&auth_worker_connection_settings,
					   &auth_worker_connection_funcs);
}

void auth_worker_connection_deinit(void)
{
	connection_list_deinit(&connections);

	aqueue_deinit(&worker_request_queue);
	array_free(&worker_request_array);
}
