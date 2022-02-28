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
#include "eacces-error.h"
#include "auth-request.h"
#include "auth-worker-client.h"
#include "auth-worker-server.h"

#include <unistd.h>

/* Initial lookup timeout */
#define AUTH_WORKER_LOOKUP_TIMEOUT_SECS 60
/* Timeout for multi-line replies, e.g. listing users. This should be a much
   higher value, because e.g. doveadm could be doing some long-running commands
   for the users. And because of buffering this timeout is for handling
   multiple users, not just one. */
#define AUTH_WORKER_RESUME_TIMEOUT_SECS (30*60)
#define AUTH_WORKER_MAX_IDLE_SECS (60*5)
#define AUTH_WORKER_ABORT_SECS 60
#define AUTH_WORKER_DELAY_WARN_SECS 3
#define AUTH_WORKER_DELAY_WARN_MIN_INTERVAL_SECS 300

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

static ARRAY(struct auth_worker_connection *) connections = ARRAY_INIT;
static unsigned int idle_count = 0, auth_workers_with_errors = 0;
static ARRAY(struct auth_worker_request *) worker_request_array;
static struct aqueue *worker_request_queue;
static time_t auth_worker_last_warn;
static unsigned int auth_workers_throttle_count;

static const char *worker_socket_path;

static void worker_input(struct auth_worker_connection *worker);
static void auth_worker_destroy(struct auth_worker_connection **worker,
				const char *reason, bool restart) ATTR_NULL(2);

static void auth_worker_idle_timeout(struct auth_worker_connection *worker)
{
	i_assert(worker->request == NULL);

	if (idle_count > 1)
		auth_worker_destroy(&worker, NULL, FALSE);
	else
		timeout_reset(worker->to_lookup);
}

static void auth_worker_call_timeout(struct auth_worker_connection *worker)
{
	i_assert(worker->request != NULL);

	auth_worker_destroy(&worker, "Lookup timed out", TRUE);
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
		request->callback(t_strdup_printf(
			"FAIL\t%d", PASSDB_RESULT_INTERNAL_FAILURE),
			request->context);
		return FALSE;
	}
	if (age_secs >= AUTH_WORKER_DELAY_WARN_SECS &&
	    ioloop_time - auth_worker_last_warn >
	    AUTH_WORKER_DELAY_WARN_MIN_INTERVAL_SECS) {
		auth_worker_last_warn = ioloop_time;
		e_error(worker->conn.event, "Auth request was queued for %d "
			"seconds, %d left in queue "
			"(see auth_worker_max_count)",
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

static void auth_worker_send_handshake(struct auth_worker_connection *worker)
{
	string_t *str;
	unsigned char passdb_md5[MD5_RESULTLEN];
	unsigned char userdb_md5[MD5_RESULTLEN];

	str = t_str_new(128);
	str_printfa(str, "VERSION\tauth-worker\t%u\t%u\n",
		    AUTH_WORKER_PROTOCOL_MAJOR_VERSION,
		    AUTH_WORKER_PROTOCOL_MINOR_VERSION);

	passdbs_generate_md5(passdb_md5);
	userdbs_generate_md5(userdb_md5);
	str_append(str, "DBHASH\t");
	binary_to_hex_append(str, passdb_md5, sizeof(passdb_md5));
	str_append_c(str, '\t');
	binary_to_hex_append(str, userdb_md5, sizeof(userdb_md5));
	str_append_c(str, '\n');

	o_stream_nsend(worker->conn.output, str_data(str), str_len(str));
}

static struct auth_worker_connection *auth_worker_create(void)
{
	struct auth_worker_connection *worker;
	struct event *event;

	if (array_count(&connections) >= auth_workers_throttle_count)
		return NULL;

	event = event_create(auth_event);
	event_set_append_log_prefix(event, "auth-worker: ");

	worker = i_new(struct auth_worker_connection, 1);
	worker->conn.fd_in = net_connect_unix_with_retries(worker_socket_path, 5000);
	if (worker->conn.fd_in == -1) {
		if (errno == EACCES) {
			e_error(event, "%s",
				eacces_error_get("net_connect_unix",
						 worker_socket_path));
		} else {
			e_error(event, "net_connect_unix(%s) failed: %m",
				worker_socket_path);
		}
		event_unref(&event);
		return NULL;
	}
	worker->conn.input = i_stream_create_fd(worker->conn.fd_in,
						AUTH_WORKER_MAX_LINE_LENGTH);
	worker->conn.output = o_stream_create_fd(worker->conn.fd_in, SIZE_MAX);
	o_stream_set_no_error_handling(worker->conn.output, TRUE);
	worker->conn.io = io_add(worker->conn.fd_in, IO_READ, worker_input, worker);
	worker->to_lookup = timeout_add(AUTH_WORKER_MAX_IDLE_SECS * 1000,
					auth_worker_idle_timeout, worker);
	worker->conn.event = event;
	auth_worker_send_handshake(worker);

	idle_count++;
	array_push_back(&connections, &worker);
	return worker;
}

static void auth_worker_destroy(struct auth_worker_connection **_worker,
				const char *reason, bool restart)
{
	struct auth_worker_connection *worker = *_worker;
	struct auth_worker_connection *const *workers;
	unsigned int idx;

	*_worker = NULL;

	if (worker->received_error) {
		i_assert(auth_workers_with_errors > 0);
		i_assert(auth_workers_with_errors <= array_count(&connections));
		auth_workers_with_errors--;
	}

	array_foreach(&connections, workers) {
		if (*workers == worker) {
			idx = array_foreach_idx(&connections, workers);
			array_delete(&connections, idx, 1);
			break;
		}
	}

	if (worker->request == NULL)
		idle_count--;

	if (worker->request != NULL) {
		e_error(worker->conn.event, "Aborted %s request for %s: %s",
			t_strcut(worker->request->data, '\t'),
			worker->request->username, reason);
		worker->request->callback(t_strdup_printf(
				"FAIL\t%d", PASSDB_RESULT_INTERNAL_FAILURE),
				worker->request->context);
	}

	io_remove(&worker->conn.io);
	i_stream_destroy(&worker->conn.input);
	o_stream_destroy(&worker->conn.output);
	timeout_remove(&worker->to_lookup);

	if (close(worker->conn.fd_in) < 0)
		e_error(worker->conn.event, "close() failed: %m");
	event_unref(&worker->conn.event);
	i_free(worker);

	if (idle_count == 0 && restart) {
		worker = auth_worker_create();
		if (worker != NULL)
			auth_worker_request_send_next(worker);
	}
}

static struct auth_worker_connection *auth_worker_find_free(void)
{
	struct auth_worker_connection *worker;

	if (idle_count == 0)
		return NULL;

	array_foreach_elem(&connections, worker) {
		if (worker->request == NULL)
			return worker;
	}
	i_unreached();
}

static bool auth_worker_request_handle(struct auth_worker_connection *worker,
				       struct auth_worker_request *request,
				       const char *line)
{
	if (str_begins_with(line, "*\t")) {
		/* multi-line reply, not finished yet */
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

	if (!request->callback(line, request->context) &&
	    worker->conn.io != NULL) {
		worker->timeout_pending_resume = FALSE;
		timeout_remove(&worker->to_lookup);
		io_remove(&worker->conn.io);
		return FALSE;
	}
	return TRUE;
}

static bool auth_worker_error(struct auth_worker_connection *worker)
{
	if (worker->received_error)
		return TRUE;
	worker->received_error = TRUE;
	auth_workers_with_errors++;
	i_assert(auth_workers_with_errors <= array_count(&connections));

	if (auth_workers_with_errors == 1) {
		/* this is the only failing auth worker connection.
		   don't create new ones until this one sends SUCCESS. */
		auth_workers_throttle_count = array_count(&connections);
		return TRUE;
	}

	/* too many auth workers, reduce them */
	i_assert(array_count(&connections) > 1);
	if (auth_workers_throttle_count >= array_count(&connections))
		auth_workers_throttle_count = array_count(&connections)-1;
	else if (auth_workers_throttle_count > 1)
		auth_workers_throttle_count--;
	auth_worker_destroy(&worker, "Internal auth worker failure", FALSE);
	return FALSE;
}

static void auth_worker_success(struct auth_worker_connection *worker)
{
	unsigned int max_count = global_auth_settings->worker_max_count;

	if (!worker->received_error)
		return;

	i_assert(auth_workers_with_errors > 0);
	i_assert(auth_workers_with_errors <= array_count(&connections));
	auth_workers_with_errors--;

	if (auth_workers_with_errors == 0) {
		/* all workers are succeeding now, set the limit back to
		   original. */
		auth_workers_throttle_count = max_count;
	} else if (auth_workers_throttle_count < max_count)
		auth_workers_throttle_count++;
	worker->received_error = FALSE;
}

static void worker_input(struct auth_worker_connection *worker)
{
	const char *line, *id_str;
	unsigned int id;

	switch (i_stream_read(worker->conn.input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_worker_destroy(&worker, "Worker process died unexpectedly",
				    TRUE);
		return;
	case -2:
		/* buffer full */
		e_error(worker->conn.event,
			"BUG: Auth worker sent us more than %d bytes",
			(int)AUTH_WORKER_MAX_LINE_LENGTH);
		auth_worker_destroy(&worker, "Worker is buggy", TRUE);
		return;
	}

	while ((line = i_stream_next_line(worker->conn.input)) != NULL) {
		if (strcmp(line, "RESTART") == 0) {
			worker->restart = TRUE;
			continue;
		}
		if (strcmp(line, "SHUTDOWN") == 0) {
			worker->shutdown = TRUE;
			continue;
		}
		if (strcmp(line, "ERROR") == 0) {
			if (!auth_worker_error(worker))
				return;
			continue;
		}
		if (strcmp(line, "SUCCESS") == 0) {
			auth_worker_success(worker);
			continue;
		}
		id_str = line;
		line = strchr(line, '\t');
		if (line == NULL ||
		    str_to_uint(t_strdup_until(id_str, line), &id) < 0)
			continue;

		if (worker->request != NULL && id == worker->request->id) {
			if (!auth_worker_request_handle(worker, worker->request,
							line + 1))
				break;
		} else {
			if (worker->request != NULL) {
				e_error(worker->conn.event,
					"BUG: Worker sent reply with id %u, "
					"expected %u", id, worker->request->id);
			} else {
				e_error(worker->conn.event,
					"BUG: Worker sent reply with id %u, "
					"none was expected", id);
			}
			auth_worker_destroy(&worker, "Worker is buggy", TRUE);
			return;
		}
	}

	if (worker->request != NULL) {
		/* there's still a pending request */
	} else if (worker->restart)
		auth_worker_destroy(&worker, "Max requests limit", TRUE);
	else if (worker->shutdown)
		auth_worker_destroy(&worker, "Idle kill", FALSE);
	else
		auth_worker_request_send_next(worker);
}

static void worker_input_resume(struct auth_worker_connection *worker)
{
	worker->timeout_pending_resume = FALSE;
	timeout_remove(&worker->to_lookup);
	worker->to_lookup = timeout_add(AUTH_WORKER_RESUME_TIMEOUT_SECS * 1000,
					auth_worker_call_timeout, worker);
	worker_input(worker);
}

struct auth_worker_connection *
auth_worker_call(pool_t pool, const char *username, const char *data,
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
	return worker;
}

void auth_worker_server_resume_input(struct auth_worker_connection *worker)
{
	if (worker->request == NULL) {
		/* request was just finished, don't try to resume it */
		return;
	}

	if (worker->conn.io == NULL)
		worker->conn.io = io_add(worker->conn.fd_in, IO_READ, worker_input, worker);
	if (!worker->timeout_pending_resume) {
		worker->timeout_pending_resume = TRUE;
		timeout_remove(&worker->to_lookup);
		worker->to_lookup = timeout_add_short(0, worker_input_resume, worker);
	}
}

void auth_worker_server_init(void)
{
	worker_socket_path = "auth-worker";
	auth_workers_throttle_count = global_auth_settings->worker_max_count;
	i_assert(auth_workers_throttle_count > 0);

	i_array_init(&worker_request_array, 128);
	worker_request_queue = aqueue_init(&worker_request_array.arr);

	i_array_init(&connections, 16);
}

void auth_worker_server_deinit(void)
{
	struct auth_worker_connection **workerp, *worker;

	while (array_count(&connections) > 0) {
		workerp = array_front_modifiable(&connections);
		worker = *workerp;
		auth_worker_destroy(&worker, "Shutting down", FALSE);
	}
	array_free(&connections);

	aqueue_deinit(&worker_request_queue);
	array_free(&worker_request_array);
}
