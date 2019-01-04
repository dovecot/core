/* Copyright (c) 2005-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "ioloop.h"
#include "array.h"
#include "aqueue.h"
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
	int fd;

	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to;

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

static void worker_input(struct auth_worker_connection *conn);
static void auth_worker_destroy(struct auth_worker_connection **conn,
				const char *reason, bool restart) ATTR_NULL(2);

static void auth_worker_idle_timeout(struct auth_worker_connection *conn)
{
	i_assert(conn->request == NULL);

	if (idle_count > 1)
		auth_worker_destroy(&conn, NULL, FALSE);
	else
		timeout_reset(conn->to);
}

static void auth_worker_call_timeout(struct auth_worker_connection *conn)
{
	i_assert(conn->request != NULL);

	auth_worker_destroy(&conn, "Lookup timed out", TRUE);
}

static bool auth_worker_request_send(struct auth_worker_connection *conn,
				     struct auth_worker_request *request)
{
	struct const_iovec iov[3];
	unsigned int age_secs = ioloop_time - request->created;

	i_assert(conn->to != NULL);

	if (age_secs >= AUTH_WORKER_ABORT_SECS) {
		i_error("Aborting auth request that was queued for %d secs, "
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
		i_warning("auth workers: Auth request was queued for %d "
			  "seconds, %d left in queue "
			  "(see auth_worker_max_count)",
			  age_secs, aqueue_count(worker_request_queue));
	}

	request->id = ++conn->id_counter;

	iov[0].iov_base = t_strdup_printf("%d\t", request->id);
	iov[0].iov_len = strlen(iov[0].iov_base);
	iov[1].iov_base = request->data;
	iov[1].iov_len = strlen(request->data);
	iov[2].iov_base = "\n";
	iov[2].iov_len = 1;

	o_stream_nsendv(conn->output, iov, 3);

	i_assert(conn->request == NULL);
	conn->request = request;

	timeout_remove(&conn->to);
	conn->to = timeout_add(AUTH_WORKER_LOOKUP_TIMEOUT_SECS * 1000,
			       auth_worker_call_timeout, conn);
	idle_count--;
	return TRUE;
}

static void auth_worker_request_send_next(struct auth_worker_connection *conn)
{
	struct auth_worker_request *request, *const *requestp;

	do {
		if (aqueue_count(worker_request_queue) == 0)
			return;

		requestp = array_idx(&worker_request_array,
				     aqueue_idx(worker_request_queue, 0));
		request = *requestp;
		aqueue_delete_tail(worker_request_queue);
	} while (!auth_worker_request_send(conn, request));
}

static void auth_worker_send_handshake(struct auth_worker_connection *conn)
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

	o_stream_nsend(conn->output, str_data(str), str_len(str));
}

static struct auth_worker_connection *auth_worker_create(void)
{
	struct auth_worker_connection *conn;
	int fd;

	if (array_count(&connections) >= auth_workers_throttle_count)
		return NULL;

	fd = net_connect_unix_with_retries(worker_socket_path, 5000);
	if (fd == -1) {
		if (errno == EACCES) {
			i_error("%s", eacces_error_get("net_connect_unix",
						       worker_socket_path));
		} else {
			i_error("net_connect_unix(%s) failed: %m",
				worker_socket_path);
		}
		return NULL;
	}

	conn = i_new(struct auth_worker_connection, 1);
	conn->fd = fd;
	conn->input = i_stream_create_fd(fd, AUTH_WORKER_MAX_LINE_LENGTH);
	conn->output = o_stream_create_fd(fd, (size_t)-1);
	o_stream_set_no_error_handling(conn->output, TRUE);
	conn->io = io_add(fd, IO_READ, worker_input, conn);
	conn->to = timeout_add(AUTH_WORKER_MAX_IDLE_SECS * 1000,
			       auth_worker_idle_timeout, conn);
	auth_worker_send_handshake(conn);

	idle_count++;
	array_append(&connections, &conn, 1);
	return conn;
}

static void auth_worker_destroy(struct auth_worker_connection **_conn,
				const char *reason, bool restart)
{
	struct auth_worker_connection *conn = *_conn;
	struct auth_worker_connection *const *conns;
	unsigned int idx;

	*_conn = NULL;

	if (conn->received_error) {
		i_assert(auth_workers_with_errors > 0);
		i_assert(auth_workers_with_errors <= array_count(&connections));
		auth_workers_with_errors--;
	}

	array_foreach(&connections, conns) {
		if (*conns == conn) {
			idx = array_foreach_idx(&connections, conns);
			array_delete(&connections, idx, 1);
			break;
		}
	}

	if (conn->request == NULL)
		idle_count--;

	if (conn->request != NULL) {
		i_error("auth worker: Aborted %s request for %s: %s",
			t_strcut(conn->request->data, '\t'),
			conn->request->username, reason);
		conn->request->callback(t_strdup_printf(
				"FAIL\t%d", PASSDB_RESULT_INTERNAL_FAILURE),
				conn->request->context);
	}

	io_remove(&conn->io);
	i_stream_destroy(&conn->input);
	o_stream_destroy(&conn->output);
	timeout_remove(&conn->to);

	if (close(conn->fd) < 0)
		i_error("close(auth worker) failed: %m");
	i_free(conn);

	if (idle_count == 0 && restart) {
		conn = auth_worker_create();
		if (conn != NULL)
			auth_worker_request_send_next(conn);
	}
}

static struct auth_worker_connection *auth_worker_find_free(void)
{
	struct auth_worker_connection **conns;

	if (idle_count == 0)
		return NULL;

	array_foreach_modifiable(&connections, conns) {
		struct auth_worker_connection *conn = *conns;

		if (conn->request == NULL)
			return conn;
	}
	i_unreached();
	return NULL;
}

static bool auth_worker_request_handle(struct auth_worker_connection *conn,
				       struct auth_worker_request *request,
				       const char *line)
{
	if (str_begins(line, "*\t")) {
		/* multi-line reply, not finished yet */
		if (conn->resuming)
			timeout_reset(conn->to);
		else {
			conn->resuming = TRUE;
			timeout_remove(&conn->to);
			conn->to = timeout_add(AUTH_WORKER_RESUME_TIMEOUT_SECS * 1000,
					       auth_worker_call_timeout, conn);
		}
	} else {
		conn->resuming = FALSE;
		conn->request = NULL;
		conn->timeout_pending_resume = FALSE;
		timeout_remove(&conn->to);
		conn->to = timeout_add(AUTH_WORKER_MAX_IDLE_SECS * 1000,
				       auth_worker_idle_timeout, conn);
		idle_count++;
	}

	if (!request->callback(line, request->context) && conn->io != NULL) {
		conn->timeout_pending_resume = FALSE;
		timeout_remove(&conn->to);
		io_remove(&conn->io);
		return FALSE;
	}
	return TRUE;
}

static bool auth_worker_error(struct auth_worker_connection *conn)
{
	if (conn->received_error)
		return TRUE;
	conn->received_error = TRUE;
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
	auth_worker_destroy(&conn, "Internal auth worker failure", FALSE);
	return FALSE;
}

static void auth_worker_success(struct auth_worker_connection *conn)
{
	unsigned int max_count = global_auth_settings->worker_max_count;

	if (!conn->received_error)
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
	conn->received_error = FALSE;
}

static void worker_input(struct auth_worker_connection *conn)
{
	const char *line, *id_str;
	unsigned int id;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_worker_destroy(&conn, "Worker process died unexpectedly",
				    TRUE);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth worker sent us more than %d bytes",
			(int)AUTH_WORKER_MAX_LINE_LENGTH);
		auth_worker_destroy(&conn, "Worker is buggy", TRUE);
		return;
	}

	while ((line = i_stream_next_line(conn->input)) != NULL) {
		if (strcmp(line, "RESTART") == 0) {
			conn->restart = TRUE;
			continue;
		}
		if (strcmp(line, "SHUTDOWN") == 0) {
			conn->shutdown = TRUE;
			continue;
		}
		if (strcmp(line, "ERROR") == 0) {
			if (!auth_worker_error(conn))
				return;
			continue;
		}
		if (strcmp(line, "SUCCESS") == 0) {
			auth_worker_success(conn);
			continue;
		}
		id_str = line;
		line = strchr(line, '\t');
		if (line == NULL ||
		    str_to_uint(t_strdup_until(id_str, line), &id) < 0)
			continue;

		if (conn->request != NULL && id == conn->request->id) {
			if (!auth_worker_request_handle(conn, conn->request,
							line + 1))
				break;
		} else {
			if (conn->request != NULL) {
				i_error("BUG: Worker sent reply with id %u, "
					"expected %u", id, conn->request->id);
			} else {
				i_error("BUG: Worker sent reply with id %u, "
					"none was expected", id);
			}
			auth_worker_destroy(&conn, "Worker is buggy", TRUE);
			return;
		}
	}

	if (conn->request != NULL) {
		/* there's still a pending request */
	} else if (conn->restart)
		auth_worker_destroy(&conn, "Max requests limit", TRUE);
	else if (conn->shutdown)
		auth_worker_destroy(&conn, "Idle kill", FALSE);
	else
		auth_worker_request_send_next(conn);
}

static void worker_input_resume(struct auth_worker_connection *conn)
{
	conn->timeout_pending_resume = FALSE;
	timeout_remove(&conn->to);
	conn->to = timeout_add(AUTH_WORKER_RESUME_TIMEOUT_SECS * 1000,
			       auth_worker_call_timeout, conn);
	worker_input(conn);
}

struct auth_worker_connection *
auth_worker_call(pool_t pool, const char *username, const char *data,
		 auth_worker_callback_t *callback, void *context)
{
	struct auth_worker_connection *conn;
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
		conn = NULL;
	} else {
		conn = auth_worker_find_free();
		if (conn == NULL) {
			/* no free connections, create a new one */
			conn = auth_worker_create();
		}
	}
	if (conn != NULL) {
		if (!auth_worker_request_send(conn, request))
			i_unreached();
	} else {
		/* reached the limit, queue the request */
		aqueue_append(worker_request_queue, &request);
	}
	return conn;
}

void auth_worker_server_resume_input(struct auth_worker_connection *conn)
{
	if (conn->request == NULL) {
		/* request was just finished, don't try to resume it */
		return;
	}

	if (conn->io == NULL)
		conn->io = io_add(conn->fd, IO_READ, worker_input, conn);
	if (!conn->timeout_pending_resume) {
		conn->timeout_pending_resume = TRUE;
		timeout_remove(&conn->to);
		conn->to = timeout_add_short(0, worker_input_resume, conn);
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
	struct auth_worker_connection **connp, *conn;

	while (array_count(&connections) > 0) {
		connp = array_first_modifiable(&connections);
		conn = *connp;
		auth_worker_destroy(&conn, "Shutting down", FALSE);
	}
	array_free(&connections);

	aqueue_deinit(&worker_request_queue);
	array_free(&worker_request_array);
}
