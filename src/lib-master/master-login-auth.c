/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "net.h"
#include "ioloop.h"
#include "hostpid.h"
#include "istream.h"
#include "ostream.h"
#include "llist.h"
#include "hex-binary.h"
#include "hash.h"
#include "str.h"
#include "strescape.h"
#include "time-util.h"
#include "connection.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-auth.h"
#include "master-login-auth.h"


#define AUTH_MAX_INBUF_SIZE 8192

struct master_login_auth_request {
	struct master_login_auth_request *prev, *next;

	unsigned int id;
	struct timeval create_stamp;

	pid_t auth_pid;
	unsigned int auth_id;
	unsigned int client_pid;
	uint8_t cookie[MASTER_AUTH_COOKIE_SIZE];

	master_login_auth_request_callback_t *callback;
	void *context;

	bool aborted:1;
};

struct master_login_auth {
	struct connection conn;
	struct connection_list *clist;
	pool_t pool;
	int refcount;

	const char *auth_socket_path;

	struct timeval connect_time, handshake_time;

	struct timeout *to;

	unsigned int id_counter;
	HASH_TABLE(void *, struct master_login_auth_request *) requests;
	/* linked list of requests, ordered by create_stamp */
	struct master_login_auth_request *request_head, *request_tail;

	pid_t auth_server_pid;

	unsigned int timeout_msecs;

	bool connected:1;
	bool request_auth_token:1;
};

static void master_login_auth_connected(struct connection *_conn, bool success);
static int
master_login_auth_input_args(struct connection *_conn, const char *const *args);
static int
master_login_auth_handshake_line(struct connection *_conn, const char *line);
static void master_login_auth_destroy(struct connection *_conn);

static void master_login_auth_update_timeout(struct master_login_auth *auth);
static void master_login_auth_check_spids(struct master_login_auth *auth);

static const struct connection_vfuncs master_login_auth_vfuncs = {
	.destroy = master_login_auth_destroy,
	.handshake_line = master_login_auth_handshake_line,
	.input_args = master_login_auth_input_args,
	.client_connected = master_login_auth_connected,
};

static const struct connection_settings master_login_auth_set = {
	.dont_send_version = TRUE,
	.service_name_in = "auth-master",
	.service_name_out = "auth-master",
	.major_version = AUTH_MASTER_PROTOCOL_MAJOR_VERSION,
	.minor_version = AUTH_MASTER_PROTOCOL_MINOR_VERSION,
	.unix_client_connect_msecs = 1000,
	.input_max_size = AUTH_MAX_INBUF_SIZE,
	.output_max_size = (size_t)-1,
	.client = TRUE,
};

struct master_login_auth *
master_login_auth_init(const char *auth_socket_path, bool request_auth_token)
{
	struct master_login_auth *auth;
	pool_t pool;

	pool = pool_alloconly_create("master login auth", 1024);
	auth = p_new(pool, struct master_login_auth, 1);
	auth->pool = pool;
	auth->auth_socket_path = p_strdup(pool, auth_socket_path);
	auth->request_auth_token = request_auth_token;
	auth->refcount = 1;
	hash_table_create_direct(&auth->requests, pool, 0);
	auth->id_counter = i_rand_limit(32767) * 131072U;

	auth->clist = connection_list_init(&master_login_auth_set,
					   &master_login_auth_vfuncs);
	connection_init_client_unix(auth->clist, &auth->conn,
				    auth->auth_socket_path);

	auth->timeout_msecs = 1000 * MASTER_AUTH_LOOKUP_TIMEOUT_SECS;
	return auth;
}

static void request_failure(struct master_login_auth *auth,
			    struct master_login_auth_request *request,
			    const char *log_reason, const char *client_reason)
{
	string_t *str = t_str_new(128);

	str_printfa(str, "auth connected %u msecs ago",
		    timeval_diff_msecs(&ioloop_timeval, &auth->connect_time));
	if (auth->handshake_time.tv_sec != 0) {
		str_printfa(str, ", handshake %u msecs ago",
			    timeval_diff_msecs(&ioloop_timeval, &auth->handshake_time));
	}
	str_printfa(str, ", request took %u msecs, client-pid=%u client-id=%u",
		    timeval_diff_msecs(&ioloop_timeval, &request->create_stamp),
		    request->client_pid, request->auth_id);

	i_error("%s (%s)", log_reason, str_c(str));
	request->callback(NULL, client_reason, request->context);
}

static void
request_internal_failure(struct master_login_auth *auth,
			 struct master_login_auth_request *request,
			 const char *reason)
{
	request_failure(auth, request, reason, MASTER_AUTH_ERRMSG_INTERNAL_FAILURE);
}

static void
master_login_auth_fail(struct master_login_auth *auth,
		       const char *reason) ATTR_NULL(2)
{
	struct master_login_auth_request *request;

	if (reason == NULL)
		reason = "Disconnected from auth server, aborting";

	auth->connected = FALSE;

	while (auth->request_head != NULL) {
		request = auth->request_head;
		DLLIST2_REMOVE(&auth->request_head,
			       &auth->request_tail, request);

		request_internal_failure(auth, request, reason);
		i_free(request);
	}
	hash_table_clear(auth->requests, FALSE);

	timeout_remove(&auth->to);
	i_zero(&auth->connect_time);
	i_zero(&auth->handshake_time);
}

void master_login_auth_disconnect(struct master_login_auth *auth)
{
	connection_disconnect(&auth->conn);
	master_login_auth_fail(auth, NULL);
}

static void master_login_auth_unref(struct master_login_auth **_auth)
{
	struct master_login_auth *auth = *_auth;
	struct connection_list *clist = auth->clist;

	*_auth = NULL;

	i_assert(auth->refcount > 0);
	if (--auth->refcount > 0)
		return;

	hash_table_destroy(&auth->requests);
	connection_deinit(&auth->conn);
	connection_list_deinit(&clist);
	pool_unref(&auth->pool);
}

void master_login_auth_deinit(struct master_login_auth **_auth)
{
	struct master_login_auth *auth = *_auth;

	*_auth = NULL;

	master_login_auth_disconnect(auth);
	master_login_auth_unref(&auth);
}

void master_login_auth_set_timeout(struct master_login_auth *auth,
				   unsigned int msecs)
{
	auth->timeout_msecs = msecs;
}

static void master_login_auth_destroy(struct connection *_conn)
{
	struct master_login_auth *auth =
		container_of(_conn, struct master_login_auth, conn);

	auth->connected = FALSE;

	switch (_conn->disconnect_reason) {
	case CONNECTION_DISCONNECT_HANDSHAKE_FAILED:
		master_login_auth_fail(auth,
				       "Handshake with auth service failed");
		break;
	case CONNECTION_DISCONNECT_BUFFER_FULL:
		/* buffer full */
		i_error("Auth server sent us too long line");
		master_login_auth_fail(auth, NULL);
		break;
	default:
		/* disconnected. stop accepting new connections, because in
		   default configuration we no longer have permissions to
		   connect back to auth-master */
		master_service_stop_new_connections(master_service);
		master_login_auth_fail(auth, NULL);
	}
}

static unsigned int auth_get_next_timeout_msecs(struct master_login_auth *auth)
{
	struct timeval expires;
	int diff;

	expires = auth->request_head->create_stamp;
	timeval_add_msecs(&expires, auth->timeout_msecs);

	diff = timeval_diff_msecs(&expires, &ioloop_timeval);
	return (diff <= 0 ? 0 : (unsigned int)diff);
}

static void master_login_auth_timeout(struct master_login_auth *auth)
{
	struct master_login_auth_request *request;
	const char *reason;

	while (auth->request_head != NULL &&
	       auth_get_next_timeout_msecs(auth) == 0) {
		int msecs;

		request = auth->request_head;
		DLLIST2_REMOVE(&auth->request_head,
			       &auth->request_tail, request);
		hash_table_remove(auth->requests, POINTER_CAST(request->id));

		msecs = timeval_diff_msecs(&ioloop_timeval,
					   &request->create_stamp);
		reason = t_strdup_printf(
			"Auth server request timed out after %u.%03u secs",
			msecs/1000, msecs%1000);
		request_internal_failure(auth, request, reason);
		i_free(request);
	}
	timeout_remove(&auth->to);
	master_login_auth_update_timeout(auth);
}

static void master_login_auth_update_timeout(struct master_login_auth *auth)
{
	i_assert(auth->to == NULL);

	if (auth->request_head != NULL) {
		auth->to = timeout_add(auth_get_next_timeout_msecs(auth),
				       master_login_auth_timeout, auth);
	}
}

static int
master_login_auth_handshake_line(struct connection *_conn, const char *line)
{
	struct master_login_auth *auth =
		container_of(_conn, struct master_login_auth, conn);
	const char *const *tmp;
	unsigned int major_version, minor_version;

	tmp = t_strsplit_tabescaped(line);
	if (!auth->conn.version_received && strcmp(tmp[0], "VERSION") == 0 &&
	    tmp[1] != NULL && tmp[2] != NULL) {
		if (str_to_uint(tmp[1], &major_version) < 0 ||
		    str_to_uint(tmp[2], &minor_version) < 0) {
			i_error("Auth server sent invalid version line: %s",
				line);
			return -1;
		}

		if (connection_verify_version(_conn, "auth-master",
					      major_version,
					      minor_version) < 0)
			return -1;
		return 0;
	}
	if (strcmp(tmp[0], "SPID") != 0 ||
	    str_to_pid(tmp[1], &auth->auth_server_pid) < 0) {
		i_error("Auth server did not send valid SPID: %s", line);
		return -1;
	}

	master_login_auth_check_spids(auth);
	return 1;
}

static void
master_login_auth_request_remove(struct master_login_auth *auth,
				 struct master_login_auth_request *request)
{
	bool update_timeout;

	update_timeout = request->prev == NULL;

	hash_table_remove(auth->requests, POINTER_CAST(request->id));
	DLLIST2_REMOVE(&auth->request_head, &auth->request_tail, request);

	if (update_timeout) {
		timeout_remove(&auth->to);
		master_login_auth_update_timeout(auth);
	}
}

static struct master_login_auth_request *
master_login_auth_lookup_request(struct master_login_auth *auth,
				 unsigned int id)
{
	struct master_login_auth_request *request;

	request = hash_table_lookup(auth->requests, POINTER_CAST(id));
	if (request == NULL) {
		i_error("Auth server sent reply with unknown ID %u", id);
		return NULL;
	}
	master_login_auth_request_remove(auth, request);
	if (request->aborted) {
		request->callback(NULL, MASTER_AUTH_ERRMSG_INTERNAL_FAILURE,
				  request->context);
		i_free(request);
		return NULL;
	}
	return request;
}

static void
master_login_auth_input_user(struct master_login_auth *auth, unsigned int id,
			     const char *const *args)
{
	struct master_login_auth_request *request;

	/* USER <id> <userid> [..] */
	request = master_login_auth_lookup_request(auth, id);
	if (request != NULL) {
		request->callback(args, NULL, request->context);
		i_free(request);
	}
}

static void
master_login_auth_input_notfound(struct master_login_auth *auth,
				 unsigned int id,
				 const char *const *args ATTR_UNUSED)
{
	struct master_login_auth_request *request;

	/* NOTFOUND <id> */
	request = master_login_auth_lookup_request(auth, id);
	if (request != NULL) {
		const char *reason = t_strdup_printf(
			"Authenticated user not found from userdb, "
			"auth lookup id=%u", id);
		request_internal_failure(auth, request, reason);
		i_free(request);
	}
}

static void
master_login_auth_input_fail(struct master_login_auth *auth, unsigned int id,
			     const char *const *args)
{
	struct master_login_auth_request *request;
	const char *error = NULL;
	unsigned int i;

	/* FAIL <id> [..] [reason=<error>] [..] */
	for (i = 0; args[i] != NULL; i++) {
		if (str_begins(args[i], "reason="))
			error = args[i] + 7;
	}

	request = master_login_auth_lookup_request(auth, id);
	if (request != NULL) {
		if (error == NULL) {
			request_internal_failure(auth, request,
						 "Internal auth failure");
		} else {
			const char *log_reason = t_strdup_printf(
				"Internal auth failure: %s", error);
			request_failure(auth, request, log_reason, error);
		}
		i_free(request);
	}
}

static int
master_login_auth_input_args(struct connection *_conn, const char *const *args)
{
	struct master_login_auth *auth =
		container_of(_conn, struct master_login_auth, conn);
	unsigned int id;

	if (args[0] == NULL || args[1] == NULL ||
	    str_to_uint(args[1], &id) < 0) {
		i_error("BUG: Unexpected input: %s",
			t_strarray_join(args, "\t"));
		return -1;
	}

	auth->refcount++;
	if (strcmp(args[0], "USER") == 0)
		master_login_auth_input_user(auth, id, &args[2]);
	else if (strcmp(args[0], "NOTFOUND") == 0)
		master_login_auth_input_notfound(auth, id, &args[2]);
	else if (strcmp(args[0], "FAIL") == 0)
		master_login_auth_input_fail(auth, id, &args[2]);
	master_login_auth_unref(&auth);

	return 0;
}

static void master_login_auth_connected(struct connection *_conn, bool success)
{
	struct master_login_auth *auth =
		container_of(_conn, struct master_login_auth, conn);

	/* Cannot get here unless connect() was successful */
	i_assert(success);

	auth->connected = TRUE;
}

static int
master_login_auth_connect(struct master_login_auth *auth)
{
	i_assert(!auth->connected);

	if (connection_client_connect(&auth->conn) < 0) {
		i_error("net_connect_unix(%s) failed: %m",
			auth->auth_socket_path);
		return -1;
	}
	io_loop_time_refresh();
	auth->connect_time = ioloop_timeval;
	return 0;
}

static bool
auth_request_check_spid(struct master_login_auth *auth,
			struct master_login_auth_request *req)
{
	if (auth->auth_server_pid != req->auth_pid &&
	    auth->conn.handshake_received) {
		/* auth server was restarted. don't even attempt a login. */
		i_warning("Auth server restarted (pid %u -> %u), aborting auth",
			  (unsigned int)req->auth_pid,
			  (unsigned int)auth->auth_server_pid);
		return FALSE;
	}
	return TRUE;
}

static void master_login_auth_check_spids(struct master_login_auth *auth)
{
	struct master_login_auth_request *req, *next;

	for (req = auth->request_head; req != NULL; req = next) {
		next = req->next;
		if (!auth_request_check_spid(auth, req))
			req->aborted = TRUE;
	}
}

static void
master_login_auth_send_request(struct master_login_auth *auth,
			       struct master_login_auth_request *req)
{
	string_t *str;

	if (!auth_request_check_spid(auth, req)) {
		master_login_auth_request_remove(auth, req);
		req->callback(NULL, MASTER_AUTH_ERRMSG_INTERNAL_FAILURE,
			      req->context);
		i_free(req);
		return;
	}

	str = t_str_new(128);
	str_printfa(str, "REQUEST\t%u\t%u\t%u\t", req->id,
		    req->client_pid, req->auth_id);
	binary_to_hex_append(str, req->cookie, sizeof(req->cookie));
	str_printfa(str, "\tsession_pid=%s", my_pid);
	if (auth->request_auth_token)
		str_append(str, "\trequest_auth_token");
	str_append_c(str, '\n');
	o_stream_nsend(auth->conn.output, str_data(str), str_len(str));
}

void master_login_auth_request(struct master_login_auth *auth,
			       const struct master_auth_request *req,
			       master_login_auth_request_callback_t *callback,
			       void *context)
{
	struct master_login_auth_request *login_req;
	unsigned int id;

	if (!auth->connected) {
		if (master_login_auth_connect(auth) < 0) {
			/* we couldn't connect to auth now,
			   so we probably can't in future either. */
			master_service_stop_new_connections(master_service);
			callback(NULL, MASTER_AUTH_ERRMSG_INTERNAL_FAILURE,
				 context);
			return;
		}
		o_stream_nsend_str(auth->conn.output,
			t_strdup_printf("VERSION\t%u\t%u\n",
					AUTH_MASTER_PROTOCOL_MAJOR_VERSION,
					AUTH_MASTER_PROTOCOL_MINOR_VERSION));
	}

	id = ++auth->id_counter;
	if (id == 0)
		id++;

	io_loop_time_refresh();
	login_req = i_new(struct master_login_auth_request, 1);
	login_req->create_stamp = ioloop_timeval;
	login_req->id = id;
	login_req->auth_pid = req->auth_pid;
	login_req->client_pid = req->client_pid;
	login_req->auth_id = req->auth_id;
	memcpy(login_req->cookie, req->cookie, sizeof(login_req->cookie));
	login_req->callback = callback;
	login_req->context = context;
	i_assert(hash_table_lookup(auth->requests, POINTER_CAST(id)) == NULL);
	hash_table_insert(auth->requests, POINTER_CAST(id), login_req);
	DLLIST2_APPEND(&auth->request_head, &auth->request_tail, login_req);

	if (auth->to == NULL)
		master_login_auth_update_timeout(auth);

	master_login_auth_send_request(auth, login_req);
}

unsigned int master_login_auth_request_count(struct master_login_auth *auth)
{
	return hash_table_count(auth->requests);
}
