/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "llist.h"
#include "str.h"
#include "str-sanitize.h"
#include "strescape.h"
#include "ioloop.h"
#include "safe-mkstemp.h"
#include "hostpid.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "write-full.h"
#include "array.h"
#include "aqueue.h"
#include "connection.h"
#include "mail-user.h"
#include "imap-urlauth-fetch.h"

#include "imap-urlauth-connection.h"

enum imap_urlauth_state {
	IMAP_URLAUTH_STATE_DISCONNECTED = 0,
	IMAP_URLAUTH_STATE_CONNECTING,
	IMAP_URLAUTH_STATE_AUTHENTICATING,
	IMAP_URLAUTH_STATE_AUTHENTICATED,
	IMAP_URLAUTH_STATE_SELECTING_TARGET,
	IMAP_URLAUTH_STATE_UNSELECTING_TARGET,
	IMAP_URLAUTH_STATE_READY,
	IMAP_URLAUTH_STATE_REQUEST_PENDING,
	IMAP_URLAUTH_STATE_REQUEST_WAIT,
};

struct imap_urlauth_request {
	struct imap_urlauth_target *target;
	struct imap_urlauth_request *prev, *next;

	char *url;
	enum imap_urlauth_fetch_flags flags;

	char *bodypartstruct;

	imap_urlauth_request_callback_t *callback;
	void *context;

	bool binary_has_nuls;
};

struct imap_urlauth_target {
	struct imap_urlauth_target *prev, *next;

	char *userid;

	struct imap_urlauth_request *requests_head, *requests_tail;
};

struct imap_urlauth_connection {
	struct connection conn;
	struct event *event;

	char *path, *service, *session_id;
	struct mail_user *user;

	struct timeout *to_reconnect, *to_idle, *to_response;
	time_t last_reconnect;
	unsigned int reconnect_attempts;
	unsigned int idle_timeout_msecs;

	char *literal_temp_path;
	int literal_fd;
	buffer_t *literal_buf;
	uoff_t literal_size, literal_bytes_left;

	enum imap_urlauth_state state;

	/* userid => target struct */
	struct imap_urlauth_target *targets_head, *targets_tail;

	bool reading_literal:1;
};

#define IMAP_URLAUTH_RECONNECT_MIN_SECS 2
#define IMAP_URLAUTH_RECONNECT_MAX_ATTEMPTS 3

#define IMAP_URLAUTH_RESPONSE_TIMEOUT_MSECS 2*60*1000

#define IMAP_URLAUTH_MAX_INLINE_LITERAL_SIZE (1024*32)

static struct connection_list *imap_urlauth_connections = NULL;

static void imap_urlauth_connection_connected(struct connection *_conn,
					      bool success);
static void imap_urlauth_connection_input(struct connection *_conn);
static void imap_urlauth_connection_destroy(struct connection *_conn);

static void
imap_urlauth_connection_disconnect(struct imap_urlauth_connection *conn,
				   const char *reason);
static void
imap_urlauth_connection_abort(struct imap_urlauth_connection *conn,
			      const char *reason);
static void
imap_urlauth_connection_reconnect(struct imap_urlauth_connection *conn);
static void
imap_urlauth_connection_idle_disconnect(struct imap_urlauth_connection *conn);
static void
imap_urlauth_connection_timeout_abort(struct imap_urlauth_connection *conn);
static void
imap_urlauth_connection_fail(struct imap_urlauth_connection *conn);

static const struct connection_vfuncs imap_urlauth_connection_vfuncs = {
	.destroy = imap_urlauth_connection_destroy,
	.input = imap_urlauth_connection_input,
	.client_connected = imap_urlauth_connection_connected,
};

static const struct connection_settings imap_urlauth_connection_set = {
	.service_name_in = "imap-urlauth",
	.service_name_out = "imap-urlauth",
	.major_version = IMAP_URLAUTH_PROTOCOL_MAJOR_VERSION,
	.minor_version = IMAP_URLAUTH_PROTOCOL_MINOR_VERSION,
	.input_max_size = SIZE_MAX,
	.output_max_size = SIZE_MAX,
	.client = TRUE,
};

struct imap_urlauth_connection *
imap_urlauth_connection_init(const char *path, const char *service,
			     struct mail_user *user, const char *session_id,
			     unsigned int idle_timeout_msecs)
{
	struct imap_urlauth_connection *conn;

	if (imap_urlauth_connections == NULL) {
		imap_urlauth_connections =
			connection_list_init(&imap_urlauth_connection_set,
					     &imap_urlauth_connection_vfuncs);
	}

	conn = i_new(struct imap_urlauth_connection, 1);
	conn->service = i_strdup(service);
	conn->path = i_strdup(path);
	if (session_id != NULL)
		conn->session_id = i_strdup(session_id);
	conn->user = user;
	conn->literal_fd = -1;
	conn->idle_timeout_msecs = idle_timeout_msecs;

	conn->event = event_create(user->event);
	event_set_append_log_prefix(conn->event, "imap-urlauth: ");

	conn->conn.event_parent = conn->event;
	connection_init_client_unix(imap_urlauth_connections,
				    &conn->conn, conn->path);
	return conn;
}

void imap_urlauth_connection_deinit(struct imap_urlauth_connection **_conn)
{
	struct imap_urlauth_connection *conn = *_conn;

	*_conn = NULL;

	imap_urlauth_connection_abort(conn, NULL);

	i_free(conn->path);
	i_free(conn->service);
	if (conn->session_id != NULL)
		i_free(conn->session_id);

	i_assert(conn->to_idle == NULL);
	i_assert(conn->to_reconnect == NULL);
	i_assert(conn->to_response == NULL);

	connection_deinit(&conn->conn);
	event_unref(&conn->event);
	i_free(conn);

	if (imap_urlauth_connections->connections == NULL)
		connection_list_deinit(&imap_urlauth_connections);
}

static void
imap_urlauth_stop_response_timeout(struct imap_urlauth_connection *conn)
{
	timeout_remove(&conn->to_response);
}

static void
imap_urlauth_start_response_timeout(struct imap_urlauth_connection *conn)
{
	imap_urlauth_stop_response_timeout(conn);
	conn->to_response = timeout_add(IMAP_URLAUTH_RESPONSE_TIMEOUT_MSECS,
		imap_urlauth_connection_timeout_abort, conn);
}

static struct imap_urlauth_target *
imap_urlauth_connection_get_target(struct imap_urlauth_connection *conn,
				   const char *target_user)
{
	struct imap_urlauth_target *target = conn->targets_head;

	while (target != NULL) {
		if (strcmp(target->userid, target_user) == 0)
			return target;
		target = target->next;
	}

	target = i_new(struct imap_urlauth_target, 1);
	target->userid = i_strdup(target_user);
	DLLIST2_APPEND(&conn->targets_head, &conn->targets_tail, target);
	return target;
}

static void
imap_urlauth_target_free(struct imap_urlauth_connection *conn,
			 struct imap_urlauth_target *target)
{
	DLLIST2_REMOVE(&conn->targets_head, &conn->targets_tail, target);
	i_free(target->userid);
	i_free(target);
}

static void
imap_urlauth_connection_select_target(struct imap_urlauth_connection *conn)
{
	struct imap_urlauth_target *target = conn->targets_head;
	const char *cmd;

	if (target == NULL || conn->state != IMAP_URLAUTH_STATE_AUTHENTICATED)
		return;

	e_debug(conn->event, "Selecting target user `%s'", target->userid);

	conn->state = IMAP_URLAUTH_STATE_SELECTING_TARGET;
	cmd = t_strdup_printf("USER\t%s\n", str_tabescape(target->userid));
	if (o_stream_send_str(conn->conn.output, cmd) < 0) {
		e_warning(conn->event,
			  "Error sending USER request to imap-urlauth server: %m");
		imap_urlauth_connection_fail(conn);
	}

	imap_urlauth_start_response_timeout(conn);
}

static void
imap_urlauth_connection_send_request(struct imap_urlauth_connection *conn)
{
	struct imap_urlauth_request *urlreq;
	string_t *cmd;

	if (conn->targets_head == NULL ||
	    (conn->targets_head->requests_head == NULL &&
	     conn->targets_head->next == NULL &&
	     conn->state == IMAP_URLAUTH_STATE_READY)) {
		e_debug(conn->event,
			"No more requests pending; scheduling disconnect");
		timeout_remove(&conn->to_idle);
		if (conn->idle_timeout_msecs > 0) {
			conn->to_idle =	timeout_add(conn->idle_timeout_msecs,
				imap_urlauth_connection_idle_disconnect, conn);
		}
		return;
	}

	if (conn->state == IMAP_URLAUTH_STATE_AUTHENTICATED) {
		imap_urlauth_connection_select_target(conn);
		return;
	}

	if (conn->state != IMAP_URLAUTH_STATE_READY)
		return;

	urlreq = conn->targets_head->requests_head;
	if (urlreq == NULL) {
		if (conn->targets_head->next == NULL)
			return;

		conn->state = IMAP_URLAUTH_STATE_UNSELECTING_TARGET;
		imap_urlauth_target_free(conn, conn->targets_head);

		if (o_stream_send_str(conn->conn.output, "END\n") < 0) {
			e_warning(conn->event,
				  "Error sending END request to imap-urlauth server: %m");
			imap_urlauth_connection_fail(conn);
		}
		imap_urlauth_start_response_timeout(conn);
		return;
	}

	e_debug(conn->event, "Fetching URL `%s'", urlreq->url);

	cmd = t_str_new(128);
	str_append(cmd, "URL\t");
	str_append_tabescaped(cmd, urlreq->url);
	if ((urlreq->flags & IMAP_URLAUTH_FETCH_FLAG_BODYPARTSTRUCTURE) != 0)
		str_append(cmd, "\tbpstruct");
	if ((urlreq->flags & IMAP_URLAUTH_FETCH_FLAG_BINARY) != 0)
		str_append(cmd, "\tbinary");
	else if ((urlreq->flags & IMAP_URLAUTH_FETCH_FLAG_BODY) != 0)
		str_append(cmd, "\tbody");
	str_append_c(cmd, '\n');

	conn->state = IMAP_URLAUTH_STATE_REQUEST_PENDING;
	if (o_stream_send(conn->conn.output, str_data(cmd), str_len(cmd)) < 0) {
		e_warning(conn->event,
			  "Error sending URL request to imap-urlauth server: %m");
		imap_urlauth_connection_fail(conn);
	}

	imap_urlauth_start_response_timeout(conn);
}

struct imap_urlauth_request *
imap_urlauth_request_new(struct imap_urlauth_connection *conn,
			 const char *target_user, const char *url,
			 enum imap_urlauth_fetch_flags flags,
			 imap_urlauth_request_callback_t *callback,
			 void *context)
{
	struct imap_urlauth_request *urlreq;
	struct imap_urlauth_target *target;

	target = imap_urlauth_connection_get_target(conn, target_user);

	urlreq = i_new(struct imap_urlauth_request, 1);
	urlreq->url = i_strdup(url);
	urlreq->flags = flags;
	urlreq->target = target;
	urlreq->callback = callback;
	urlreq->context = context;

	DLLIST2_APPEND(&target->requests_head, &target->requests_tail, urlreq);

	timeout_remove(&conn->to_idle);

	e_debug(conn->event, "Added request for URL `%s' from user `%s'",
		url, target_user);

	imap_urlauth_connection_send_request(conn);
	return urlreq;
}

static void imap_urlauth_request_free(struct imap_urlauth_request *urlreq)
{
	struct imap_urlauth_target *target = urlreq->target;

	DLLIST2_REMOVE(&target->requests_head, &target->requests_tail, urlreq);
	i_free(urlreq->url);
	i_free(urlreq->bodypartstruct);
	i_free(urlreq);
}

static void
imap_urlauth_request_drop(struct imap_urlauth_connection *conn,
			  struct imap_urlauth_request *urlreq)
{
	if ((conn->state == IMAP_URLAUTH_STATE_REQUEST_PENDING ||
	     conn->state == IMAP_URLAUTH_STATE_REQUEST_WAIT) &&
	    conn->targets_head != NULL &&
	    conn->targets_head->requests_head == urlreq) {
		/* Cannot just drop pending request without breaking protocol
		   state */
		return;
	}
	imap_urlauth_request_free(urlreq);

}

void imap_urlauth_request_abort(struct imap_urlauth_connection *conn,
				struct imap_urlauth_request *urlreq)
{
	imap_urlauth_request_callback_t *callback;

	callback = urlreq->callback;
	urlreq->callback = NULL;
	if (callback != NULL) {
		T_BEGIN {
			callback(NULL, urlreq->context);
		} T_END;
	}

	imap_urlauth_request_drop(conn, urlreq);
}

static void
imap_urlauth_request_fail(struct imap_urlauth_connection *conn,
			  struct imap_urlauth_request *urlreq,
			  const char *error)
{
	struct imap_urlauth_fetch_reply reply;
	imap_urlauth_request_callback_t *callback;
	int ret = 1;

	callback = urlreq->callback;
	urlreq->callback = NULL;
	if (callback != NULL) {
		i_zero(&reply);
		reply.url = urlreq->url;
		reply.flags = urlreq->flags;
		reply.succeeded = FALSE;
		reply.error = error;

		T_BEGIN {
			ret = callback(&reply, urlreq->context);
		} T_END;
	}

	void *urlreq_context = urlreq->context;
	imap_urlauth_request_drop(conn, urlreq);

	if (ret < 0) {
		/* Drop any related requests upon error */
		imap_urlauth_request_abort_by_context(conn, urlreq_context);
	}

	if (ret != 0)
		imap_urlauth_connection_continue(conn);
}

static void
imap_urlauth_target_abort(struct imap_urlauth_connection *conn,
			  struct imap_urlauth_target *target)
{
	struct imap_urlauth_request *urlreq, *next;

	urlreq = target->requests_head;
	while (urlreq != NULL) {
		next = urlreq->next;
		imap_urlauth_request_abort(conn, urlreq);
		urlreq = next;
	}

	imap_urlauth_target_free(conn, target);
}

static void
imap_urlauth_target_fail(struct imap_urlauth_connection *conn,
			 struct imap_urlauth_target *target, const char *error)
{
	struct imap_urlauth_request *urlreq, *next;

	urlreq = target->requests_head;
	while (urlreq != NULL) {
		next = urlreq->next;
		imap_urlauth_request_fail(conn, urlreq, error);
		urlreq = next;
	}

	imap_urlauth_target_free(conn, target);
}

static void
imap_urlauth_target_abort_by_context(struct imap_urlauth_connection *conn,
				     struct imap_urlauth_target *target,
				     void *context)
{
	struct imap_urlauth_request *urlreq, *next;

	/* Abort all matching requests */
	urlreq = target->requests_head;
	while (urlreq != NULL) {
		next = urlreq->next;
		if (urlreq->context == context)
			imap_urlauth_request_abort(conn, urlreq);
		urlreq = next;
	}

	if (target->requests_head == NULL)
		imap_urlauth_target_free(conn, target);
}

static void
imap_urlauth_connection_abort(struct imap_urlauth_connection *conn,
			      const char *reason)
{
	struct imap_urlauth_target *target, *next;

	if (reason == NULL)
		reason = "Aborting due to error";
	imap_urlauth_connection_disconnect(conn, reason);

	/* Abort all requests */
	target = conn->targets_head;
	while (target != NULL) {
		next = target->next;
		imap_urlauth_target_abort(conn, target);
		target = next;
	}
}

void imap_urlauth_request_abort_by_context(struct imap_urlauth_connection *conn,
					   void *context)
{
	struct imap_urlauth_target *target, *next;

	/* Abort all matching requests */
	target = conn->targets_head;
	while (target != NULL) {
		next = target->next;
		imap_urlauth_target_abort_by_context(conn, target, context);
		target = next;
	}
}

static void imap_urlauth_connection_fail(struct imap_urlauth_connection *conn)
{
	if (conn->reconnect_attempts > IMAP_URLAUTH_RECONNECT_MAX_ATTEMPTS) {
		imap_urlauth_connection_abort(conn,
			"Connection failed and connection attempts exhausted");
	} else {
		imap_urlauth_connection_reconnect(conn);
	}
}

static int
imap_urlauth_connection_create_temp_fd(struct imap_urlauth_connection *conn,
				       const char **path_r)
{
	string_t *path;
	int fd;

	path = t_str_new(128);
	mail_user_set_get_temp_prefix(path, conn->user->set);
	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		e_error(conn->event,
			"safe_mkstemp(%s) failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (i_unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_close_fd(&fd);
		return -1;
	}

	*path_r = str_c(path);
	return fd;
}

static int
imap_urlauth_connection_read_literal_init(struct imap_urlauth_connection *conn,
					  uoff_t size)
{
	const char *path;

	i_assert(conn->literal_fd == -1 && conn->literal_buf == NULL);

	if (size <= IMAP_URLAUTH_MAX_INLINE_LITERAL_SIZE) {
		/* Read the literal directly */
		if (size > 0) {
			conn->literal_buf =
				buffer_create_dynamic(default_pool, size);
		}
	} else {
		/* Read it into a file */
		conn->literal_fd =
			imap_urlauth_connection_create_temp_fd(conn, &path);
		if (conn->literal_fd == -1)
			return -1;
		conn->literal_temp_path = i_strdup(path);
	}

	conn->literal_size = size;
	conn->literal_bytes_left = size;
	conn->reading_literal = TRUE;
	return 1;
}

void imap_urlauth_connection_continue(struct imap_urlauth_connection *conn)
{
	i_assert(conn->targets_head != NULL);
	i_assert(conn->targets_head->requests_head != NULL);

	if (conn->state != IMAP_URLAUTH_STATE_REQUEST_WAIT)
		return;

	conn->state = IMAP_URLAUTH_STATE_READY;
	imap_urlauth_request_free(conn->targets_head->requests_head);

	imap_urlauth_connection_send_request(conn);
}

static int
imap_urlauth_connection_read_literal_data(struct imap_urlauth_connection *conn)
{
	const unsigned char *data;
	size_t size;

	/* Read data */
	data = i_stream_get_data(conn->conn.input, &size);
	if (size > conn->literal_bytes_left)
		size = conn->literal_bytes_left;

	/* Write to buffer or file */
	if (size > 0) {
		if (conn->literal_fd >= 0) {
			if (write_full(conn->literal_fd, data, size) < 0) {
				e_error(conn->event, "write(%s) failed: %m",
					conn->literal_temp_path);
				return -1;
			}
		} else {
			i_assert(conn->literal_buf != NULL);
			buffer_append(conn->literal_buf, data, size);
		}
		i_stream_skip(conn->conn.input, size);
		conn->literal_bytes_left -= size;
	}

	/* Exit if not finished */
	if (conn->literal_bytes_left > 0)
		return 0;

	/* Read LF guard */
	data = i_stream_get_data(conn->conn.input, &size);
	if (size < 1)
		return 0;

	/* Check LF guard */
	if (data[0] != '\n') {
		e_error(conn->event, "no LF at end of literal (found 0x%x)",
			data[0]);
		return -1;
	}
	i_stream_skip(conn->conn.input, 1);
	return 1;
}

static void literal_stream_destroy(buffer_t *buffer)
{
	buffer_free(&buffer);
}

static int
imap_urlauth_fetch_reply_set_literal_stream(
	struct imap_urlauth_connection *conn,
	struct imap_urlauth_fetch_reply *reply)
{
	const unsigned char *data;
	size_t size;
	uoff_t fd_size;

	if (conn->literal_fd != -1) {
		reply->input = i_stream_create_fd_autoclose(&conn->literal_fd,
							    SIZE_MAX);
		if (i_stream_get_size(reply->input, TRUE, &fd_size) < 1 ||
		    fd_size != conn->literal_size) {
			i_stream_unref(&reply->input);
			e_error(conn->event,
				"Failed to obtain proper size from literal stream");
			imap_urlauth_connection_abort(conn,
				"Failed during literal transfer");
			return -1;
		}
	} else {
		data = buffer_get_data(conn->literal_buf, &size);
		i_assert(size == conn->literal_size);
		reply->input = i_stream_create_from_data(data, size);
		i_stream_add_destroy_callback(reply->input,
					      literal_stream_destroy,
					      conn->literal_buf);
	}
	reply->size = conn->literal_size;
	return 0;
}

static int
imap_urlauth_connection_read_literal(struct imap_urlauth_connection *conn)
{
	struct imap_urlauth_request *urlreq = conn->targets_head->requests_head;
	struct imap_urlauth_fetch_reply reply;
	imap_urlauth_request_callback_t *callback;
	int ret;

	i_assert(conn->reading_literal);
	i_assert(urlreq != NULL);

	if (conn->literal_size > 0) {
		ret = imap_urlauth_connection_read_literal_data(conn);
		if (ret <= 0)
			return ret;
	}
	i_assert(conn->literal_bytes_left == 0);

	/* Reply */
	i_zero(&reply);
	reply.url = urlreq->url;
	reply.flags = urlreq->flags;
	reply.bodypartstruct = urlreq->bodypartstruct;
	reply.binary_has_nuls = urlreq->binary_has_nuls ? 1 : 0;

	if (conn->literal_size > 0) {
		if (imap_urlauth_fetch_reply_set_literal_stream(
			conn, &reply) < 0)
			return -1;
	}
	reply.succeeded = TRUE;

	ret = 1;
	callback = urlreq->callback;
	urlreq->callback = NULL;
	if (callback != NULL) T_BEGIN {
		ret = callback(&reply, urlreq->context);
	} T_END;
	if (ret == 0)
		urlreq->callback = callback;

	if (reply.input != NULL)
		i_stream_unref(&reply.input);

	if (ret < 0) {
		/* Drop any related requests upon error */
		imap_urlauth_request_abort_by_context(conn, urlreq->context);
	}

	conn->state = IMAP_URLAUTH_STATE_REQUEST_WAIT;
	if (ret != 0)
		imap_urlauth_connection_continue(conn);

	/* Finished */
	i_free_and_null(conn->literal_temp_path);
	conn->literal_fd = -1;
	conn->literal_buf = NULL;
	conn->reading_literal = FALSE;
	return 1;
}

static void imap_urlauth_connection_destroy(struct connection *_conn)
{
	struct imap_urlauth_connection *conn =
		container_of(_conn, struct imap_urlauth_connection, conn);

	switch (_conn->disconnect_reason) {
	case CONNECTION_DISCONNECT_HANDSHAKE_FAILED:
		imap_urlauth_connection_disconnect(
			conn, "Handshake with imap-urlauth service failed");
		break;
	case CONNECTION_DISCONNECT_BUFFER_FULL:
		i_unreached();
	default:
		/* Disconnected */
		imap_urlauth_connection_reconnect(conn);
	}
}

static int imap_urlauth_input_pending(struct imap_urlauth_connection *conn)
{
	struct imap_urlauth_request *urlreq;
	const char *value, *response, *const *args, *bpstruct = NULL;
	uoff_t literal_size;

	i_assert(conn->targets_head != NULL);
	i_assert(conn->targets_head->requests_head != NULL);
	urlreq = conn->targets_head->requests_head;

	if (conn->reading_literal) {
		/* Read pending literal; may callback */
		return imap_urlauth_connection_read_literal(conn);
	}

	/* "OK"[<metadata-items>]"\t"<literal-size>"\n" or
	   "NO"["\terror="<error>]"\n" */
	if ((response = i_stream_next_line(conn->conn.input)) == NULL)
		return 0;
	imap_urlauth_stop_response_timeout(conn);

	args = t_strsplit_tabescaped(response);
	if (args[0] == NULL) {
		e_error(conn->event, "Empty URL response: %s",
			str_sanitize(response, 80));
		return -1;
	}

	if (strcmp(args[0], "OK") != 0 || args[1] == NULL) {
		if (strcmp(args[0], "NO") == 0) {
			const char *param = args[1], *error = NULL;

			if (param != NULL &&
			    str_begins_icase(param, "error=", &value) &&
			    value[0] != '\0')
				error = value;
			conn->state = IMAP_URLAUTH_STATE_REQUEST_WAIT;
			imap_urlauth_request_fail(conn,
				conn->targets_head->requests_head, error);
			return 1;
		}
		e_error(conn->event, "Unexpected URL response: %s",
			str_sanitize(response, 80));
		return -1;
	}

	/* Read metadata */
	args++;
	for (; args[1] != NULL; args++) {
		const char *param = args[0];

		if (strcasecmp(param, "hasnuls") == 0) {
			urlreq->binary_has_nuls = TRUE;
		} else if (str_begins_icase(param, "bpstruct=", &value) &&
			   value[0] != '\0') {
			bpstruct = value;
		}
	}

	/* Read literal size */
	if (str_to_uoff(args[0], &literal_size) < 0) {
		e_error(conn->event,
			"Overflowing unsigned integer value for literal size: %s",
			args[1]);
		return -1;
	}

	/* Read literal */
	if (imap_urlauth_connection_read_literal_init(conn, literal_size) < 0)
		return -1;

	urlreq->bodypartstruct = i_strdup(bpstruct);
	return imap_urlauth_connection_read_literal(conn);
}

static int imap_urlauth_authenticate(struct imap_urlauth_connection *conn)
{
	string_t *str;

	conn->state = IMAP_URLAUTH_STATE_AUTHENTICATING;

	str = t_str_new(128);
        str_printfa(str, "AUTH\t%s\t%s\t", conn->service, my_pid);
	str_append_tabescaped(str, conn->user->username);
	str_append_c(str, '\t');
	if (conn->session_id != NULL)
		str_append_tabescaped(str, conn->session_id);
	str_append_c(str, '\t');
	str_append_tabescaped(str, conn->user->auth_token);
	str_append_c(str, '\n');
	if (o_stream_send(conn->conn.output, str_data(str), str_len(str)) < 0) {
		e_warning(conn->event,
			  "Error sending handshake to imap-urlauth server: %m");
		imap_urlauth_connection_abort(conn, NULL);
		return -1;
	}

	return 0;
}

static int imap_urlauth_input_next(struct imap_urlauth_connection *conn)
{
	const char *response;
	int ret;

	if (!conn->conn.version_received) {
		if ((response = i_stream_next_line(conn->conn.input)) == NULL)
			return 0;

		if (connection_handshake_args_default(
			&conn->conn, t_strsplit_tabescaped(response)) < 0) {
			imap_urlauth_connection_fail(conn);
			return -1;
		}
		if (imap_urlauth_authenticate(conn) < 0)
			return -1;
		return 1;
	}

	switch (conn->state) {
	case IMAP_URLAUTH_STATE_CONNECTING:
		break;
	case IMAP_URLAUTH_STATE_AUTHENTICATING:
	case IMAP_URLAUTH_STATE_UNSELECTING_TARGET:
		if ((response = i_stream_next_line(conn->conn.input)) == NULL)
			return 0;
		imap_urlauth_stop_response_timeout(conn);

		if (strcasecmp(response, "OK") != 0) {
			if (conn->state == IMAP_URLAUTH_STATE_AUTHENTICATING) {
				e_error(conn->event,
					"Failed to authenticate to service: "
					"Got unexpected response: %s",
					str_sanitize(response, 80));
			} else {
				e_error(conn->event,
					"Failed to unselect target user: "
					"Got unexpected response: %s",
					str_sanitize(response, 80));
			}
			imap_urlauth_connection_abort(conn, NULL);
			return -1;
		}

		if (conn->state == IMAP_URLAUTH_STATE_AUTHENTICATING) {
			e_debug(conn->event,
				"Successfully authenticated to service");
		} else {
			e_debug(conn->event,
				"Successfully unselected target user");
		}

		conn->state = IMAP_URLAUTH_STATE_AUTHENTICATED;
		imap_urlauth_connection_select_target(conn);
		return 0;
	case IMAP_URLAUTH_STATE_SELECTING_TARGET:
		if ((response = i_stream_next_line(conn->conn.input)) == NULL)
			return 0;
		imap_urlauth_stop_response_timeout(conn);

		i_assert(conn->targets_head != NULL);

		if (strcasecmp(response, "NO") == 0) {
			e_debug(conn->event, "Failed to select target user %s",
				conn->targets_head->userid);
			imap_urlauth_target_fail(conn, conn->targets_head,
						 NULL);

			conn->state = IMAP_URLAUTH_STATE_AUTHENTICATED;
			imap_urlauth_connection_select_target(conn);
			return 0;
		}
		if (strcasecmp(response, "OK") != 0) {
			e_error(conn->event,
				"Failed to select target user %s: "
				"Got unexpected response: %s",
				conn->targets_head->userid,
				str_sanitize(response, 80));
			imap_urlauth_connection_abort(conn, NULL);
			return -1;
		}

		e_debug(conn->event, "Successfully selected target user %s",
			conn->targets_head->userid);
		conn->state = IMAP_URLAUTH_STATE_READY;
		imap_urlauth_connection_send_request(conn);
		return 0;
	case IMAP_URLAUTH_STATE_AUTHENTICATED:
	case IMAP_URLAUTH_STATE_READY:
	case IMAP_URLAUTH_STATE_REQUEST_WAIT:
		if ((response = i_stream_next_line(conn->conn.input)) == NULL)
			return 0;

		e_error(conn->event,
			"Received input while no requests were pending: %s",
			str_sanitize(response, 80));
		imap_urlauth_connection_abort(conn, NULL);
		return -1;
	case IMAP_URLAUTH_STATE_REQUEST_PENDING:
		if ((ret = imap_urlauth_input_pending(conn)) < 0)
			imap_urlauth_connection_fail(conn);
		return ret;
	case IMAP_URLAUTH_STATE_DISCONNECTED:
		break;
	}
	i_unreached();
}

static void imap_urlauth_connection_input(struct connection *_conn)
{
	struct imap_urlauth_connection *conn =
		container_of(_conn, struct imap_urlauth_connection, conn);

	i_assert(conn->state != IMAP_URLAUTH_STATE_DISCONNECTED);

	if (conn->conn.input->closed) {
		/* Disconnected */
		e_error(conn->event, "Service disconnected unexpectedly");
		imap_urlauth_connection_fail(conn);
		return;
	}

	switch (i_stream_read(conn->conn.input)) {
	case -1:
		/* Disconnected */
		e_error(conn->event, "Service disconnected unexpectedly");
		imap_urlauth_connection_fail(conn);
		return;
	case -2:
		/* Input buffer full */
		e_error(conn->event, "Service sent too large input");
		imap_urlauth_connection_abort(conn, NULL);
		return;
	}

	while (!conn->conn.input->closed) {
		if (imap_urlauth_input_next(conn) <= 0)
			break;
	}
}

static void
imap_urlauth_connection_connected(struct connection *_conn, bool success)
{
	struct imap_urlauth_connection *conn =
		container_of(_conn, struct imap_urlauth_connection, conn);

	/* Cannot get here unless UNIX socket connect() was successful */
	i_assert(success);

	imap_urlauth_start_response_timeout(conn);
}

static int
imap_urlauth_connection_do_connect(struct imap_urlauth_connection *conn)
{
	if (conn->state >= IMAP_URLAUTH_STATE_AUTHENTICATED) {
		imap_urlauth_connection_send_request(conn);
		return 1;
	}
	if (conn->state >= IMAP_URLAUTH_STATE_CONNECTING)
		return 1;

	if (conn->user->auth_token == NULL) {
		e_error(conn->event,
			"cannot authenticate because no auth token "
			"is available for this session (running standalone?).");
		imap_urlauth_connection_abort(conn, NULL);
		return -1;
	}

	e_debug(conn->event, "Connecting to service at %s", conn->path);

	timeout_remove(&conn->to_reconnect);

	conn->state = IMAP_URLAUTH_STATE_CONNECTING;
	imap_urlauth_start_response_timeout(conn);

	if (connection_client_connect(&conn->conn) < 0) {
		e_error(conn->event, "net_connect_unix(%s) failed: %m",
			conn->path);
		imap_urlauth_connection_abort(conn, NULL);
		return -1;
	}
	return 0;
}

int imap_urlauth_connection_connect(struct imap_urlauth_connection *conn)
{
	conn->reconnect_attempts = 0;

	if (conn->to_reconnect == NULL)
		return imap_urlauth_connection_do_connect(conn);
	return 0;
}

static void
imap_urlauth_connection_disconnect(struct imap_urlauth_connection *conn,
				   const char *reason)
{
	conn->state = IMAP_URLAUTH_STATE_DISCONNECTED;

	if (!conn->conn.disconnected) {
		if (reason == NULL)
			e_debug(conn->event, "Disconnecting from service");
		else
			e_debug(conn->event, "Disconnected: %s", reason);

		connection_disconnect(&conn->conn);
	}
	conn->reading_literal = FALSE;

	if (conn->literal_fd != -1) {
		if (close(conn->literal_fd) < 0) {
			e_error(conn->event, "close(%s) failed: %m",
				conn->literal_temp_path);
		}
		i_free_and_null(conn->literal_temp_path);
		conn->literal_fd = -1;
	}

	buffer_free(&conn->literal_buf);
	timeout_remove(&conn->to_reconnect);
	timeout_remove(&conn->to_idle);
	imap_urlauth_stop_response_timeout(conn);
}

static void
imap_urlauth_connection_do_reconnect(struct imap_urlauth_connection *conn)
{
	if (conn->reconnect_attempts >= IMAP_URLAUTH_RECONNECT_MAX_ATTEMPTS) {
		imap_urlauth_connection_abort(conn,
			"Connection failed and connection attempts exhausted");
		return;
	}

	if (ioloop_time - conn->last_reconnect <
	    IMAP_URLAUTH_RECONNECT_MIN_SECS) {
		e_debug(conn->event, "Scheduling reconnect");
		timeout_remove(&conn->to_reconnect);
		conn->to_reconnect =
			timeout_add(IMAP_URLAUTH_RECONNECT_MIN_SECS*1000,
				imap_urlauth_connection_do_reconnect, conn);
	} else {
		conn->reconnect_attempts++;
		conn->last_reconnect = ioloop_time;
		(void)imap_urlauth_connection_do_connect(conn);
	}
}

static void
imap_urlauth_connection_reconnect(struct imap_urlauth_connection *conn)
{
	imap_urlauth_connection_disconnect(conn, NULL);

	/* Don't reconnect if there are no requests */
	if (conn->targets_head == NULL)
		return;

	imap_urlauth_connection_do_reconnect(conn);
}

static void
imap_urlauth_connection_idle_disconnect(struct imap_urlauth_connection *conn)
{
	imap_urlauth_connection_disconnect(conn, "Idle timeout");
}

static void
imap_urlauth_connection_timeout_abort(struct imap_urlauth_connection *conn)
{
	imap_urlauth_connection_abort(conn, "Service is not responding");
}

bool imap_urlauth_connection_is_connected(struct imap_urlauth_connection *conn)
{
	return (conn->conn.disconnected &&
		conn->state != IMAP_URLAUTH_STATE_DISCONNECTED);
}
